# Building Serverless Vulnerability Scanning for AWS Lambda Functions

Serverless computing has fundamentally changed how organizations deploy and scale applications. AWS Lambda, the most widely adopted serverless compute platform, now powers millions of workloads across industries. But with this shift comes a new security challenge: how do you scan ephemeral, event-driven functions for vulnerabilities when there is no traditional infrastructure to attach an agent to?

This post explores the technical architecture behind agentless vulnerability scanning for AWS Lambda, walking through the design decisions, component interactions, and implementation patterns that make it possible to scan serverless workloads at scale.

## The Challenge with Serverless Security

Traditional vulnerability scanning relies on agents installed on hosts or containers. These agents run continuously, monitoring file systems and reporting back to centralized management consoles. This model breaks down with Lambda for several reasons:

**No persistent compute**: Lambda functions execute in response to events and terminate when idle. There is no long-running process to host a scanning agent.

**Ephemeral file systems**: The `/tmp` directory is the only writable space, and it gets wiped between invocations unless the execution environment is reused.

**Cold start sensitivity**: Adding heavy dependencies to Lambda packages increases cold start latency, directly impacting user experience and costs.

**Scale dynamics**: A single AWS account might have hundreds or thousands of Lambda functions, each potentially running different runtimes and dependencies.

The solution is agentless scanning, where the scanner runs externally and pulls function code for analysis rather than running inside the function itself.

## Architecture Overview

The scanning architecture consists of several AWS services working together to detect Lambda changes, trigger scans, and store results. Here is the high-level flow:

```mermaid
flowchart TB
    subgraph triggers["Event Sources"]
        CT[CloudTrail]
        EB[EventBridge Rules]
        SCHED[Scheduled Events]
    end

    subgraph scanner["Scanner Infrastructure"]
        SL[Scanner Lambda]
        QS[QScanner Binary<br/>Lambda Layer]
        SM[Secrets Manager<br/>Qualys Credentials]
    end

    subgraph targets["Target Functions"]
        L1[Lambda Function A]
        L2[Lambda Function B]
        L3[Lambda Function C]
        ECR[ECR Images]
    end

    subgraph storage["Results & State"]
        S3[S3 Bucket<br/>Scan Results]
        DDB[DynamoDB<br/>Scan Cache]
        SNS[SNS Topic<br/>Notifications]
        CW[CloudWatch<br/>Metrics]
    end

    subgraph qualys["Qualys Platform"]
        API[Qualys API<br/>Vulnerability Database]
    end

    CT --> EB
    EB --> SL
    SCHED --> SL

    SL --> QS
    SL --> SM

    SL -->|GetFunction API| L1
    SL -->|GetFunction API| L2
    SL -->|GetFunction API| L3
    SL -->|BatchGetImage| ECR

    QS -->|Submit Results| API

    SL --> S3
    SL --> DDB
    SL --> SNS
    SL --> CW

    style triggers fill:#e1f5fe
    style scanner fill:#fff3e0
    style targets fill:#f3e5f5
    style storage fill:#e8f5e9
    style qualys fill:#fce4ec
```

## Event-Driven Trigger Architecture

The system needs to detect when Lambda functions are created or modified. AWS CloudTrail logs all API calls to Lambda, and EventBridge can filter these events and route them to our scanner.

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant Lambda as AWS Lambda API
    participant CT as CloudTrail
    participant EB as EventBridge
    participant Scanner as Scanner Lambda

    Dev->>Lambda: CreateFunction / UpdateFunctionCode
    Lambda->>CT: Log API Call
    CT->>EB: Publish Event

    Note over EB: Filter by eventName:<br/>CreateFunction20150331<br/>UpdateFunctionCode20150331v2

    EB->>Scanner: Invoke with Event Payload
    Scanner->>Lambda: GetFunction (target)
    Scanner->>Scanner: Run QScanner
    Scanner->>Scanner: Store Results
```

The EventBridge rules are configured to match specific CloudTrail event patterns:

```json
{
  "source": ["aws.lambda"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["lambda.amazonaws.com"],
    "eventName": [
      "CreateFunction20150331",
      "UpdateFunctionCode20150331v2"
    ]
  }
}
```

This pattern captures both new function deployments and code updates to existing functions. Configuration-only updates can optionally trigger scans as well, though the code hash will typically remain unchanged.

## Scanner Lambda Internals

The scanner Lambda function is the core component. It receives event payloads from EventBridge, retrieves target function code, executes the vulnerability scanner, and distributes results.

```mermaid
flowchart TD
    START([Invocation]) --> PARSE[Parse Event<br/>Extract Function ARN]
    PARSE --> VALIDATE{Validate ARN<br/>Format}

    VALIDATE -->|Invalid| ERROR[Return Error]
    VALIDATE -->|Valid| SELF{Self-Scan<br/>Check}

    SELF -->|Is Self| SKIP[Skip Scan<br/>Return 200]
    SELF -->|Not Self| CREDS[Get Qualys<br/>Credentials]

    CREDS --> DETAILS[Get Lambda<br/>Details]
    DETAILS --> CACHE{Check<br/>Scan Cache}

    CACHE -->|Cache Hit| CACHERET[Return Cached<br/>Result]
    CACHE -->|Cache Miss| SCAN[Execute<br/>QScanner]

    SCAN --> PROCESS{Scan<br/>Succeeded?}

    PROCESS -->|Yes| STORE[Store Results]
    PROCESS -->|Partial| STOREP[Store Partial<br/>Results]
    PROCESS -->|No| FAIL[Log Failure]

    STORE --> UPDATE[Update Cache]
    STOREP --> UPDATE
    UPDATE --> METRICS[Publish Metrics]
    METRICS --> SUCCESS([Return 200])

    FAIL --> FAILMET[Publish Failure<br/>Metrics]
    FAILMET --> ERRORRET([Return 500])

    style START fill:#4caf50,color:#fff
    style SUCCESS fill:#4caf50,color:#fff
    style SKIP fill:#2196f3,color:#fff
    style CACHERET fill:#2196f3,color:#fff
    style ERROR fill:#f44336,color:#fff
    style ERRORRET fill:#f44336,color:#fff
```

### Code Retrieval

For zip-packaged Lambda functions, the scanner calls the `GetFunction` API which returns a presigned S3 URL to download the deployment package. The scanner does not need to invoke the target function; it only reads the static code package.

For container image-based Lambda functions, the scanner authenticates with ECR using `GetAuthorizationToken` and pulls the image layers using standard registry APIs. This allows scanning of both the base image and any added application layers.

```mermaid
flowchart LR
    subgraph zip["Zip Package Flow"]
        GF[GetFunction API] --> PS[Presigned URL]
        PS --> DL[Download Package]
        DL --> SCAN1[Scan Dependencies]
    end

    subgraph image["Container Image Flow"]
        ECR[ECR GetAuthToken] --> AUTH[Registry Auth]
        AUTH --> PULL[Pull Image Layers]
        PULL --> SCAN2[Scan Layers]
    end

    style zip fill:#e3f2fd
    style image fill:#fce4ec
```

## Scan Caching Architecture

Scanning the same unchanged code repeatedly wastes compute resources. The architecture includes a DynamoDB-based cache that tracks which function and code combinations have been scanned.

```mermaid
erDiagram
    SCAN_CACHE {
        string function_arn PK
        string code_sha256
        string scan_timestamp
        string function_name
        string package_type
        string runtime
        boolean scan_success
        number ttl
    }
```

The cache key is the function ARN, and the stored code_sha256 is compared against the current function's hash. If they match and the scan is within the TTL window (default 30 days), the scanner returns early without running a new scan.

```mermaid
sequenceDiagram
    participant Scanner
    participant DynamoDB
    participant QScanner

    Scanner->>DynamoDB: GetItem(function_arn)

    alt Cache Hit
        DynamoDB-->>Scanner: Item with code_sha256
        Scanner->>Scanner: Compare hashes
        Note over Scanner: If match + within TTL<br/>skip scan
        Scanner-->>Scanner: Return cached status
    else Cache Miss or Hash Changed
        DynamoDB-->>Scanner: No item / Different hash
        Scanner->>QScanner: Execute scan
        QScanner-->>Scanner: Results
        Scanner->>DynamoDB: PutItem(new cache entry)
    end
```

## Security Model

The scanner requires carefully scoped IAM permissions. It needs read access to target Lambda functions but should not be able to invoke or modify them beyond adding Qualys-specific tags.

```mermaid
flowchart TB
    subgraph scanner_perms["Scanner Lambda Permissions"]
        direction TB
        P1[lambda:GetFunction<br/>lambda:GetFunctionConfiguration]
        P2[lambda:TagResource<br/>Condition: QualysScan* keys only]
        P3[ecr:GetAuthorizationToken<br/>ecr:BatchGetImage]
        P4[secretsmanager:GetSecretValue<br/>Qualys credentials only]
        P5[dynamodb:GetItem/PutItem<br/>Cache table only]
        P6[s3:PutObject<br/>Results bucket only]
        P7[sns:Publish<br/>Notifications topic only]
    end

    subgraph encryption["Encryption"]
        KMS[Customer Managed<br/>KMS Key]
        KMS --> DDB[(DynamoDB)]
        KMS --> SQS[(SQS DLQ)]
        KMS --> CWL[(CloudWatch Logs)]
        KMS --> SNSE[(SNS Topic)]
    end

    style scanner_perms fill:#e8f5e9
    style encryption fill:#fff3e0
```

All data at rest is encrypted using a customer-managed KMS key. This includes DynamoDB items, SQS dead letter queue messages, CloudWatch logs, and SNS notifications. The key policy restricts usage to the specific services that need it.

### Cross-Account Scanning

For organizations with multiple AWS accounts, the scanner supports assuming a role in target accounts:

```mermaid
sequenceDiagram
    participant Scanner as Scanner Lambda<br/>(Account A)
    participant STS as AWS STS
    participant Target as Target Lambda<br/>(Account B)
    participant Qualys as Qualys API

    Scanner->>STS: AssumeRole<br/>(cross-account-role, external-id)
    STS-->>Scanner: Temporary Credentials

    Scanner->>Target: GetFunction<br/>(with temp creds)
    Target-->>Scanner: Function Code URL

    Scanner->>Scanner: Run QScanner
    Scanner->>Qualys: Submit Results
```

## Results Distribution

Scan results flow to multiple destinations depending on the use case:

```mermaid
flowchart LR
    SCAN[Scan Complete] --> S3[S3 Bucket<br/>Full JSON Results]
    SCAN --> SNS[SNS Topic<br/>Notifications]
    SCAN --> TAG[Lambda Tags<br/>Scan Status]
    SCAN --> CW[CloudWatch<br/>Custom Metrics]

    S3 --> SIEM[SIEM Integration]
    S3 --> DASH[Dashboard Queries]

    SNS --> EMAIL[Email Alerts]
    SNS --> SLACK[Slack Webhook]
    SNS --> TICKET[Ticketing System]

    CW --> ALARM[CloudWatch Alarms]
    CW --> GRAPH[Metric Graphs]

    style SCAN fill:#4caf50,color:#fff
    style S3 fill:#ff9800,color:#fff
    style SNS fill:#9c27b0,color:#fff
    style TAG fill:#2196f3,color:#fff
    style CW fill:#f44336,color:#fff
```

**S3 Storage**: Full scan results in JSON format, organized by function name and timestamp. Lifecycle policies automatically expire old results.

**SNS Notifications**: Summary messages suitable for alerting pipelines. Subscribers can filter by message attributes to route critical vulnerabilities differently than informational findings.

**Lambda Tags**: The target function is tagged with `QualysScanTimestamp` and `QualysScanStatus` for quick visibility in the AWS Console.

**CloudWatch Metrics**: Custom metrics track scan success rates, durations, cache hit ratios, and vulnerability counts. These power operational dashboards and alarms.

## Bulk Scanning Existing Functions

New deployments are captured by EventBridge, but existing functions need an initial scan. A separate bulk scan Lambda enumerates all functions in the account and invokes the scanner for each:

```mermaid
sequenceDiagram
    participant Schedule as EventBridge<br/>Schedule
    participant Bulk as Bulk Scan Lambda
    participant Lambda as Lambda API
    participant Scanner as Scanner Lambda

    Schedule->>Bulk: Scheduled Trigger<br/>(e.g., weekly)

    Bulk->>Lambda: ListFunctions
    Lambda-->>Bulk: Function List

    loop For each function
        Bulk->>Bulk: Check exclusion patterns
        alt Not excluded
            Bulk->>Scanner: Invoke (async)
            Note over Bulk: Throttled invocation<br/>100ms delay
        end
    end

    Bulk-->>Schedule: Complete
```

The bulk scanner respects exclusion patterns to skip infrastructure functions (like itself and the scanner) and implements rate limiting to avoid overwhelming the scanner or hitting Lambda concurrency limits.

## Deployment Architecture

The infrastructure can be deployed via CloudFormation or Terraform. Here is the resource topology:

```mermaid
flowchart TB
    subgraph core["Core Resources"]
        SCANNER[Scanner Lambda]
        LAYER[QScanner Layer]
        ROLE[IAM Role]
        SECRET[Secrets Manager]
    end

    subgraph events["Event Infrastructure"]
        TRAIL[CloudTrail]
        RULES[EventBridge Rules]
        PERMS[Lambda Permissions]
    end

    subgraph optional["Optional Resources"]
        S3[Results S3 Bucket]
        DDB[Cache DynamoDB Table]
        SNS[Notifications Topic]
        BULK[Bulk Scan Lambda]
        ALARM[CloudWatch Alarms]
    end

    subgraph shared["Shared Resources"]
        KMS[KMS Key]
        DLQ[SQS Dead Letter Queue]
        LOGS[CloudWatch Log Groups]
    end

    SCANNER --> LAYER
    SCANNER --> ROLE
    SCANNER --> SECRET

    TRAIL --> RULES
    RULES --> PERMS
    PERMS --> SCANNER

    SCANNER -.-> S3
    SCANNER -.-> DDB
    SCANNER -.-> SNS

    KMS --> DDB
    KMS --> DLQ
    KMS --> LOGS
    KMS --> SNS

    DLQ --> SCANNER
    LOGS --> SCANNER

    style core fill:#e3f2fd
    style events fill:#fff3e0
    style optional fill:#e8f5e9
    style shared fill:#fce4ec
```

### Configuration Parameters

Key deployment parameters include:

| Parameter | Description | Default |
|-----------|-------------|---------|
| ScannerMemorySize | Memory allocation for scanner Lambda | 2048 MB |
| ScannerTimeout | Maximum scan duration | 900 seconds |
| EphemeralStorage | Temp storage for downloaded packages | 2048 MB |
| CacheTTLDays | How long to cache scan results | 30 days |
| EnableTagging | Tag scanned functions with status | true |
| BulkScanSchedule | Cron expression for periodic scans | (manual) |

## Monitoring and Observability

The architecture includes built-in monitoring through CloudWatch alarms:

```mermaid
flowchart LR
    subgraph metrics["CloudWatch Metrics"]
        ERR[Lambda Errors]
        THR[Lambda Throttles]
        DUR[Lambda Duration]
        DLQ[DLQ Message Count]
    end

    subgraph alarms["CloudWatch Alarms"]
        A1[Error Rate > 5]
        A2[Throttles > 1]
        A3[Duration > 80% timeout]
        A4[DLQ Messages > 0]
    end

    subgraph actions["Alarm Actions"]
        SNS[SNS Topic]
        OPS[Ops Team]
    end

    ERR --> A1
    THR --> A2
    DUR --> A3
    DLQ --> A4

    A1 --> SNS
    A2 --> SNS
    A3 --> SNS
    A4 --> SNS

    SNS --> OPS

    style metrics fill:#e3f2fd
    style alarms fill:#ffebee
    style actions fill:#e8f5e9
```

Custom metrics published by the scanner provide additional visibility:

- **ScanSuccess / ScanPartialSuccess**: Track scan completion rates
- **ScanDuration**: Monitor performance trends
- **CacheHit**: Measure cache effectiveness
- **VulnerabilityCount**: Aggregate vulnerability metrics

## Performance Considerations

Several design choices optimize for performance at scale:

**Reserved Concurrency**: Setting a reserved concurrency limit (e.g., 10) prevents the scanner from consuming all available Lambda concurrency during bulk operations.

**Ephemeral Storage**: Large function packages and container images require substantial temp space. The default 512 MB is often insufficient; 2048 MB handles most workloads.

**Memory Allocation**: Higher memory allocations provide proportionally more CPU. The scanner benefits from 2048 MB or higher for CPU-intensive vulnerability analysis.

**Caching**: The DynamoDB cache eliminates redundant scans. With a 30-day TTL and code hash validation, only actual code changes trigger new scans.

## Conclusion

Agentless vulnerability scanning for serverless workloads requires rethinking traditional security patterns. By leveraging CloudTrail for change detection, EventBridge for event routing, and Lambda for compute, the architecture achieves continuous security monitoring without impacting application performance.

The design prioritizes minimal permissions, encryption at rest, and operational visibility. Optional components like caching and bulk scanning address real-world operational needs while keeping the core architecture simple.

Organizations adopting serverless should treat vulnerability scanning as a first-class concern, not an afterthought. The patterns described here provide a foundation for building or evaluating serverless security tooling.
