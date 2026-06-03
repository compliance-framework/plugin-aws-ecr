# plugin-aws-ecr

CCF compliance plugin for AWS Elastic Container Registry (ECR). Evaluates private ECR repositories and container image scan results against SOC2 TSC 2017 controls.

## What it checks

### CONFIG checks (per repository)

| Check | Description | Controls |
|-------|-------------|---------|
| `ecr_require_scan_on_push` | `imageScanningConfiguration.scanOnPush` must be `true` | CC5.3, CC6.8, CC7.1 |
| `ecr_require_tag_immutability` | `imageTagImmutability` must be `IMMUTABLE` | CC6.8, CC8.1 |
| `ecr_require_encryption` | Encryption type must be in `approved_encryption_types` | CC5.2 |
| `ecr_require_lifecycle_policy` | Repository must have a lifecycle policy configured | CC6.5 |
| `ecr_deny_public_access` | Resource policy must not grant `Principal: "*"` with `Effect: Allow` | CC6.8, CC8.1 |
| `ecr_require_tags` | Repository must carry all `required_repository_tags` | CC6.1 |

### CONFIG checks (per registry / account+region)

| Check | Description | Controls |
|-------|-------------|---------|
| `ecr_require_registry_scanning` | Registry-level scan type must be in `approved_registry_scan_types` | CC5.2, CC5.3, CC7.1 |

### DYNAMIC checks (per image digest, 90-day lookback)

| Check | Description | Controls |
|-------|-------------|---------|
| `ecr_require_image_scan_complete` | Image scan `status` must be `COMPLETE` | CC3.2, CC5.2, CC7.1, CC8.1 |
| `ecr_require_no_critical_image_findings` | `CRITICAL` finding count must be 0 | CC6.8, CC7.1, CC8.1 |
| `ecr_require_no_high_image_findings` | `HIGH` finding count must be ≤ `max_high_finding_count` | CC6.8, CC7.1, CC8.1 |
| `ecr_require_scan_findings_retrievable` | Scan findings with severity data must be accessible | CC6.8, CC7.1 |

## Required IAM actions

```json
{
  "Effect": "Allow",
  "Action": [
    "ecr:DescribeRepositories",
    "ecr:GetLifecyclePolicy",
    "ecr:GetRepositoryPolicy",
    "ecr:ListTagsForResource",
    "ecr:GetRegistryScanningConfiguration",
    "ecr:DescribeImages",
    "ecr:DescribeImageScanFindings"
  ],
  "Resource": "*"
}
```

## Configuration

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `regions` | `string` | Yes | Comma-separated AWS regions to scan (e.g. `"us-east-1,eu-west-1"`) |
| `accounts` | `string` | No | Comma-separated account IDs to filter on. If omitted, all repositories in the region are evaluated. |
| `policy_labels` | `string` (JSON) | No | Extra labels added to every Evidence record (e.g. `{"env":"prod"}`) |

## Policy data (overrides `data.json` defaults)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `approved_encryption_types` | `[]string` | `["KMS"]` | Allowed ECR encryption types |
| `approved_registry_scan_types` | `[]string` | `["ENHANCED"]` | Allowed registry-level scan modes |
| `required_repository_tags` | `[]string` | `["Environment","Owner"]` | Tag keys every repository must carry |
| `required_tag_values` | `object` | `{}` | Enforce specific values for certain tags |
| `image_lookback_days` | `number` | `90` | Days back to evaluate image digests |
| `max_high_finding_count` | `number` | `0` | Maximum HIGH severity findings allowed per image |

## Local development

```bash
# Build the binary
make build

# Run unit tests
make test

# Run against a dev account (requires AWS credentials)
make run
```

See `examples/agent-config.yaml` for a full configuration reference.
