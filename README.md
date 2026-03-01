## AWS CSPM

Lightweight AWS Cloud Security Posture Management (CSPM) CLI.

This tool helps you quickly inspect your AWS environments for common
misconfigurations and gain a high‑level view of your cloud security posture
from the terminal.

### Installation

Requirements:

- **Python**: 3.11+
- **AWS credentials** configured in your environment (e.g. via `aws configure`,
  environment variables, or an IAM role).
- **uv**: install from `https://github.com/astral-sh/uv` or your package manager.

From the project root:

```bash
uv venv                    # create a local virtualenv (optional but recommended)
source .venv/bin/activate  # or your shell's equivalent
uv pip install -e .        # install aws-cspm into that environment
```

### Usage

After installation, the CLI is available as the `cspm` command.

- **Run a quick scan** (current AWS profile and region):

  ```bash
  cspm
  ```

- **Choose profile and regions**:

  ```bash
  cspm --profile my-profile --regions eu-west-1 eu-central-1
  ```

- **Limit to specific services** (otherwise all supported services are scanned):

  ```bash
  cspm --services S3 IAM EC2 RDS CloudTrail EBS Lambda ECS ECSFargate ECR
  ```

- **Filter by severity** (only show findings at that level or higher):

  ```bash
  cspm --severity HIGH
  ```

- **Export a JSON report** (machine-readable output with summaries and findings):

  ```bash
  cspm --output-json report.json
  ```

- **Concurrent scanning** — use `--workers N` to control the number of parallel
  scanner threads (default: 10):

  ```bash
  cspm --workers 20
  ```

The CLI uses `boto3` under the hood and renders rich, colored terminal output
via `rich` (use `--no-color` to disable colors). Container and image-related
checks (for example from ECR/ECS) surface CVEs with CVSS/EPSS, exploit
availability, and fix information when available.

### Acknowledging findings

Some findings may be intentional or accepted risks (e.g. a Lambda that
deliberately runs outside a VPC). Use the `ack` subcommand to suppress them so
they no longer clutter your scan output.

Acks are stored in `.cspm-ack.json` in the current directory by default and are
safe to commit to git for team-wide suppression.

- **Suppress a specific finding** (exact resource ARN):

  ```bash
  cspm ack add \
    --check-id LAMBDA_001 \
    --resource-arn arn:aws:lambda:eu-west-1:123456789012:function:my-api \
    --reason "Public API — no VPC required" \
    --by alice \
    --expires 2027-01-01
  ```

- **Suppress a check across all resources** (wildcard):

  ```bash
  cspm ack add --check-id LAMBDA_001 --resource-arn '*' --reason "Not applicable"
  ```

- **List all active acknowledgments**:

  ```bash
  cspm ack list
  ```

- **Remove an acknowledgment**:

  ```bash
  cspm ack remove --check-id LAMBDA_001 --resource-arn '*'
  ```

- **Show suppressed findings** during a scan (visible in a separate table):

  ```bash
  cspm --show-acked
  ```

- **Use a custom ack file** (e.g. per-environment):

  ```bash
  cspm --ack-file acks/prod.json
  cspm ack list --ack-file acks/prod.json
  ```

Acks support optional expiry (`--expires YYYY-MM-DD`). Once an ack expires it
stops matching and the finding resurfaces automatically — useful for suppressing
a known issue while a fix is in progress.

### Development

To work on the project locally:

```bash
git clone <this-repo-url>
cd vaern
uv venv
source .venv/bin/activate
uv pip install -e .  # or `uv pip install -e ".[dev]"` if you have dev extras
```

Run tests and linters as configured in the project (see source and tooling
config files).

### Limitations / Notes

- **IAM data freshness**: Checks such as `IAM_006` (unused/old access keys) and
  `IAM_007` (password not rotated) rely on the AWS IAM credential report, which
  can be cached by AWS for several hours. This means very recent password or
  key changes might not show up immediately.
- **CloudTrail dependency**: `cspm` cross-references CloudTrail management
  events for recent password changes to reduce this staleness, but this only
  works if you have a trail with management events (including IAM) enabled in
  the account/region being scanned.