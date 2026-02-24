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

After installation, the CLI is available as the `cspm` command:

```bash
cspm --help
```

Use the help output to discover available subcommands and options.

Typical workflow:

- **List available checks and capabilities**:

  ```bash
  cspm --help
  ```

- **Run CSPM operations against an AWS account/role/profile** using the flags
  described in the help text (for example, to target a specific profile or
  region).

The CLI uses `boto3` and `awscrt` under the hood and renders rich, colored
terminal output via `rich` where supported.

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