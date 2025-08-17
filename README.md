# NoLeak 🔒

**Find secrets hiding in your code!**
NoLeak is a powerful, extensible secret scanner designed to detect hardcoded credentials, 
API keys, tokens, and other sensitive information in your codebase before they reach 
production. Built with enterprise-grade reliability and performance in mind.

## Features
- **Comprehensive Detection**: Built-in rules for 20+ types of secrets including AWS 
keys, API tokens, database credentials, and more
- **Custom Rules**: Support for custom regex rules via YAML configuration files
- **Multiple Output Formats**: Console, JSON, SARIF, and compact formats for different 
use cases
- **High Performance**: Concurrent scanning with configurable thread pools
- **Professional CLI**: Rich command-line interface with extensive configuration options
- **CI/CD Ready**: Proper exit codes and structured output for pipeline integration
- **Extensible Architecture**: Clean, modular design for easy customization and extension

## Super Quick Start

### Step 1: Install
```bash
pip install noleak
```

### Step 2: Use it!
```bash
# Scan your project
noleak .

# Scan a specific file
noleak myfile.py
```

**That's it!** 🎉

## What does it do?

NoLeak looks for things like:
- 🔑 **API Keys** (AWS, Google, Stripe, etc.)
- 🔐 **Passwords** in your code
- 🗄️ **Database credentials**
- 🎫 **Tokens** (GitHub, Slack, etc.)
- 📜 **Private keys and certificates**

## Basic Examples

```bash
# Check your entire project for secrets
noleak .

# Check just one file
noleak config.py

# Get results as JSON (for tools)
noleak . --output json

# See what rules it uses
noleak --list-rules
```

## What the results mean

- **✅ Exit code 0**: No secrets found - you're safe!
- **⚠️ Exit code 1**: Found secrets - fix them!
- **❌ Exit code 2**: Something went wrong

## Example Output

```
./config.py
  [C] AWS Access Key ID (aws_access_key)
    Line 15:
      AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
                           ^^^^^^^^^^^^^^^^^^^^
    Matched: AKIAIOSFODNN7EXAMPLE
```

**[C] = Critical, [H] = High, [M] = Medium, [L] = Low**

## More Options (If You Need Them)

```bash
# Quiet mode (less text)
noleak . --minimal

# Custom rules
noleak . --rules my_rules.yaml

# Create example rules file
noleak --create-rules-example my_rules.yaml
```

## Use in CI/CD

Add this to your build pipeline to catch secrets before they go live:

```bash
noleak .
if [ $? -eq 1 ]; then
  echo "❌ Secrets found! Fix them before deploying."
  exit 1
fi
```

## Advanced Usage

<details>
<summary>Click for advanced options</summary>

### Command Line Interface

```
usage: noleak [-h] [--output {console,json,sarif,compact}] [--no-color] 
              [--minimal] [--quiet] [--verbose] [--rules FILE]
              [--no-builtin-rules] [--list-rules] [--create-rules-example FILE]
              [--max-file-size BYTES] [--include-ext EXT] [--exclude-ext EXT]
              [--threads N] [--version] [--info]
              path

Output Options:
  --output, -o          Output format (console, json, sarif, compact)
  --no-color            Disable colored output
  --minimal             Use minimal output format
  --quiet, -q           Suppress all output except errors
  --verbose, -v         Enable verbose output

Rule Options:
  --rules, -r FILE      Path to custom rules file (YAML format)
  --no-builtin-rules    Disable built-in rules
  --list-rules          List all available rules and exit
  --create-rules-example FILE
                        Create an example rules file and exit

Scanning Options:
  --max-file-size BYTES Maximum file size to scan in bytes (default: 10MB)
  --include-ext EXT     Include additional file extensions (e.g., .txt)
  --exclude-ext EXT     Exclude file extensions from scanning
  --threads N           Number of concurrent threads for scanning (default: 50)

Information:
  --version             show program's version number and exit
  --info                Show scanner configuration and exit
```

### Built-in Detection Rules

**Critical Severity:**
- AWS Access Keys and Secret Keys
- Database connection strings with credentials
- Private keys and certificates
- Stripe API keys

**High Severity:**
- GitHub personal access tokens
- Google API keys
- Slack tokens
- Docker authentication tokens
- Generic API keys

**Medium Severity:**
- JWT tokens
- Password assignments in code
- Email/SMTP credentials
- Base64 encoded secrets

**Low Severity:**
- Public certificates
- Some generic secret patterns

### Custom Rules

Create custom detection rules using YAML format:

```bash
# Generate example rules file
noleak --create-rules-example my_rules.yaml
```

Example custom rule:
```yaml
rules:
  - id: "custom_api_key"
    name: "My Company API Key"
    description: "Detects MyCompany API keys"
    pattern: "(?i)mycompany[_-]?api[_-]?key\\s*[:=]\\s*['\"]?([a-zA-Z0-9_\\-]{32})['\"]?"
    severity: "high"
    enabled: true
```

Use custom rules:
```bash
noleak . --rules my_rules.yaml
```

### Output Formats

**Console Output (Default)**
Human-readable terminal output with colors and context.

**JSON Output**
```bash
noleak . --output json > results.json
```

**SARIF Output**
Standard format for static analysis tools:
```bash
noleak . --output sarif > results.sarif
```

**Compact Output**
Minimal JSON for basic integration:
```bash
noleak . --output compact
```

### CI/CD Integration Examples

**GitHub Actions:**
```yaml
name: Secret Scan
on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Install NoLeak
        run: pip install noleak
      - name: Scan for secrets
        run: |
          noleak . --output json > results.json
          if [ $? -eq 1 ]; then
            echo "::error::Secrets detected in repository"
            cat results.json
            exit 1
          fi
```

**Jenkins Pipeline:**
```groovy
pipeline {
    agent any
    stages {
        stage('Secret Scan') {
            steps {
                sh 'pip install noleak'
                sh '''
                    noleak . --output json > scan_results.json
                    exit_code=$?
                    if [ $exit_code -eq 1 ]; then
                        echo "Secrets detected!"
                        cat scan_results.json
                        exit 1
                    fi
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'scan_results.json', fingerprint: true
                }
            }
        }
    }
}
```

**GitLab CI:**
```yaml
secret_scan:
  stage: security
  image: python:3.9
  script:
    - pip install noleak
    - noleak . --output json > results.json
    - |
      if [ $? -eq 1 ]; then
        echo "Secrets detected in repository!"
        cat results.json
        exit 1
      fi
  artifacts:
    reports:
      sast: results.json
    when: always
```

### Python API

Use NoLeak programmatically in Python:

```python
import noleak

# Quick text scanning
matches = noleak.scan_text('api_key = "secret123"')
if matches:
    print(f"Found {len(matches)} secrets!")

# File scanning
matches = noleak.scan_file("config.py")

# Advanced usage
scanner = noleak.create_scanner(
    builtin_rules=True,
    external_rules_file="custom_rules.yaml"
)

result = scanner.scan_path("/path/to/project")
print(f"Scanned {result.stats.files_scanned} files")
print(f"Found {len(result.matches)} secrets")

# Custom configuration
config = noleak.ScannerConfig(
    max_file_size=5 * 1024 * 1024,  # 5MB
    max_concurrent_files=20
)
scanner = noleak.SecretScanner(config=config)
```

### Performance

NoLeak is designed for high performance:

- **Concurrent Scanning**: Scan multiple files simultaneously
- **Smart File Filtering**: Skip binary files and excluded patterns
- **Efficient Pattern Matching**: Compiled regex patterns for speed
- **Memory Management**: Streaming for large files

Typical performance:
- ~1000 files/second on modern hardware
- ~50MB/second throughput
- Linear scaling with thread count

### Configuration

**File Extensions**
By default, NoLeak scans common source code file types. Customize with:

```bash
# Include additional extensions
noleak . --include-ext .txt --include-ext .log

# Exclude specific extensions  
noleak . --exclude-ext .md --exclude-ext .rst
```

**File Size Limits**
Control maximum file size to scan:

```bash
# Scan files up to 5MB
noleak . --max-file-size 5242880
```

**Threading**
Adjust concurrent scanning threads:

```bash
# Use 20 threads for faster scanning
noleak . --threads 20
```

</details>

## Test It Out

The `examples/` directory contains test files with fake secrets:

```bash
# Try it on our test files
noleak examples/

# You should see lots of detections!
```

## Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Development Setup

```bash
git clone https://github.com/Seichs/NoLeak.git
cd NoLeak
pip install -e ".[dev]"
pytest
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/Seichs/NoLeak/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Seichs/NoLeak/discussions)

## Security

Found a security issue? Please email security@noleak.dev instead of creating a public issue.

---

**🛡️ Protect your code. Secure your secrets. Use NoLeak.**