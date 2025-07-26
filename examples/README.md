# NoLeak Examples

This directory contains example files with intentionally embedded fake secrets for testing the NoLeak scanner. These files demonstrate various types of hardcoded credentials that the scanner can detect.

## ⚠️ WARNING

All secrets in these files are **FAKE** and for **TESTING PURPOSES ONLY**. Do not use any of these values in real applications. They are intentionally insecure examples.

## Example Files

### `fake_leaks.py`
A Python file demonstrating various types of hardcoded secrets commonly found in source code:
- API keys (Stripe, Google, GitHub, etc.)
- AWS credentials
- Database connection strings
- JWT tokens
- Private keys and certificates
- Generic passwords and tokens

### `fake_config.env`
An environment file (`.env`) with various configuration secrets:
- Database credentials
- Third-party API keys
- OAuth secrets
- SMTP passwords
- Redis and MongoDB credentials

### `fake_config.yaml`
A YAML configuration file with nested secret structures:
- Structured API key configurations
- Database connection details
- SSL certificates and private keys
- Service-specific credentials

### `fake_dockerfile`
A Dockerfile with embedded secrets demonstrating bad practices:
- Environment variables with secrets
- Hardcoded passwords in RUN commands
- Git credentials in clone operations
- API tokens in curl commands

## Testing the Scanner

### Basic Scanning

Scan a single file:
```bash
noleak examples/fake_leaks.py
```

Scan all example files:
```bash
noleak examples/
```

### Output Formats

Console output (default):
```bash
noleak examples/ --output console
```

JSON output:
```bash
noleak examples/ --output json
```

SARIF output for integration tools:
```bash
noleak examples/ --output sarif
```

Minimal output:
```bash
noleak examples/ --minimal
```

### Filtering and Configuration

Disable colors:
```bash
noleak examples/ --no-color
```

Use custom rules:
```bash
noleak examples/ --rules custom_rules.yaml
```

Disable built-in rules:
```bash
noleak examples/ --no-builtin-rules
```

Save JSON output to file:
```bash
noleak examples/ --output json > scan_results.json
```

## Expected Results

When scanning these example files, you should see:

### High-Severity Detections
- AWS access keys and secret keys
- API keys for various services
- Database connection strings with credentials
- Private keys and certificates

### Medium-Severity Detections
- Generic password assignments
- JWT tokens
- Email credentials
- Base64 encoded secrets

### Low-Severity Detections
- Certificates (public keys)
- Some generic secret patterns

## Using for Integration Testing

These files are perfect for:

1. **CI/CD Pipeline Testing**: Verify your pipeline correctly fails when secrets are detected
2. **Rule Validation**: Test custom rules against known patterns
3. **Performance Testing**: Benchmark scanning speed with realistic content
4. **Training**: Demonstrate to teams what types of secrets to avoid

### Example CI Integration

```yaml
# GitHub Actions example
- name: Scan for secrets
  run: |
    noleak . --output json > results.json
    # Fail if exit code is 1 (secrets found)
    if [ $? -eq 1 ]; then
      echo "Secrets detected! Check results.json"
      exit 1
    fi
```

## Creating Custom Test Files

When creating your own test files:

1. Use obviously fake values that still match real patterns
2. Include various severity levels
3. Test edge cases and false positives
4. Document expected detections
5. Keep secrets clearly marked as fake

## Rule Testing

Use these files to test custom rules:

```bash
# Create example custom rules
noleak --create-rules-example custom_rules.yaml

# Test with custom rules only
noleak examples/ --rules custom_rules.yaml --no-builtin-rules

# List all active rules
noleak --list-rules
```

## Performance Benchmarking

For performance testing:

```bash
# Time the scan
time noleak examples/

# Use multiple threads
noleak examples/ --threads 10

# Scan larger directories
noleak /path/to/large/project --verbose
```

Remember: These examples help ensure NoLeak works correctly and can detect the types of secrets commonly found in real codebases. 