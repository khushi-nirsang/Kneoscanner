# Kneoscanner

Kneoscanner is an OWASP-focused web vulnerability scanner with a CLI and a
local browser GUI. It loads YAML templates, crawls same-origin application
routes, mutates discovered parameters in authorized active scans, and writes
JSON, HTML, PDF, and SARIF reports.

> Use Kneoscanner only on applications you own or are explicitly authorized to
> test. Active and intrusive profiles send mutation payloads.

## Requirements

- Go 1.22 or newer
- Git

## Install From Git Clone

```text
git clone https://github.com/khushi-nirsang/Kneoscanner.git
cd Kneoscanner
go mod download
go build -o kneoscanner .
```

On Windows PowerShell:

```text
git clone https://github.com/khushi-nirsang/Kneoscanner.git
cd Kneoscanner
go mod download
go build -o kneoscanner.exe .
```

## Quick Checks

```bash
go test ./...
go run . --lint-templates
```

## Basic Usage

Passive/safe scan:

```bash
./kneoscanner -u https://example.com
```

OWASP active scan for authorized targets:

```bash
./kneoscanner -u https://example.com --profile active --acknowledge-authorization
```

Add an AI analyst summary to the generated reports:

```bash
./kneoscanner -u https://example.com --profile active --acknowledge-authorization --ai
```

Use an OpenAI-compatible API instead of the local offline analyst:

```bash
export OPENAI_API_KEY=your_api_key
./kneoscanner -u https://example.com --profile active --acknowledge-authorization --ai --ai-provider openai --ai-model gpt-4o-mini
```

Target list:

```bash
./kneoscanner -l targets.txt --profile active --acknowledge-authorization
```

Focus active mutation on specific parameter names:

```bash
./kneoscanner -u https://example.com --profile active --acknowledge-authorization --parameter id,search,q,url
```

Start the local GUI:

```bash
./kneoscanner --gui
```

The GUI listens only on loopback, normally `127.0.0.1:8080`.
Use the **Generate AI analyst summary** checkbox in Scan setup to include the
same AI summary in GUI status and reports.

## Scan Profiles

- `passive`: discovery and passive security checks only.
- `safe`: passive checks plus safe template checks.
- `active`: OWASP mutation checks such as XSS, SQL injection, SSRF, path traversal, SSTI, and open redirect. Requires `--acknowledge-authorization`.
- `intrusive`: higher-risk checks such as command injection and race/mass-assignment style probes. Requires `--acknowledge-authorization`.

If an active scan discovers input parameters, Kneoscanner tests those inputs
first. If no eligible input is discovered, it falls back to the built-in
template paths so lab/demo applications can still be tested.

## Reports

Default output:

```text
reports/results.json
reports/results.html
reports/results.pdf
reports/results.sarif
reports/history.json
```

When AI analysis is enabled, JSON and HTML reports include an `ai_analysis`
section with executive summary, risk level, priority findings, and next steps.

Change output path:

```bash
./kneoscanner -u https://example.com -o reports/example.json
```

## Configuration

The scanner reads `config.yaml` from the project root by default. You can also
provide an explicit config:

```bash
./kneoscanner --config configs/config.yaml -u https://example.com
```

Important settings:

```yaml
verify_ssl: true
follow_redirects: true
allow_external_urls: false
crawl: true
crawl_max_depth: 3
crawl_max_pages: 100
redact_sensitive_data: true
```

## Troubleshooting

- No SQLi/XSS/SSRF findings: use `--profile active --acknowledge-authorization`.
- No parameters discovered: pass likely names with `--parameter id,search,q,url`.
- Template problems: run `go run . --lint-templates`.
- Reports not created: check the `output` path and file permissions.
- GUI port busy: run `./kneoscanner --gui --gui-address 127.0.0.1:9090`.
