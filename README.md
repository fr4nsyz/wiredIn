# wiredIn

terminal security intelligence aggregator — wired into the pulse of systems security.

pulls from 28 feeds across cybersecurity research, kernel security, vendor advisories, exploits, and threat intel. designed for density: more signal, less noise.

```bash
pip install defusedxml certifi
```

```bash
python wiredIn.py
```

## usage

```
wiredIn                          daily briefing (20 articles)
wiredIn --limit 30               more headlines
wiredIn --source thn,krebs       filter sources
wiredIn --source-type advisory   filter by source class
wiredIn --tag kernel             kernel security only
wiredIn --tag linux --cve        CVEs in Linux security
wiredIn --search "salt typhoon"  search
wiredIn --event defcon           conference mode
wiredIn --ai                     AI one-liner summaries
wiredIn --intel                  structured intel format
wiredIn --intel --ai             AI-powered threat brief
wiredIn --deep                   full article deep-dive
wiredIn --cve                    CVE-only mode
wiredIn --meta                   show source type metadata
wiredIn --export                 markdown export
wiredIn --export html            HTML export
wiredIn --list                   list sources, events, tags
```

### AI

runs locally via [Ollama](https://ollama.com). defaults to `qwen2.5-coder:7b`:

```bash
ollama pull qwen2.5-coder:7b
wiredIn --ai                     one-liner summaries
wiredIn --intel --ai             structured intel brief
wiredIn --script                 video script from top stories
```

use a different model:

```bash
export WIREDIN_MODEL=llama3.1:8b
wiredIn --ai --ai-model mistral:7b-instruct-v0.3    # flag overrides env
```

cloud nvidia nim (optional — needs api key):

```bash
export WIREDIN_API_KEY=nvapi-xxxxx
export WIREDIN_API_BASE=https://integrate.api.nvidia.com/v1

wiredIn --ai
```

### caching

articles are cached for 15 minutes in `~/.cache/wiredIn/`. bypass with `--no-cache`.

```
wiredIn --no-cache               force fresh fetch
```

## sources (28)

| key | source | type |
|-----|--------|------|
| `thn` | The Hacker News | news |
| `krebs` | Krebs on Security | analysis |
| `darkread` | Dark Reading | news |
| `secweek` | SecurityWeek | news |
| `bleeping` | BleepingComputer | news |
| `schneier` | Schneier on Security | analysis |
| `helpnet` | Help Net Security | news |
| `therecord` | The Record | news |
| `talos` | Talos Intelligence | research |
| `unit42` | Unit 42 | research |
| `sans` | SANS ISC Diary | ops |
| `gryph` | GryphSec | research |
| `lwnkernel` | LWN Kernel Security | development |
| `archsec` | Arch Linux Security | advisory |
| `redhat` | Red Hat Security | advisory |
| `ubuntusec` | Ubuntu Security | advisory |
| `debiansec` | Debian Security | advisory |
| `freebsdsec` | FreeBSD Security | advisory |
| `msrc` | MSRC | advisory |
| `exploitdb` | Exploit-DB | exploit |
| `nvd` | NVD | cve |
| `cisa` | CISA Alerts | advisory |
| `certcc` | CERT/CC | advisory |
| `portswigger` | PortSwigger Research | research |
| `golangsec` | Go Security | advisory |
| `rustsec` | Rust Security | advisory |
| `cloudflare` | Cloudflare Blog | research |
| `falco` | Falco Security | development |

## tags (27)

articles are auto-tagged from title + summary:

`kernel` · `ebpf` · `edr` · `firmware` · `sidechannel` · `exploit` · `cve` · `ransomware` · `supplychain` · `ai` · `zeroday` · `apt` · `phishing` · `breach` · `malware` · `vuln` · `cloud` · `iot` · `crypto` · `network` · `windows` · `linux` · `macos` · `mobile` · `blockchain` · `privacy` · `hacktivism`

## events

```
wiredIn --event rsac
wiredIn --event defcon
wiredIn --event blackhat
wiredIn --event bsides
```

## modes

| flag | description |
|------|-------------|
| `--cve` | only articles mentioning CVEs |
| `--deep` | full article view with metadata |
| `--intel` | structured one-line-per-article |
| `--intel --ai` | AI threat brief + headlines |
| `--meta` | show source type tag |
| `--source-type advisory` | advisories only |
| `--search` | keyword search |
| `--export html` | export as styled HTML |
| `--verbose` | full article summaries |
| `--script` | short-form video script |

## security

- XML parsing uses defusedxml (XXE/billion laughs protection)
- TLS verification always enforced
- API calls sanitize exceptions (no key leakage)
- no eval, exec, subprocess, or shell
- no secrets hardcoded, no data collection
