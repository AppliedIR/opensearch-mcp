![Valhuntir](docs/images/vhir-logo.png)

# opensearch-mcp
[![CI](https://github.com/AppliedIR/opensearch-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/AppliedIR/opensearch-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/AppliedIR/opensearch-mcp/blob/main/LICENSE)

Forensic evidence indexing for [Valhuntir](https://github.com/AppliedIR/Valhuntir) — parse, index, and query digital forensic artifacts at scale using OpenSearch.

Built by [Applied IR](https://github.com/AppliedIR) with Claude Code.

> **Important Note** — While extensively tested, this is a new platform.
> ALWAYS verify results and guide the investigative process. If you just
> tell Valhuntir to "Find Evil" it will more than likely hallucinate
> rather than provide meaningful results. The AI can accelerate, but the
> human must guide it and review all decisions.

## Why This Exists

A KAPE triage collection from 30 hosts produces ~50 million evidence records across hundreds of artifact types. An LLM reading these directly would consume billions of tokens and still miss patterns buried in the noise.

opensearch-mcp solves this by **parsing evidence programmatically and indexing it into OpenSearch**, then giving the LLM 17 purpose-built query tools. The LLM asks structured questions ("show me all 4688 events where the parent process is cmd.exe") and gets precise answers — no token waste on raw log parsing, no missed evidence from context window limits. The LLM focuses on investigation logic. The parsers handle the data.

## What It Does

### Ingest

15 parsers cover the forensic evidence spectrum:

| Parser | Artifacts | Source |
|--------|-----------|--------|
| evtx | Windows Event Logs | pyevtx-rs (ECS-normalized) |
| EZ Tools (10) | Shimcache, Amcache, MFT, USN, Registry, Shellbags, Jumplists, LNK, Recyclebin, Timeline | Eric Zimmerman tools via wintools-mcp |
| Volatility 3 | Memory forensics (26 plugins, 3 tiers) | vol3 subprocess |
| JSON/JSONL | Suricata EVE, tshark, Velociraptor, any JSON | Auto-detect format |
| Delimited | CSV, TSV, Zeek TSV, bodyfile, L2T supertimelines | Auto-detect delimiter |
| Access logs | Apache/Nginx combined/common format | Regex parser |
| W3C | IIS, HTTPERR, Windows Firewall | W3C Extended Log Format |
| Defender | Windows Defender MPLog | Pattern extraction |
| Tasks | Windows Scheduled Tasks XML | defusedxml |
| WER | Windows Error Reporting | Crash report parser |
| SSH | OpenSSH auth logs | Regex with timezone handling |
| Transcripts | PowerShell transcripts | Header + command extraction |
| Prefetch/SRUM | Execution + network usage | Plaso or wintools |

Every parser produces:
- Deterministic content-based document IDs (re-ingest = zero duplicates)
- Full provenance: `host.name`, `vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`, `pipeline_version`
- Proper `@timestamp` with timezone handling (local-time artifacts require `--source-timezone`)

### Query (17 MCP Tools)

The LLM gets these tools via the MCP protocol:

| Tool | Purpose |
|------|---------|
| `idx_case_summary` | Complete case overview: hosts, artifacts, fields, enrichment status |
| `idx_search` | Full-text + structured queries across all artifact types |
| `idx_count` | Fast document counts with filters |
| `idx_aggregate` | Group-by analysis (top processes, IP distribution, etc.) |
| `idx_timeline` | Date histogram for temporal analysis |
| `idx_field_values` | Enumerate unique values in a field |
| `idx_get_event` | Retrieve a single document by ID |
| `idx_status` | Index inventory: names, doc counts, sizes |
| `idx_ingest` | Full disk artifact ingest pipeline |
| `idx_ingest_memory` | Volatility 3 memory analysis |
| `idx_ingest_json` | Generic JSON/JSONL ingest |
| `idx_ingest_delimited` | Generic CSV/TSV/Zeek/bodyfile ingest |
| `idx_ingest_accesslog` | Apache/Nginx access log ingest |
| `idx_ingest_status` | Monitor running ingest operations |
| `idx_enrich_triage` | Baseline enrichment via windows-triage-mcp |
| `idx_enrich_intel` | Threat intel enrichment via OpenCTI |
| `idx_list_detections` | Detection alerts (Hayabusa/Sigma) |

### Enrich

Two post-ingest enrichment pipelines add context without LLM token cost:

**Triage baseline** — Checks indexed filenames and services against the Windows baseline database (via windows-triage-mcp, part of the [sift-mcp](https://github.com/AppliedIR/sift-mcp) monorepo). Stamps documents with `triage.verdict` (EXPECTED, SUSPICIOUS, UNKNOWN, EXPECTED_LOLBIN). Includes 14 registry persistence detection rules (IFEO, Winlogon, LSA, Print Monitors, etc.) that run as direct OpenSearch queries — no external calls needed.

**OpenCTI threat intel** — Extracts unique external IPs, hashes, and domains from indexed data, looks them up in OpenCTI via the gateway, and stamps matching documents with `threat_intel.verdict` and confidence. 200 unique IOCs checked in ~10 seconds vs. 100K inline lookups that would take 83 minutes.

Both enrichments are programmatic — zero LLM tokens consumed.

## Architecture

```
Evidence (disk images, triage packages, memory dumps, logs)
    |
    v
opensearch-mcp parsers (15 types, programmatic, deterministic)
    |
    v
OpenSearch (Docker, single-node, 4-12GB heap)
    |
    v
17 MCP tools <-- LLM queries here (structured, ~500 tokens each)
    |
    v
Enrichment (triage baseline + threat intel, programmatic)
```

opensearch-mcp runs as:
- **stdio MCP server** — default, connects via gateway or Claude Code
- **HTTP server** — `python -m opensearch_mcp --http --port 4625` for remote deployment
- **CLI** — `opensearch-ingest` for direct command-line use
- **vhir plugin** — `vhir ingest` when installed alongside Valhuntir

## Quick Start

### 1. Set up OpenSearch

```bash
cd opensearch-mcp
./scripts/setup-opensearch.sh
```

This starts a Docker container with OpenSearch 3.5, registers all 15 index templates (including Hayabusa), and creates the GeoIP enrichment pipeline. Detection is handled by Hayabusa (3,700+ Sigma-based rules) which runs automatically after evtx ingest if installed.

### 2. Ingest evidence

```bash
# Full triage package (auto-discovers hosts and artifacts)
opensearch-ingest scan /path/to/kape/output --hostname SERVER01 --case incident-001

# Memory image
opensearch-ingest memory /path/to/memory.raw --hostname DC01 --case incident-001

# Generic formats
opensearch-ingest json /path/to/suricata/eve.json --hostname FW01 --case incident-001
opensearch-ingest delimited /path/to/zeek/logs/ --hostname SENSOR01 --case incident-001
opensearch-ingest accesslog /path/to/apache/access.log --hostname WEB01 --case incident-001
```

### 3. Query via MCP

Connect the MCP server to your LLM client (Claude Code, gateway, etc.):

```bash
# stdio (default)
python -m opensearch_mcp

# HTTP
python -m opensearch_mcp --http --port 4625
```

The LLM starts with a case overview, then queries:
```
# First call — understand what's available
idx_case_summary(case_id="incident-001")
# Returns: hosts, artifact types, doc counts, field names per type, enrichment status

# Then query with full context
idx_search(query="event.code:4688 AND process.parent.name:cmd.exe", index="case-incident-001-evtx-*")
idx_aggregate(field="process.name", query="triage.verdict:SUSPICIOUS")
idx_timeline(query="threat_intel.verdict:MALICIOUS", interval="1h")
```

### 4. Enrich

```bash
# Triage baseline (via gateway to windows-triage-mcp)
# Runs automatically after ingest, or manually:
opensearch-ingest enrich-intel --case incident-001

# Or via MCP:
# idx_enrich_triage(case_id="incident-001")
# idx_enrich_intel(case_id="incident-001")
```

## Index Naming

All indices follow: `case-{case_id}-{artifact_type}-{hostname}`

Examples:
- `case-incident-001-evtx-server01`
- `case-incident-001-shimcache-dc01`
- `case-incident-001-zeek-conn-fw01`
- `case-incident-001-vol-pslist-dc01`

Wildcard queries across a case: `idx_search(query="...", index="case-incident-001-*")`

## Configuration

### OpenSearch connection

Created by `setup-opensearch.sh` at `~/.vhir/opensearch.yaml`:

```yaml
host: https://localhost:9200
user: admin
password: <generated>
verify_certs: false
```

### Gateway (for enrichment + wintools)

`~/.vhir/gateway.yaml` — configured by `vhir setup client`:

```yaml
gateway:
  port: 4508
api_keys:
  vhir_gw_<token>:
    examiner: steve
    role: examiner
```

### Operator environment variables (ingest resilience)

| Env var | Default | Purpose |
|---|---|---|
| `HAYABUSA_RULES_DIR` | *(autodetect)* | Path to hayabusa-rules directory (must contain a `config/` subdirectory). Set when hayabusa rules are installed outside the default locations (`/usr/local/share/hayabusa-rules`, `/usr/share/hayabusa-rules`, `/opt/hayabusa*/rules`). Example: `Environment=HAYABUSA_RULES_DIR=/srv/forensics/hayabusa-rules` in the gateway systemd unit file. |
| `VHIR_SHARD_BREAKER_THRESHOLD` | `3` | Consecutive shard-limit batch failures before the bulk-write circuit breaker halts ingest. |
| `VHIR_INTEL_BREAKER_THRESHOLD` | `10` | Consecutive non-rate-limit OpenCTI errors before enrichment halts. |
| `VHIR_INTEL_RATE_LIMIT_RETRIES` | `5` | Per-IOC retry cap when OpenCTI rate-limits. |
| `VHIR_INTEL_MIN_INTERVAL_MS` | `100` | Minimum milliseconds between OpenCTI requests (default ~10 QPS). Prevents self-inflicted rate limits. Clamped to a 10ms floor. |

All thresholds clamp to a sane lower bound (operator typo of `0` won't disable safety).

### First-run ordering note (cold clusters)

Index templates are installed by the MCP server at its first verified
OpenSearch connection (inside `ensure_winlog_pipeline` /
`install_all_templates`). On a freshly set-up cluster, start the
Valhuntir gateway (or the opensearch-mcp server) at least once before
running `vhir idx ingest …` directly from the CLI.

Direct CLI ingest on a cluster where templates have never been
installed will create indices with OpenSearch's default dynamic
mappings (including `number_of_replicas: 1`) — no data loss, but the
replicas-0 and per-artifact-type mappings won't apply until the
templates land. MCP-driven ingest (via `idx_ingest`, etc.) is
unaffected; the server boot path installs templates before spawning
any ingest subprocess.

## Template Priorities

15 index templates with non-overlapping priorities:

| Priority | Template | Pattern |
|----------|----------|---------|
| 10 | CSV (EZ tools) | `case-*-{tool}-*` |
| 11 | Delimited | `case-*-delim-*`, `case-*-zeek-*`, `case-*-bodyfile-*` |
| 12 | JSON | `case-*-json-*` |
| 15 | Vol3 memory | `case-*-vol-*` |
| 18 | Hayabusa alerts | `case-*-hayabusa-*` |
| 19 | EVTX | `case-*-evtx-*` |
| 20 | Prefetch | `case-*-prefetch-*` |
| 21 | SRUM | `case-*-srum-*` |
| 22 | Transcripts | `case-*-transcripts-*` |
| 23 | W3C (IIS/Firewall) | `case-*-iis-*`, `case-*-httperr-*`, `case-*-firewall-*` |
| 24 | Defender | `case-*-defender-*` |
| 25 | Tasks | `case-*-tasks-*` |
| 26 | WER | `case-*-wer-*` |
| 27 | SSH | `case-*-ssh-*` |
| 28 | Access log | `case-*-accesslog-*` |

## Requirements

- Python 3.10+
- Docker (for OpenSearch)
- 8GB+ RAM recommended (OpenSearch heap + parsing)

Optional:
- Volatility 3 (for memory forensics)
- Gateway + windows-triage-mcp (for triage enrichment)
- Gateway + opencti-mcp (for threat intel enrichment)

**Docker container data:** OpenSearch stores all indexed evidence in a Docker named volume (`opensearch-data`). Removing or recreating the container with `docker rm -f` destroys all indices. Use `vhir backup --all` before any Docker maintenance. The named volume persists across `docker compose down && up -d` (normal restart) but NOT across `docker volume rm` or `docker system prune --volumes`.

## Development

```bash
pip install -e ".[test]"
ruff check . && ruff format --check .
pytest tests/
```

## License

MIT License - see [LICENSE](LICENSE)
