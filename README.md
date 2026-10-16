![Valhuntir](docs/images/vhir-logo.png)

# opensearch-mcp
[![CI](https://github.com/AppliedIR/opensearch-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/AppliedIR/opensearch-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/AppliedIR/opensearch-mcp/blob/main/LICENSE)

Forensic evidence indexing for [Valhuntir](https://github.com/AppliedIR/Valhuntir) — parse, index, and query digital forensic artifacts at scale using OpenSearch.

> **Important Note** — While extensively tested, this is a new platform.
> ALWAYS verify results and guide the investigative process. If you just
> tell Valhuntir to "Find Evil" it will more than likely hallucinate
> rather than provide meaningful results. The AI can accelerate, but the
> human must guide it and review all decisions.

## Why This Exists

A KAPE triage collection from 30 hosts produces ~50 million evidence records across hundreds of artifact types. An LLM reading these directly would consume billions of tokens and still miss patterns buried in the noise.

opensearch-mcp solves this by **parsing evidence programmatically and indexing it into OpenSearch**, then giving the LLM purpose-built query tools. The LLM asks structured questions ("show me all 4688 events where the parent process is cmd.exe") and gets precise answers — no token waste on raw log parsing, no missed evidence from context window limits. The LLM focuses on investigation logic. The parsers handle the data.

## What It Does

### Ingest

16 parsers cover the forensic evidence spectrum:

| Parser | Artifacts | Source |
|--------|-----------|--------|
| evtx | Windows Event Logs | pyevtx-rs (ECS-normalized) |
| EZ Tools | Shimcache, Amcache, MFT, USN, Registry (system hives, and each user's NTUSER.DAT and UsrClass.dat), Shellbags, Jumplists, LNK, Recyclebin, Timeline | Eric Zimmerman tools via wintools-mcp |
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
| Plaso | Linux and macOS volumes (the OS preset); on Windows, Chromium history, WebCache and SetupAPI | Plaso, into `case-*-plaso-*` (see [Plaso: known gaps](#plaso-fallback-known-gaps)) |

Every parser produces:
- Deterministic content-based document IDs (re-ingest = zero duplicates)
- Full provenance: `host.name`, `host.id`, `vhir.source_file`, `vhir.ingest_audit_id`, `vhir.content_hash`, `vhir.parse_method`, `pipeline_version`, and `vhir.original.path` and `vhir.original.sha256` when the ingest started from registered evidence
- Proper `@timestamp` with timezone handling (local-time artifacts require `--source-timezone`)

### Query (MCP Tools)

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
| `idx_enrich_intel` | Threat intel enrichment via lookup_ioc (threat intel) |
| `idx_list_detections` | Hayabusa detection alerts (count and query) |
| `idx_host_inventory` | A case's machines (`host.id`), the names and evidence units behind each, and ingests awaiting host confirmation |

### Enrich

Two post-ingest enrichment pipelines add context without LLM token cost:

**Triage baseline** — Checks indexed filenames and services against the Windows baseline database (via windows-triage-mcp, part of the [sift-mcp](https://github.com/AppliedIR/sift-mcp) monorepo). Stamps documents with `triage.verdict` (EXPECTED, SUSPICIOUS, UNKNOWN, EXPECTED_LOLBIN). Includes 14 registry persistence detection rules (IFEO, Winlogon, LSA, Print Monitors, etc.) that run as direct OpenSearch queries — no external calls needed.

**Threat intel** — Extracts unique external IPs, hashes, and domains from indexed data, looks each up with `lookup_ioc` (threat intel) via the gateway, and stamps every document carrying it with an entry in `threat_intel.iocs`: the outcome (MATCH, NO_MATCH, or UNAVAILABLE when it couldn't be asked) and each platform's own records. No verdict is computed. 200 unique IOCs checked in ~10 seconds vs. 100K inline lookups that would take 83 minutes.

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
MCP tools <-- LLM queries here (structured, ~500 tokens each)
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

This starts a Docker container with OpenSearch 3.5, registers all 16 index templates (including Hayabusa and Plaso), and creates the GeoIP enrichment pipeline. Detection is handled by Hayabusa (3,700+ Sigma-based rules) which runs automatically after evtx ingest if installed.

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

Every ingest waits until the hosts its evidence names are confirmed in the Examiner Portal's Hosts tab (`vhir portal`). Upload the list of machines in scope there before the first ingest; hosts on the list confirm as the evidence arrives. Until then the CLI prints only "Waiting for host confirmation (N host name(s)): ..." and the host names it waits on. Confirm them in the Hosts tab, or choose Start now there to let the run write with its hosts as proposed.

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
idx_timeline(query="threat_intel.iocs.outcome:MATCH", interval="1h")
```

### 4. Enrich

```bash
# Triage baseline (via gateway to windows-triage-mcp)
# Runs automatically at the end of a scan ingest (opensearch-ingest scan,
# vhir ingest); --skip-triage turns it off. A re-run is MCP-only:
# idx_enrich_triage, below.

# Threat intel
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
| `VHIR_INTEL_BREAKER_THRESHOLD` | `10` | Consecutive lookup errors, or consecutive UNAVAILABLE answers from every provider, before enrichment halts. Rate limits don't count. |
| `VHIR_INTEL_RATE_LIMIT_RETRIES` | `5` | Per-IOC retry cap when a lookup is rate-limited. |
| `VHIR_INTEL_MIN_INTERVAL_MS` | `100` | Minimum milliseconds between threat-intel lookups (default ~10 QPS). Prevents self-inflicted rate limits. Clamped to a 10ms floor. |

All thresholds clamp to a sane lower bound (operator typo of `0` won't disable safety).

### First-run ordering note (cold clusters)

Index templates are installed by the MCP server at its first verified
OpenSearch connection (inside `ensure_winlog_pipeline` /
`install_all_templates`). On a freshly set-up cluster, start the
Valhuntir gateway (or the opensearch-mcp server) at least once before
running `vhir ingest …` directly from the CLI.

Direct CLI ingest on a cluster where templates have never been
installed will create indices with OpenSearch's default dynamic
mappings (including `number_of_replicas: 1`) — no data loss, but the
replicas-0 and per-artifact-type mappings won't apply until the
templates land. MCP-driven ingest (via `idx_ingest`, etc.) is
unaffected; the server boot path installs templates before spawning
any ingest subprocess.

## Template Priorities

16 index templates with non-overlapping priorities:

| Priority | Template | Pattern |
|----------|----------|---------|
| 10 | CSV (EZ tools) | `case-*-{tool}-*` |
| 11 | Delimited | `case-*-delim-*`, `case-*-zeek-*`, `case-*-bodyfile-*` |
| 12 | JSON | `case-*-json-*` |
| 15 | Vol3 memory | `case-*-vol-*` |
| 18 | Hayabusa alerts | `case-*-hayabusa-*` |
| 20 | Prefetch | `case-*-prefetch-*` |
| 21 | SRUM | `case-*-srum-*` |
| 22 | Transcripts | `case-*-transcripts-*` |
| 23 | W3C (IIS/Firewall) | `case-*-iis-*`, `case-*-httperr-*`, `case-*-firewall-*` |
| 24 | Defender | `case-*-defender-*` |
| 25 | Tasks | `case-*-tasks-*` |
| 26 | WER | `case-*-wer-*` |
| 27 | SSH | `case-*-ssh-*` |
| 28 | Access log | `case-*-accesslog-*` |
| 29 | Plaso | `case-*-plaso-*` |
| 100 | EVTX | `case-*-evtx-*` |

## Plaso fallback: known gaps

Linux and macOS hosts are parsed by Plaso with the OS preset (`macos` adds `unified_logging`); Windows hosts get Plaso's Chromium history, WebCache and SetupAPI parsers over `Users` and `Windows/inf`.

- **Folders** are read as the examiner, or, when `sudo -n` works, as the examiner with root's read capability only, so files only root can read are included.
- **Disk images** (raw, E01, VMDK, VHD/VHDX, `.dmg`, `.sparseimage`): Plaso reads each Linux or macOS volume straight off the image, with no mount and no root, including LVM volumes and APFS containers. Plaso applies each volume's own time zone (from an `etc/localtime` link); `--source-timezone` reaches only volumes where it finds none, and the status says when an override wasn't applied. A `.dmg` is never mounted. LVM is never loop-mounted, so the analysis host can't activate the evidence's volume group. Each volume is its own host, named `<image>-<partition>` (for example `disk-0a1b2c3d-p2-lvm1`) unless `--hostname` is given, and its documents carry `vhir.volume`. Windows volumes are mounted and parsed as before.
- **Not parsed, and named in the status:** encrypted volumes (FileVault, LUKS) and APFS containers holding one, volumes with no file system or no OS root, and partitions or volumes numbered 10 or higher (Plaso selects those wrongly). A Linux root Plaso can't read off the image (btrfs, for example) is parsed from its mount instead. Each host's `plaso` status entry lists the events per parser, the time zone used and where it came from (the registry, `etc/localtime` or `etc/timezone`, the examiner's `--source-timezone`, or unknown), and every file Plaso warned about. Plaso 20240308 also loses some input without any warning:

| File | OS | Expected parser | Gap |
|------|----|-----------------|-----|
| `var/log/dpkg.log*` | Linux | `text/dpkg` | no events under the `linux` preset (the parser alone reads it) |
| `root/.bash_history`, `home/*/.bash_history`, `Users/*/.bash_history` | Linux, macOS | `text/bash_history` | lines without `#epoch` timestamps give no events |
| `Library/Receipts/InstallHistory.plist` | macOS | `plist/macos_install_history` | a top-level array isn't parsed |
| `Library/LaunchDaemons/*.plist`, `Library/LaunchAgents/*.plist`, `Users/*/Library/LaunchAgents/*.plist` | macOS | `plist/launchd_plist` | a plist missing any of the five keys it needs gives no event |

Also:
- Junk or truncated files are dropped without a warning.
- Syslog lines carry no year. Plaso takes it from the file's own time, so a copied folder without its original times gets the copy's year.
- utmp records with an empty host field show `localhost`.
- The per-event `hostname` field is Plaso's: the remote host for utmp, `_HOSTNAME` for the journal. The host the evidence came from is `host.name`.
- filestat gives 3 times per file from a folder (no creation time) and 4 from a disk image. On a folder the times may reflect the copy, not the original system, and the status says so.
- psort removes duplicate events, so the indexed count can be lower than the count Plaso reports (6,134 → 6,122 on one Windows host).
- An APFS container is one Plaso run. The zone of the volume that holds a zone file applies to that volume; other volumes in the container without a zone file are stored as UTC. The status names the volume the zone came from.
- On an image, when `/etc/localtime` is a copy rather than a link, Plaso may use UTC or a fixed-offset abbreviation (an hour or more off); the status says so.
- A dirty `NTUSER.DAT`'s transaction logs (`ntuser.dat.LOG1`) aren't found by RECmd on a case-sensitive file system, which looks for `NTUSER.DAT.LOG1`.
- These were measured with Plaso 20240308; later releases may fix some.

## Requirements

- Python 3.10+
- Docker (for OpenSearch)
- 8GB+ RAM recommended (OpenSearch heap + parsing)

Optional:
- Volatility 3 (for memory forensics)
- Gateway + windows-triage-mcp (for triage enrichment)
- Gateway + the threat-intel backend (for threat intel enrichment)

**Docker container data:** OpenSearch stores all indexed evidence in a Docker named volume (`opensearch-data`, in compose project `docker`). The volume survives removing or recreating the container (`docker rm -f`, `docker compose down && up -d`, `setup-opensearch.sh`). It is lost to `docker volume rm` and `docker system prune --volumes`; a compose run under another project name (`-p`) starts a new, empty volume beside it. Before Docker maintenance, back up each case's indices: `vhir backup <destination> --case <case-id> --include-opensearch`, once per case (`vhir backup --all` covers only the one case it backs up).

## Development

```bash
pip install -e ".[test]"
ruff check . && ruff format --check .
pytest tests/
```

## Acknowledgments

Architecture and direction by Steve Anson. Implementation by Claude Code (Anthropic). Code review by Codex (OpenAI). Design inspiration drawn from Lenny Zeltser's [REMnux MCP](https://github.com/REMnux/remnux-mcp-server).

## Clear Disclosure

I do DFIR. I am not a developer. This project would not exist without Claude Code handling the implementation. While an immense amount of effort has gone into design, testing, and review, I fully acknowledge that I may have been working hard and not smart in places. My intent is to jumpstart discussion around ways this technology can be leveraged for efficiency in incident response while ensuring that the ultimate responsibility for accuracy remains with the human examiner.

## License

MIT License - see [LICENSE](LICENSE)
