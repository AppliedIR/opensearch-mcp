#!/usr/bin/env python3
# ruff: noqa: E501
"""Generate synthetic test data for opensearch-mcp parser tests.

Creates /tmp/opensearch-test-data/ with 19 fixture files exercising all
parser code paths. Uses original investigation scenario with RFC 5737
TEST-NET IPs, RFC 2606 reserved domains, and generic hostnames.

Scenario: Corporate breach at Fictive Corp — phishing email delivers
updater.exe → credential theft → lateral movement via PsExec →
webshell persistence → data exfiltration.

Run once before pytest:
    python tests/generate_test_data.py
"""

from __future__ import annotations

import textwrap
from pathlib import Path

OUT = Path("/tmp/opensearch-test-data")

# === Identifiers (all original — no case-specific data) ===

ATTACKER_IP = "198.51.100.23"
DC_IP = "203.0.113.10"
TARGET_IP = "203.0.113.22"
INTERNAL_IP = "203.0.113.4"
EXTERNAL_IP = "198.51.100.50"
C2_DOMAIN = "bad-actor.example"
CORP_DOMAIN = "contoso"
ATTACKER_USER = "jdoe-admin"
NORMAL_USER = "jsmith"
SVC_ACCOUNT = "svc-backup"
MALWARE_BIN = "updater.exe"
WEBSHELL_PATH = "/aspnet_client/system_web.aspx"
WEBSHELL_FILE = "debug.aspx"
TASK_NAME = "Backup_Sync_Service"
HOSTNAME_WS = "WS05"
HOSTNAME_DC = "DC01"
HOSTNAME_RD = "WS01"
MALWARE_SIG = "Generic Command Shell"


def _write(relpath: str, content: str) -> None:
    """Write content to OUT/relpath, creating dirs as needed."""
    p = OUT / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")


def _write_raw(relpath: str, content: str) -> None:
    """Write raw content (no dedent) to OUT/relpath."""
    p = OUT / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def gen_accesslog_combined():
    """Apache/Nginx combined log format — 6 lines with IPs, users, paths, UAs."""
    lines = [
        f'{ATTACKER_IP} - - [25/Jan/2023:14:30:01 +0000] "POST {WEBSHELL_PATH} HTTP/1.1" 200 1024 "-" "python-requests/2.28.1"',
        f'{ATTACKER_IP} - {ATTACKER_USER} [25/Jan/2023:14:30:05 +0000] "GET {WEBSHELL_PATH} HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
        '::1 - - [25/Jan/2023:14:30:10 +0000] "GET /health HTTP/1.1" 200 64 "-" "curl/7.88.1"',
        f'{ATTACKER_IP} - - [25/Jan/2023:14:31:00 +0000] "POST /upload/{WEBSHELL_FILE} HTTP/1.1" 201 256 "-" "curl/7.88.1"',
        f'{TARGET_IP} - - [25/Jan/2023:14:32:00 +0000] "GET /index.html HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
        f'{ATTACKER_IP} - - [25/Jan/2023:14:33:00 +0000] "GET /admin/config HTTP/1.1" 403 - "https://{C2_DOMAIN}/ref" "python-requests/2.28.1"',
    ]
    _write_raw("accesslog/access.log", "\n".join(lines) + "\n")


def gen_accesslog_common():
    """Apache common log format — 2 lines, generic IPs."""
    lines = [
        '10.0.0.1 - admin [25/Jan/2023:10:00:00 +0000] "GET /status HTTP/1.1" 200 512',
        '10.0.0.2 - - [25/Jan/2023:10:01:00 +0000] "GET /favicon.ico HTTP/1.1" 404 0',
    ]
    _write_raw("accesslog/access-common.log", "\n".join(lines) + "\n")


def gen_defender_mplog():
    """Windows Defender MPLog — detection events and exclusions."""
    lines = [
        f"2023-01-17T14:30:00.000Z DETECTION_ADD Name: Trojan:Win32/{MALWARE_SIG}#ThreatType: Trojan#file: C:\\Windows\\System32\\{MALWARE_BIN}",
        f"2023-01-17T14:30:02.000Z process: C:\\Windows\\System32\\svchost.exe severity: Severe",
        f"2023-01-17T14:30:05.000Z Adding exclusion: C:\\Users\\{ATTACKER_USER}\\AppData\\Local\\Temp",
        f"2023-01-17T14:30:08.000Z Removing exclusion: C:\\Users\\Public\\Downloads",
        f"2023-01-17T14:30:10.000Z DETECTION_CLEAN Name: Trojan:Win32/{MALWARE_SIG}#file: C:\\Windows\\System32\\{MALWARE_BIN}",
    ]
    _write_raw("defender/MPLog-20230117-143000.log", "\n".join(lines) + "\n")


def gen_delimited_auth_tsv():
    """TSV with auth events — timestamps, usernames, IPs."""
    header = "timestamp\tuser\tsource_ip\tstatus\tmethod"
    rows = [
        f"2023-01-25T14:00:00Z\t{ATTACKER_USER}\t{ATTACKER_IP}\tsuccess\tntlm",
        f"2023-01-25T14:01:00Z\t{ATTACKER_USER}\t{ATTACKER_IP}\tsuccess\tkerberos",
        f"2023-01-25T14:02:00Z\t{NORMAL_USER}\t{TARGET_IP}\tfailed\tntlm",
        f"2023-01-25T14:03:00Z\t{NORMAL_USER}\t{DC_IP}\tsuccess\tkerberos",
    ]
    _write_raw("delimited/auth.tsv", header + "\n" + "\n".join(rows) + "\n")


def gen_delimited_bodyfile():
    """Bodyfile format (MFT timeline) — pipe-delimited."""
    lines = [
        f"0|C:/Windows/System32/{MALWARE_BIN}|12345|-/-rwxrwxrwx|0|0|65536|1674654600|1674654600|1674654600|1674654600",
        "0|C:/Windows/System32/cmd.exe|12346|-/-rwxrwxrwx|0|0|302080|1609459200|1609459200|1609459200|1609459200",
        "0|C:/Users/Public/Documents/exfil.docx|12347|-/-rwxrwxrwx|0|0|524288|1674655200|1674655200|1674655200|1674655200",
        "0|C:/Windows/Temp/payload.dll|12348|-/-rwxrwxrwx|0|0|131072|1674654900|0|1674654900|1674654900",
    ]
    _write_raw("delimited/body.txt", "\n".join(lines) + "\n")


def gen_delimited_zeek_conn():
    """Zeek connection log with headers."""
    header = "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n"
    rows = [
        f"1674654601.000000\tCbcF4e1\t{ATTACKER_IP}\t49832\t{DC_IP}\t445\ttcp\t-\t1.200\t1024\t2048\tSF",
        f"1674654602.000000\tCbcF4e2\t{ATTACKER_IP}\t49833\t{TARGET_IP}\t3389\ttcp\t-\t30.500\t4096\t8192\tSF",
        f"1674654603.000000\t-\t{TARGET_IP}\t49834\t{EXTERNAL_IP}\t443\ttcp\tssl\t5.100\t512\t1024\tSF",
    ]
    _write_raw("delimited/conn.log", header + "\n".join(rows) + "\n")


def gen_delimited_supertimeline():
    """L2T CSV supertimeline format — Plaso output."""
    header = "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra"
    rows = [
        f"01/25/2023,14:30:00,UTC,MACB,FILE,NTFS $MFT,Last Written,{ATTACKER_USER},{HOSTNAME_WS},C:/Windows/System32/{MALWARE_BIN},NTFS file entry,2,C:/Windows/System32/{MALWARE_BIN},12345,-,ntfs,filestat",
        f"01/25/2023,14:31:00,UTC,...B,REG,HKLM\\SYSTEM,Registry Key,SYSTEM,{HOSTNAME_WS},PSEXESVC service created,Registry key last written,2,HKLM/SYSTEM/CurrentControlSet/Services/PSEXESVC,0,-,winreg,winreg_default",
        f"01/25/2023,14:35:00,UTC,MACB,FILE,NTFS $MFT,Last Written,{NORMAL_USER},{HOSTNAME_WS},C:/Users/Public/staging.zip,NTFS file entry,2,C:/Users/Public/staging.zip,12348,-,ntfs,filestat",
    ]
    _write_raw("delimited/supertimeline.csv", header + "\n" + "\n".join(rows) + "\n")


def gen_delimited_timeline():
    """Simple CSV timeline."""
    header = "timestamp,host,source,event,user,detail"
    rows = [
        f"2023-01-25T14:30:00Z,{HOSTNAME_WS},filesystem,file_created,{ATTACKER_USER},C:\\Windows\\System32\\{MALWARE_BIN}",
        f"2023-01-25T14:31:00Z,{HOSTNAME_WS},registry,service_created,SYSTEM,PSEXESVC",
        f"2023-01-25T14:35:00Z,{HOSTNAME_WS},filesystem,file_created,{NORMAL_USER},C:\\Users\\Public\\staging.zip",
    ]
    _write_raw("delimited/timeline.csv", header + "\n" + "\n".join(rows) + "\n")


def gen_firewall_log():
    """Windows Firewall W3C log — DROP/ALLOW with TCP/UDP."""
    _write(
        "firewall/pfirewall.log",
        f"""\
        #Version: 1.5
        #Fields: date time action protocol src-ip dst-ip src-port dst-port
        2023-01-25 14:30:00 DROP TCP {ATTACKER_IP} {TARGET_IP} 49832 445
        2023-01-25 14:30:01 ALLOW TCP {DC_IP} {TARGET_IP} 49833 3389
        2023-01-25 14:30:02 DROP UDP {ATTACKER_IP} {TARGET_IP} 53 53
        2023-01-25 14:30:03 ALLOW TCP {TARGET_IP} {DC_IP} 49834 88
        """,
    )


def gen_iis_httperr():
    """HTTP.sys error log."""
    _write(
        "iis/httperr1.log",
        f"""\
        #Software: Microsoft HTTP API 2.0
        #Version: 1.0
        #Fields: date time c-ip c-port s-ip s-port cs-version cs-method cs-uri sc-status
        2023-01-25 14:30:00 {ATTACKER_IP} 49832 {DC_IP} 80 HTTP/1.1 POST {WEBSHELL_PATH} 500
        2023-01-25 14:30:01 {ATTACKER_IP} 49833 {DC_IP} 80 HTTP/1.1 GET /nonexist 404
        """,
    )


def gen_iis_access_log():
    """IIS W3C access log with fields header."""
    _write(
        "iis/u_ex230125.log",
        f"""\
        #Software: Microsoft Internet Information Services 10.0
        #Version: 1.0
        #Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port c-ip cs(User-Agent) sc-status
        2023-01-25 14:30:00 {DC_IP} POST {WEBSHELL_PATH} cmd=whoami 80 {ATTACKER_IP} python-requests/2.28.1 200
        2023-01-25 14:30:05 {DC_IP} GET /default.aspx - 80 {TARGET_IP} Mozilla/5.0 200
        2023-01-25 14:30:10 {DC_IP} POST /upload/{WEBSHELL_FILE} - 80 {ATTACKER_IP} curl/7.88.1 201
        2023-01-25 14:30:15 {DC_IP} GET /robots.txt - 80 {TARGET_IP} Googlebot/2.1 200
        """,
    )


def gen_json_mixed_timestamps():
    """JSONL with varying timestamp formats."""
    import json

    records = [
        {"@timestamp": "2023-01-25T14:30:00Z", "message": "test1", "level": "info"},
        {"timestamp": "2023-01-25 14:31:00", "message": "test2", "level": "warn"},
        {"ts": 1674654660.0, "message": "test3", "level": "error"},
    ]
    lines = [json.dumps(r) for r in records]
    _write_raw("json/mixed-timestamps.jsonl", "\n".join(lines) + "\n")


def gen_json_suricata_eve():
    """Suricata EVE JSON — alert, dns, flow, http events."""
    import json

    records = [
        {
            "timestamp": "2023-01-25T14:30:00.000000+0000",
            "event_type": "alert",
            "src_ip": ATTACKER_IP,
            "dest_ip": DC_IP,
            "alert": {
                "signature": f"ET MALWARE {MALWARE_SIG} CnC Beacon",
                "category": "A Network Trojan was Detected",
                "severity": 1,
            },
        },
        {
            "timestamp": "2023-01-25T14:30:01.000000+0000",
            "event_type": "dns",
            "src_ip": DC_IP,
            "dest_ip": "8.8.8.8",
            "dns": {"type": "query", "rrname": C2_DOMAIN, "rrtype": "A"},
        },
        {
            "timestamp": "2023-01-25T14:30:02.000000+0000",
            "event_type": "flow",
            "src_ip": ATTACKER_IP,
            "dest_ip": EXTERNAL_IP,
            "proto": "TCP",
            "dest_port": 443,
            "flow": {"bytes_toserver": 4096, "bytes_toclient": 1024},
        },
        {
            "timestamp": "2023-01-25T14:30:03.000000+0000",
            "event_type": "http",
            "src_ip": ATTACKER_IP,
            "dest_ip": DC_IP,
            "http": {
                "hostname": C2_DOMAIN,
                "url": "/beacon",
                "http_method": "POST",
                "status": 200,
            },
        },
        {
            "timestamp": "2023-01-25T14:30:04.000000+0000",
            "event_type": "flow",
            "src_ip": TARGET_IP,
            "dest_ip": EXTERNAL_IP,
            "proto": "TCP",
            "dest_port": 80,
            "flow": {"bytes_toserver": 2048, "bytes_toclient": 512},
        },
    ]
    lines = [json.dumps(r) for r in records]
    _write_raw("json/suricata-eve.jsonl", "\n".join(lines) + "\n")


def gen_json_tshark():
    """tshark JSON array with frame/ip/tcp layers."""
    import json

    packets = [
        {
            "_source": {
                "layers": {
                    "frame": {"frame.time_epoch": "1674654600.000000"},
                    "ip": {"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2"},
                    "tcp": {"tcp.srcport": "49832", "tcp.dstport": "80"},
                }
            }
        },
        {
            "_source": {
                "layers": {
                    "frame": {"frame.time_epoch": "1674654601.000000"},
                    "ip": {"ip.src": "10.0.0.2", "ip.dst": "10.0.0.1"},
                    "tcp": {"tcp.srcport": "80", "tcp.dstport": "49832"},
                }
            }
        },
    ]
    _write_raw("json/tshark-packets.json", json.dumps(packets, indent=2) + "\n")


def gen_ssh_log():
    """sshd auth log — accepted and failed entries, 6 events."""
    lines = [
        f"2023-01-25 14:30:00 sshd: Accepted publickey for {ATTACKER_USER} from {ATTACKER_IP} port 49832 ssh2: RSA SHA256:abc123",
        f"2023-01-25 14:30:05 sshd: Failed password for {ATTACKER_USER} from {ATTACKER_IP} port 49833 ssh2",
        f"2023-01-25 14:30:10 sshd: Accepted password for {NORMAL_USER} from {INTERNAL_IP} port 49834 ssh2",
        f"2023-01-25 14:30:15 sshd: Failed password for root from {ATTACKER_IP} port 49835 ssh2",
        f"2023-01-25 14:30:20 sshd: Failed password for invalid user admin from {EXTERNAL_IP} port 49836 ssh2",
        f"2023-01-25 14:30:25 sshd: Accepted publickey for {NORMAL_USER} from {INTERNAL_IP} port 49837 ssh2: ED25519 SHA256:def456",
    ]
    _write_raw("ssh/sshd.log", "\n".join(lines) + "\n")


def gen_tasks_persistence():
    """Windows scheduled task XML — non-system task with persistence indicators."""
    _write_raw(
        f"tasks/{TASK_NAME}",
        f"""\
<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>{CORP_DOMAIN}\\{SVC_ACCOUNT}</Author>
    <Description>System backup synchronization</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2023-01-25T06:00:00</StartBoundary>
      <Repetition>
        <Interval>PT1H</Interval>
      </Repetition>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <UserId>{CORP_DOMAIN}\\{SVC_ACCOUNT}</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>C:\\Windows\\System32\\{MALWARE_BIN}</Command>
      <Arguments>-s -hidden</Arguments>
    </Exec>
  </Actions>
</Task>
""",
    )


def gen_tasks_system():
    """Windows scheduled task XML — system task (baseline)."""
    _write_raw(
        "tasks/Microsoft/Windows/WindowsUpdate",
        """\
<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <Description>Schedules Windows Update scan</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2023-01-01T03:00:00</StartBoundary>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>C:\\Windows\\System32\\usoclient.exe</Command>
      <Arguments>StartScan</Arguments>
    </Exec>
  </Actions>
</Task>
""",
    )


def gen_transcripts():
    """PowerShell transcript with session header + commands."""
    _write_raw(
        f"transcripts/Users/{ATTACKER_USER}/Documents/PowerShell_transcript.WS01.txt",
        f"""\
**********************
Windows PowerShell transcript start
Start time: 20230125143000
Username: {CORP_DOMAIN}\\{ATTACKER_USER}
RunAs User: {CORP_DOMAIN}\\{ATTACKER_USER}
Configuration Name: Microsoft.PowerShell
Machine: {HOSTNAME_RD} ({HOSTNAME_RD})
Host Application: C:\\Windows\\System32\\wsmprovhost.exe
Process ID: 5432
PSVersion: 5.1.19041.2364
**********************
PS>whoami
{CORP_DOMAIN}\\{ATTACKER_USER}
PS>ipconfig /all
Windows IP Configuration

   Host Name . . . . . . . . . . . . : {HOSTNAME_RD}
**********************
Windows PowerShell transcript end
End time: 20230125143500
**********************
""",
    )


def gen_wer():
    """Windows Error Reporting crash report."""
    _write(
        f"wer/AppCrash_{MALWARE_BIN}_abcdef/Report.wer",
        f"""\
        Version=1
        EventType=APPCRASH
        EventTime=133191594000000000
        ReportType=2
        Consent=1
        ReportIdentifier=abc123-def456
        Sig[0].Name=Application Name
        Sig[0].Value={MALWARE_BIN}
        Sig[1].Name=Application Version
        Sig[1].Value=1.0.0.0
        Sig[2].Name=Application Timestamp
        Sig[2].Value=63ab1234
        Sig[3].Name=Fault Module Name
        Sig[3].Value=ntdll.dll
        Sig[4].Name=Fault Module Version
        Sig[4].Value=10.0.19041.2364
        Sig[5].Name=Fault Module Timestamp
        Sig[5].Value=5bc12345
        Sig[6].Name=Exception Code
        Sig[6].Value=c0000005
        Sig[7].Name=Exception Offset
        Sig[7].Value=000a1234
        DynamicSig[1].Name=OS Version
        DynamicSig[1].Value=10.0.19041.2
        """,
    )


def main():
    """Generate all test data files."""
    if OUT.exists():
        import shutil

        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    gen_accesslog_combined()
    gen_accesslog_common()
    gen_defender_mplog()
    gen_delimited_auth_tsv()
    gen_delimited_bodyfile()
    gen_delimited_zeek_conn()
    gen_delimited_supertimeline()
    gen_delimited_timeline()
    gen_firewall_log()
    gen_iis_httperr()
    gen_iis_access_log()
    gen_json_mixed_timestamps()
    gen_json_suricata_eve()
    gen_json_tshark()
    gen_ssh_log()
    gen_tasks_persistence()
    gen_tasks_system()
    gen_transcripts()
    gen_wer()

    count = sum(1 for _ in OUT.rglob("*") if _.is_file())
    print(f"Generated {count} test data files in {OUT}")


if __name__ == "__main__":
    main()
