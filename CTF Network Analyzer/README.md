# BADNET — Network CTF Analyzer

Passive network forensics for authorised CTF challenges and lab captures.

BADNET reads a `.pcap`/`.pcapng` file and tells you what is in it: who talked to
whom, which streams are interesting, and where the flags and credentials are.
It never touches the network — no packets are sent, nothing is executed from the
capture, and every byte of capture content is treated as untrusted hostile input.

> **Authorisation only.** Analyse systems you own or have explicit written
> permission to test.

---

## Status

This is **Phase 1 of a six-phase build**. Phase 1 is complete and verified; the
later phases are not implemented yet. This section is the single most important
one in this README, because it separates what BADNET does today from what it is
planned to do.

### Working now

| Area | What BADNET actually does today |
| --- | --- |
| `info` | File facts, capture timing, protocol hierarchy, top talkers and ports |
| `analyze` | Builds a case directory: capture facts, connection table, TCP stream table |
| `auto` | Runs the pipeline, then prints an investigation summary and ranked findings |
| `config` | Prints the effective configuration, or writes a documented YAML template |
| `doctor` | Reports every dependency, its version, and what degrades without it |
| `version` | Prints the version (`--json` supported) |
| TCP reassembly | Full in-order reconstruction of both directions of every TCP stream, with correct client/server orientation even when the capture starts mid-stream |
| Signatures | 3 YAML files, 52 regex patterns, all validated and compiled at load |
| Case storage | Append-only NDJSON plus `metadata.json`. No SQLite anywhere |

### Not implemented yet

These are planned. Commands and flags below that do not exist are marked as
such wherever they appear.

| Planned | Notes |
| --- | --- |
| `badnet stream` | Per-stream object dumping. **Does not exist yet** — `auto` currently *suggests* it. |
| `badnet search` | Regex sweep across the capture. **Does not exist yet** — `auto` currently *suggests* it. |
| `report.html` | Offline HTML report. **Does not exist yet** — `auto` currently *suggests* it. |
| Artifact extraction | `files/`, `http/`, `dns/`, `tls/` case directories are created but stay empty: `files recovered 0`. |
| Nmap integration | The `nmap/` case directory exists and `nmap` is detected, but no scan is run. Phase 1 is passive only. |
| HTTP/DNS/TLS detail parsers | `badnet/models/{http,dns,tls}.py` define the schemas; the per-record parsers land in Phase 2. |
| Content decoding | `max_decode_depth`, gzip bomb ratio limits and friends are configured but not yet applied to extracted data. |

Because artifacts are not extracted yet, `analyze` and `auto` legitimately
report `artifacts 0` and `findings 0` on **every** capture. Those counters are
wired up and correct; they are simply always zero at this phase.

---

## Requirements

**Required**

- Python 3.12 or newer
- [TShark](https://www.wireshark.org/) (`tshark` + `capinfos`) — the fast reader.
  BADNET also resolves TShark in the standard Wireshark install directories, so
  it works on Windows without `C:\Program Files\Wireshark` being on `PATH`.
- Python packages: `typer`, `rich`, `scapy`, `PyYAML`, `Jinja2`, `cryptography`

**Optional — every one degrades gracefully**

| Component | If missing |
| --- | --- |
| `nmap` | No service probing. Phase 1 does not use it regardless. |
| `file(1)` | File-type detection falls back to BADNET's built-in table |
| `strings(1)` | Falls back to BADNET's built-in scanner (same output, slower) |
| `python-magic` | Falls back to `file(1)`, then to the built-in table |
| `xxd` | Hex dumping falls back to `tshark` |
| `tcpdump` | Not required by any command |

Run `badnet doctor` at any time to see what is present and what you lose without it.

```console
$ badnet doctor
+--------------------------------------+
| BADNET  v1.0.0  Network CTF Analyzer |
+--------- environment check ----------+

component    status    version        notes
python       FOUND     3.12.10
typer        FOUND     0.27.2
rich         FOUND     15.0.0
scapy        FOUND     2.7.0
cryptography FOUND     50.0.2
python-magic NOT FOUND -              file type detection falls back to the
                                      file(1) binary and then BADNET's built-in
                                      table
tshark       FOUND     tshark 4.6.8
capinfos     FOUND     capinfos 4.6.8
nmap         FOUND     nmap 7.80
file         FOUND     file 5.48
strings      NOT FOUND -              string extraction uses BADNET's built-in
                                      scanner (same output, slower on large
                                      files)
tcpdump      NOT FOUND -              no raw packet triage helper; not required
                                      for any command
xxd          FOUND     -
```

`badnet doctor --json` gives the same data as JSON with keys `badnet`,
`requirements`, `reader` and `capable`.

---

## Install

```console
$ git clone <this repository> badnet
$ cd badnet
$ python -m venv .venv
```

**Windows (PowerShell)**

```console
$ .venv\Scripts\Activate.ps1
$ pip install -e ".[dev]"
```

**Linux / macOS**

```console
$ source .venv/bin/activate
$ pip install -e ".[dev]"
```

Verify the install:

```console
$ badnet doctor
$ badnet version
BADNET 1.0.0
```

The console script is `badnet`. Without installing you can run
`python -m badnet ...` from the repository root.

---

## Command reference

Every command accepts the same global options, so you can combine them freely.

| Option | Default | Effect |
| --- | --- | --- |
| `--output-dir DIR` | `output` | Where case directories are created |
| `--case NAME` | `<file stem>-<hash>` | Case name |
| `--force` | off | Re-analyse into an existing case. **Appends**; never deletes evidence |
| `--max-packets N` | all | Stop after N packets |
| `--verbose`, `-v` | off | Show unredacted secrets and INFO logs |
| `--no-color` | off | Disable colour (also honours the `NO_COLOR` env var) |
| `--quiet`, `-q` | off | Warnings and errors only |
| `--debug` | off | Full tracebacks plus a log file in the case's `logs/` |
| `--config FILE` | none | Load a YAML config |
| `--json` | off | Machine-readable JSON on stdout, no banner or progress |
| `--limit N` | `50` | Maximum rows displayed in tables |
| `--help`, `-h` | | Help for the command |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Error (bad input, failed analysis) |
| `2` | Usage error (bad flags, invalid config) |
| `3` | Missing required dependency |
| `130` | Interrupted; partial results kept and the case marked incomplete |

### `badnet doctor`

Check the environment. No capture needed.

```console
$ badnet doctor
$ badnet doctor --json
```

### `badnet info CAPTURE`

Read-only. **Creates no case directory and writes nothing to disk.**

```console
$ badnet info examples/sample.pcap
+--------------------------------------+
| BADNET  v1.0.0  Network CTF Analyzer |
+------------ sample.pcap -------------+

----------------------------------- Capture -----------------------------------
file          examples\sample.pcap
size          25.5 KiB
format        classic pcap, little-endian
link type     ether
snaplen       65535
packets       211
first packet  2026-01-01 12:00:00.020000 UTC
last packet   2026-01-01 12:00:09.129098 UTC
duration      9.109 s
avg rate      23.2 pkt/s
bit rate      19.9 kbps
malformed     0 packet(s)
reader        tshark
computed by   tshark, capinfos

--------------------- Protocols  (only protocols present) ---------------------
protocol packets
IPv4     210
UDP      132
DNS      131
TCP      77
HTTP     16
FTP      9
TLS      4
DHCP     1

--------------------------------- Top talkers ---------------------------------
sources
value          packets
10.10.10.50        116
10.10.10.1          61
93.184.216.34       26
198.51.100.7         6
0.0.0.0              1
destinations
value           packets
10.10.10.50           93
10.10.10.1            70
93.184.216.34         33
198.51.100.7          12
ports
value  packets
53         131
80          26
...
```

`--json` returns `info`, `protocols`, `malformed_packets`, `reader`, `degraded`.

### `badnet analyze CAPTURE`

Runs the passive pipeline and writes a case directory.

```console
$ badnet analyze examples/sample.pcap
+--------------------------------------+
| BADNET  v1.0.0  Network CTF Analyzer |
+---------- sample-516a10a3 -----------+

-------------------------------- What happened --------------------------------
capture      examples\sample.pcap
size         25.5 KiB
format       classic pcap, little-endian
packets      211
connections  78
streams      7
artifacts    0
findings     0
reader       tshark
elapsed      3.61s

--------------------------------- Case output ---------------------------------
  output\sample-516a10a3
  summary: summary.txt   metadata: metadata.json   data: *.ndjson
```

### `badnet auto CAPTURE`

Full investigation summary with ranked findings and suggested follow-ups.
Writes the same case directory as `analyze`.

```console
$ badnet auto examples/sample.pcap
+--------------------------------------+
| BADNET  v1.0.0  Network CTF Analyzer |
+---------- sample-516a10a3 -----------+

-------------------------------- What happened --------------------------------
capture           25.5 KiB classic pcap, little-endian
packets           211
duration          9.11 s
hosts seen        6
connections       78
TCP streams       7
files recovered   0
hashed artifacts  0
reader            tshark

-------------------------------- Findings  (0) --------------------------------
  No indicator matched the configured signatures in this capture.

------------------------- Suggested manual follow-ups ------------------------
  $ badnet stream ...\sample.pcap --id 0   # http 10.10.10.50:49152 -> ...
  $ badnet search ...\sample.pcap --regex 'flag\{|password|token'  # sweep everything
  $ less output\sample-516a10a3\report.html   # full offline report
```

`--ctf` (default) ranks findings flags → credentials → secrets → artifacts →
endpoints → anomalies → unusual ports. Use `--no-ctf` for the neutral ordering.

> The follow-up suggestions above reference `badnet stream`, `badnet search`
> and `report.html`. **None of those exist yet** — they are Phase 2+ commands.
> The suggestions are forward-looking, not runnable today.

### `badnet config [TEMPLATE_PATH]`

With no argument, prints the effective configuration. With a path, writes a
documented YAML template there.

```console
$ badnet config                       # show what is in effect
$ badnet config badnet.yaml           # write a template you can edit
$ badnet config --json                # machine-readable
```

`TEMPLATE_PATH` is **positional**, not `--template`.

### `badnet version`

```console
$ badnet version
BADNET 1.0.0
$ badnet version --json
{
  "badnet": "1.0.0"
}
```

---

## What the results actually contain

### The case directory

```
output/sample-516a10a3/
├── metadata.json           run provenance, tool versions, config, dataset stats
├── summary.txt             the text summary shown above
├── connections.ndjson      one row per connection (5-tuple)
├── streams/
│   └── streams.ndjson      one row per TCP stream
├── dns/
│   └── dns.ndjson          (empty — DNS records land in Phase 2)
├── http/
│   └── http.ndjson         (empty — HTTP objects land in Phase 2)
├── tls/
│   └── tls.ndjson          (empty — TLS records land in Phase 2)
├── files/
│   ├── files.ndjson        (empty — extraction lands in Phase 2)
│   └── strings.ndjson      (empty — strings land with extraction)
├── hashes/
│   └── hashes.ndjson       (empty — written alongside artifacts)
├── nmap/
│   └── nmap.ndjson         (empty — Phase 1 is passive)
└── logs/
    └── badnet.log             written only with --debug
```

The directory skeleton is created up front so the case layout is stable and
predictable even while a dataset is still empty. BADNET reserves 11 dataset
names — `packets`, `connections`, `dns`, `http`, `tls`, `streams`, `files`,
`strings`, `hashes`, `findings` and `nmap` — of which Phase 1 currently writes
only `connections` and `streams`.

### NDJSON format

One JSON object per line, UTF-8, `\n`-terminated, streamed rather than loaded
into memory. `grep` and `jq` work directly on them.

`connections.ndjson` — 23 fields per row:

```json
{"proto": "TCP", "a_ip": "10.10.10.50", "a_port": 49152, "b_ip": "93.184.216.34", "b_port": 80,
 "client_ip": "10.10.10.50", "client_port": 49152, "server_ip": "93.184.216.34", "server_port": 80,
 "packets": 16, "bytes": 2417,
 "a_to_b_packets": 9, "a_to_b_bytes": 1214, "b_to_a_packets": 7, "b_to_a_bytes": 1203,
 "first_seen": 1767268802.214104, "last_seen": 1767268802.227303, "duration": 0.0132,
 "stream_id": 0, "protocols": "eth:ethertype:ip:tcp:http:data-text-lines",
 "interesting_port": true, "service": "http", "tcp_flags_seen": ["0x0002", "0x0010", "..."]}
```

`a_ip`/`a_port` and `b_ip`/`b_port` are address-order stable. `client_*` and
`server_*` are resolved from the SYN; when no SYN is present they fall back to
the ephemeral-port side.

`service` is a real service name — `http`, `https`, `ftp`, `smb`, `dns`, `http-proxy`
— taken from the port→service table in `signatures/interesting_ports.yaml`. When
the port is not in that table it falls back to the most specific real dissector
layer, and finally to the transport name (`TCP`/`UDP`). It is deliberately *not*
the last entry of `protocols`, because that stack ends in payload dissectors such
as `data-text-lines`, which would label every web connection with an internal
tshark name.

`streams/streams.ndjson` — 20 fields per row:

```json
{"stream_id": 0, "proto": "TCP",
 "client_ip": "10.10.10.50", "client_port": 49152, "server_ip": "93.184.216.34", "server_port": 80,
 "client": "10.10.10.50:49152", "server": "93.184.216.34:80",
 "packets": 16, "bytes": 2417, "first_seen": 1767268802.214104, "last_seen": 1767268802.227303,
 "duration": 0.0132, "app_protocol": "http",
 "protocols": "eth:ethertype:ip:tcp:http:data-text-lines",
 "tcp_flags": ["0x0002", "0x0012", "0x0010", "0x0018", "0x0011"],
 "has_syn": true, "has_fin": true, "has_rst": true, "interesting_port": true}
```

`app_protocol` is a short label (`http`, `ftp`, `tls`) for sorting and filtering.
`protocols` is the full dissector layer stack, which is what tshark actually
reported — note that a stack may end in something like `data-text-lines`, which
is a real dissector name and not a protocol BADNET invented.

### `metadata.json`

```json
{
  "schema": "badnet/metadata/1.0",
  "analysis_started": "2026-10-02T11:50:32Z",
  "analysis_finished": "2026-10-02T11:50:36Z",
  "case": {
    "name": "sample-516a10a3",
    "input_path": "...\\examples\\sample.pcap",
    "input_sha256": "428cda8656383bf74e4ddfcfe1744e5dbc40635215cb791a26cef0e52a57f1af",
    "input_size": 26094,
    "input_format": "classic pcap, little-endian",
    "created": "2026-10-02T11:50:32Z",
    "status": "complete",
    "warnings": [],
    "notes": []
  },
  "tools": {
    "badnet": "1.0.0",
    "python": "3.12.10",
    "platform": "Windows 11 (AMD64)",
    "externals": { "tshark": "TShark (Wireshark) 4.6.8 ...", "capinfos": "..." }
  },
  "command_line": ["...\\__main__.py", "analyze", "examples\\sample.pcap"],
  "config": { "output_dir": "output", "interesting_ports": [21, 22, ...], ... },
  "options": {
    "max_packets": null,
    "keylog": null,
    "phases": ["info", "protocols", "connections", "streams"],
    "protocol_counts": { "IPv4": 210, "UDP": 132, "DNS": 131, "TCP": 77, "HTTP": 16, "FTP": 9, "TLS": 4, "DHCP": 1 },
    "pipeline_seconds": 3.937,
    "summary": "summary.txt"
  },
  "datasets": {
    "connections": { "rows": 78, "bytes": 41080 },
    "streams":     { "rows": 7,  "bytes": 3773 }
  },
  "runs": [ { "run": 1, "started": "...", "finished": "...", "status": "complete", "rows_before": {...} } ],
  "environment": { "cwd": "...", "argv0": "..." }
}
```

The SHA-256 of the input capture is recorded so a case can always be tied back
to the exact bytes that produced it.

### Case directories are append-only

Re-analysing with `--force` **appends**. Rows from earlier runs are never
rewritten or removed, because they are evidence:

```console
$ badnet analyze examples/sample.pcap --case force-test --quiet
run1 connections: 78   streams: 7
$ badnet analyze examples/sample.pcap --case force-test --force --quiet
run2 connections: 156  streams: 14
$ badnet analyze examples/sample.pcap --case force-test --force --quiet
run3 connections: 234  streams: 21
```

`metadata.json` gains a `runs[]` entry per run, each recording `rows_before`, so
you can still tell which rows came from which run. `case.created` keeps the
*original* creation time. Because datasets accumulate, `metadata.json`'s
`datasets` counts are cumulative — the `connections`/`streams` counters printed
by `analyze` and `auto` are for the current run only.

---

## Configuration

Precedence, lowest to highest:

```
built-in defaults  <  ~/.config/badnet/config.yaml  <  ./badnet.yaml  <  --config FILE  <  CLI flags
```

Write a fully commented template and edit it:

```console
$ badnet config badnet.yaml
```

Then use it with either `--config badnet.yaml` or by naming the file
`badnet.yaml` in the working directory.

Sections and what they control:

| Section | Controls |
| --- | --- |
| `output_dir` | Where cases are written |
| `interesting_ports` | Ports highlighted in connection/stream tables |
| `interesting_endpoints` | URI substrings worth a second look (case-insensitive) |
| `interesting_extensions` | File extensions worth extracting |
| `dns` | Tunnelling thresholds: `min_queries`, `high_unique_ratio`, `long_label_len`, `high_entropy`, `encoded_label_ratio`, `min_query_rate` |
| `limits` | Safety caps: `max_artifact_size`, `max_body_preview`, `max_strings_bytes`, `max_strings_count`, `max_decode_depth`, `max_decompress_ratio`, `max_preview_bytes`, `regex_timeout_ms` |
| `output` | `top_n`, `default_limit`, `include_banner`, `max_findings_shown`, `redact_secrets` |
| `signature_dir` | Where YAML signature files are loaded from |
| `use_libmagic`, `run_nmap_scripts`, `nmap_authorized`, `nmap_default_profile` | Optional tool behaviour |

An unusual port is **not** treated as evidence of anything. `interesting_ports`
only controls visual highlighting; BADNET never claims a port is malicious
because it is unusual.

Secrets are redacted in output by default. `--verbose` (or
`output.redact_secrets: false`) shows them in full — only do that on a capture
you already trust.

---

## Signatures

Three YAML files ship in `signatures/`:

| File | Contents |
| --- | --- |
| `ctf_patterns.yaml` | Flag formats and CTF-specific markers |
| `secrets.yaml` | Credentials, API keys, tokens, private key headers |
| `interesting_ports.yaml` | Port/service reference data |

All 52 patterns are compiled and validated at load time; an invalid regex or a
duplicate ID fails immediately with a clear message rather than silently
matching nothing. Point `signature_dir` at your own directory to extend or
replace them.

---

## Safety model

Capture contents are untrusted input. BADNET is built so that a hostile `.pcap`
cannot hurt you:

- **Never executed.** Extracted content is written to disk as data. Nothing is
  imported, `eval`'d, or run as a command.
- **No shell.** Every external tool is invoked with an argument list and
  `shell=False`.
- **Bounded everything.** Subprocess output, artifact size, decompression ratio,
  regex execution time and string counts all have hard caps.
- **Bounded recursion.** Decode depth is capped, and decompression is checked
  against a maximum expansion ratio so a decompression bomb cannot exhaust
  memory or disk.
- **Path containment.** Every output path is resolved and verified to stay
  inside the case directory, so a crafted filename cannot escape it.
- **Bounded streaming.** NDJSON is written and read row by row. No command
  loads a whole capture into memory.
- **Permissions.** On platforms that support it, case directories and files are
  hardened after creation.
- **Interrupts are survivable.** `Ctrl-C` keeps partial results, marks the case
  incomplete, and exits `130`. A truncated final NDJSON line is tolerated on
  read.

---

## Sample capture

`examples/sample.pcap` is 100% synthetic — generated by
`tools/make_sample_pcap.py`, containing no real traffic and no real
credentials. It exists so you can see what output looks like before pointing
BADNET at anything of your own.

It is fully deterministic: regenerating it produces byte-identical output
(SHA-256 `428cda8656383bf74e4ddfcfe1744e5dbc40635215cb791a26cef0e52a57f1af`),
and a test asserts that.

It contains 211 packets across 7 TCP streams and covers HTTP (three
conversations), FTP with credentials, TLS, DNS, DHCP and an SMB2 handshake,
along with DNS-tunnelling-like traffic and malformed packets.

```console
$ badnet info examples/sample.pcap
$ badnet analyze examples/sample.pcap --case demo
$ badnet auto examples/sample.pcap --case demo --force

$ # regenerate it yourself
$ python tools/make_sample_pcap.py examples/sample.pcap
```

---

## Development

```console
$ pip install -e ".[dev]"

$ .venv\Scripts\python.exe -m pytest tests -q
64 passed

$ .venv\Scripts\python.exe -m ruff check .
All checks passed!

$ .venv\Scripts\python.exe -m ruff format --check .
51 files already formatted
```

The test suite runs the real pipeline over a freshly generated capture. It does
not mock tshark, so a tshark upgrade that invalidates a field name fails the
suite rather than breaking silently.

Source layout:

| Path | Contents |
| --- | --- |
| `badnet/cli.py` | Typer commands, global options, error handling |
| `badnet/commands/` | One module per command |
| `badnet/analyzers/` | Pipeline: pcap facts, protocols, TCP tracking, orchestrator |
| `badnet/integrations/` | tshark, capinfos, external tool detection, doctor |
| `badnet/models/` | Dataclasses for every record type written to a case |
| `badnet/storage/` | Case directory layout, append-only NDJSON writer |
| `badnet/reporting/` | Rich console rendering |
| `badnet/utils/` | Subprocess safety, hashing, path safety, redaction, logging |
| `badnet/parsing/` | Capture format sniffing, Scapy fallback reader |
| `tools/` | Sample generator |

---

## Troubleshooting

**`tshark is not installed`** — BADNET looks in the standard Wireshark install
directories as well as `PATH`. On Windows, confirm with
`badnet doctor`; if it still reports NOT FOUND, set `tshark_path` in your config
or add Wireshark to `PATH`.

**`case 'x' already exists`** — expected. Choose another `--case`, or pass
`--force` to re-analyse into it. `--force` appends; it does not delete.

**`--max-packets must be at least 1`** — the flag takes a positive integer.

**Capture shows fewer packets than expected with `--max-packets`** — expected.
capinfos facts that describe the whole file are suppressed in this mode, so the
counts stay consistent with what was actually scanned.

**`strings`/`tcpdump` NOT FOUND** — both are optional. See
[Requirements](#requirements).

**`--debug` produced no log file** — the log is written to
`<case>/logs/badnet.log` and can only start once the case directory exists. If
the run failed during input validation there is no case and therefore no log
file; the traceback went to stderr instead.

---

## Licence

MIT. See [LICENSE](LICENSE).

All capture data belongs to whoever captured it. BADNET is a passive reader; the
legal and ethical responsibility for analysing a network is yours.