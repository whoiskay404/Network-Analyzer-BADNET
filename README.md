# BADNET

**Passive network forensics for authorised CTFs and lab captures.**

Point BADNET at a `.pcap` or `.pcapng` and it tells you what is inside: hosts,
conversations, streams, HTTP and DNS traffic, carved files, and ranked CTF
findings — including flags hidden inside encoded payloads on any port. Every
claim is explained rather than asserted.

> **Authorised targets only.** Analyse systems you own or have explicit written
> permission to test. BADNET is a passive reader; it never sends traffic, but the
> captures you feed it may contain other people's data.

```
Python 3.12+   ·   tshark (recommended)   ·   MIT licensed   ·   Windows / Linux / macOS
```

---

## Table of contents

- [What BADNET is](#what-badnet-is)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
  - [`badnet info`](#badnet-info)
  - [`badnet analyze`](#badnet-analyze)
  - [`badnet auto`](#badnet-auto)
  - [`badnet stream`](#badnet-stream)
  - [`badnet search`](#badnet-search)
  - [`badnet report`](#badnet-report)
  - [`badnet config`](#badnet-config)
  - [`badnet doctor`](#badnet-doctor)
  - [`badnet version`](#badnet-version)
- [Global options](#global-options)
- [Typical workflows](#typical-workflows)
- [Case output layout](#case-output-layout)
- [Detection engine](#detection-engine)
- [Configuration](#configuration)
- [Exit codes](#exit-codes)
- [Safety and legal](#safety-and-legal)
- [Troubleshooting](#troubleshooting)
- [Limitations and roadmap](#limitations-and-roadmap)
- [Development](#development)
- [License](#license)

---

## What BADNET is

BADNET is a **CLI-first** investigation tool. It reads a capture, writes a
self-describing *case directory* of plain NDJSON files plus an offline HTML
report, and prints a summary you can act on. Nothing is hidden in a database and
nothing is uploaded anywhere.

**Works today**

| Area | What you get |
| --- | --- |
| Capture facts | size, format, packet count, time span, rates, malformed count |
| Protocols | protocol hierarchy and packet counts (tshark/scapy) |
| Endpoints | top talkers: sources, destinations, ports |
| Connections | bidirectional conversation table with service labels |
| TCP streams | stream table plus two-way reassembly with correct orientation |
| HTTP | request/response extraction, bounded bodies, gzip/deflate and chunked decoding |
| DNS | wire-level parsing of A/AAAA/CNAME/NS/PTR/MX/TXT; tunnelling/exfiltration heuristics |
| Payload sweep | re-scans every TCP direction and UDP/ICMP datagram; decodes base64/base64url/hex/URL/ROT13 to recover wrapped flags |
| Findings | YAML signature set (flags, credentials, secrets, endpoints) + explained heuristics |
| Search | regex or literal sweep across reassembled TCP **and** UDP/ICMP datagrams |
| Carving | magic-byte file recovery from streams, with hashes |
| Reporting | self-contained `report.html`, plus `report.json`, `summary.txt`, `findings.ndjson` |

**What it is not.** BADNET does not decrypt TLS, does not replay traffic, does
not scan hosts, and does not try to be clever about intent. It reports what is
present, with evidence.

---

## Requirements

| Dependency | Needed? | Why |
| --- | --- | --- |
| Python **3.12+** | required | the runtime |
| **tshark** (Wireshark CLI) | strongly recommended | fast, accurate dissection and file extraction |
| **scapy** | installed with BADNET | pure-Python fallback reader when tshark is absent |
| `nmap` | optional | active profiling (never run automatically) |
| `file`, `strings` (binutils) | optional | better artifact typing and string extraction |
| `libmagic` (`python-magic`) | optional | best file-type detection |

If tshark is missing, BADNET still runs using scapy and clearly marks what it
degraded. `badnet doctor` tells you exactly what is present and what you lose.

---

## Installation

### Linux / Kali

```console
$ sudo apt update
$ sudo apt install -y tshark python3-venv python3-pip
# optional extras:
$ sudo apt install -y nmap file binutils
```

While installing, apt may ask:

> Should non-superusers be able to capture packets? **YES**

Answer **YES** if offered. Reading a PCAP file never requires capture
privileges, so **NO** is not fatal.

Kali marks system Python as externally managed (PEP 668), so install into a
virtualenv (run this from the folder that contains `pyproject.toml`):

```console
$ cd /path/to/Network-Analyzer-BADNET/"CTF Network Analyzer"
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip install --upgrade pip
$ pip install -e .
```

Your prompt changes to `(.venv)`. If it did not, run `source .venv/bin/activate`
again — forgetting this is the most common cause of `badnet: command not found`.

### macOS

```console
$ brew install tshark
$ python3 -m venv .venv && source .venv/bin/activate
$ pip install -e .
```

### Windows (PowerShell)

Install Wireshark (which includes `tshark`), then:

```powershell
> py -3.12 -m venv .venv
> .\.venv\Scripts\Activate.ps1
> pip install -e .
```

If PowerShell blocks the activation script, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or call the
executable directly: `.\.venv\Scripts\badnet.exe`.

### Verify the install

```console
$ badnet version
BADNET 1.0.0

$ badnet doctor
```

`doctor` lists every dependency, its version, and what degrades without it. The
tool is ready when `tshark`, `nmap`, `file`, `strings` and `python` show
**FOUND**; anything **NOT FOUND** is optional.

### Optional: libmagic

```console
$ sudo apt install -y libmagic1        # Linux
$ pip install python-magic
$ badnet doctor                        # python-magic should now show FOUND
```

> If `badnet` is not on your `PATH`, every command in this README also works as
> `python -m badnet <command> ...` while the virtualenv is active.

---

## Quick start

```console
$ badnet info capture.pcap        # read-only recon, writes nothing
$ badnet analyze capture.pcap     # full pipeline into ./output/<name>-<hash>/
$ badnet auto capture.pcap        # the same analysis, plus ranked CTF findings
$ badnet report capture.pcap      # write a standalone report.html
```

`auto` is the best starting point when you have no idea where to begin: it runs
the full pipeline, ranks findings by CTF value, explains each one, and prints
follow-up commands you can paste straight back into the shell.

---

## Command reference

All commands share the [global options](#global-options), which go **after** the
subcommand (`badnet info --json capture.pcap`).

### `badnet info`

Show file facts, timing, protocol hierarchy and top talkers. **Read-only — no
case directory is written.**

```console
$ badnet info capture.pcap
```

```
----------------------------------- Capture -----------------------------------
file          capture.pcap
size          25.5 KiB
format        classic pcap, little-endian
packets       211
duration      9.109 s
malformed     0 packet(s)
reader        tshark

--------------------- Protocols  (only protocols present) ---------------------
protocol packets
TCP      77
HTTP     16
DNS      131

--------------------------------- Top talkers ---------------------------------
sources
value          packets
10.10.10.50        116
```

Use it to sanity-check a capture and decide whether to run a full analysis. Add
`--max-packets N` for a fast look at a huge file.

### `badnet analyze`

Run the passive pipeline and write a case directory. Prints a summary and the
case path.

```console
$ badnet analyze capture.pcap
```

```
-------------------------------- What happened --------------------------------
capture      capture.pcap
packets      211
connections  78
streams      7
http         8 request(s), 8 response(s)
dns          70 query(ies), 62 response(s)
findings     25
reader       tshark
elapsed      3.6s

--------------------------------- Case output ---------------------------------
  output/capture-516a10a3
```

Default phases: `info`, `protocols`, `connections`, `streams`, `http`, `dns`,
`payload`. The `payload` phase sweeps every reassembled TCP stream direction and
every UDP/ICMP datagram, so flags are found wherever they travel - not only over
HTTP and DNS. This is the command to reach for when you want the raw data on disk
without the ranked presentation of `auto`.

### `badnet auto`

Full investigation: the complete pipeline, then a ranked findings table, a
plain-English "why" for every finding, and runnable follow-up commands.

```console
$ badnet auto capture.pcap
```

```
--------------------------------- CTF FINDINGS  (25) --------------------------
[!]  flag        Possible CTF flag (brace form)  high    flag{unit_testing_is_great}
[!]  flag        Possible CTF flag (brace form)  high    flag{b64_in_http_post_wins}
[~]  flag        Possible CTF flag (prefixed)    medium  ctf-challenge
[!]  dns         Possible DNS tunnelling         high    60/60 queries ...

--------------------------------- Why each finding fired ----------------------
  Possible CTF flag (brace form)  (flag/high, confidence high, detector http:flag_brace)
    why: A token with the classic flag/ctf naming and a brace-delimited body.
    evidence: flag{unit_testing_is_great}
    source: stream 0 response 200

  Possible CTF flag (brace form)  (flag/high, confidence high, detector
      payload.base64:flag_brace)
    why: A base64 blob in the stream decoded to a token with the classic
         flag/ctf naming.
    evidence: flag{b64_in_http_post_wins}
    source: tcp-stream-0 client_to_server [base64]
```

By default (`--ctf`) findings are ranked: **flags → credentials → secrets →
encoding → artifacts → endpoints → DNS → HTTP → TLS → unusual ports →
anomalies → metadata → data**. Pass `--no-ctf` to keep observation order.

Secrets and long opaque tokens are masked in default output; add `--verbose` to
reveal them on a capture you trust.

### `badnet stream`

List TCP streams, or dump and preview one stream by `--id`.

```console
$ badnet stream capture.pcap                  # list streams
$ badnet stream capture.pcap --id 0           # dump stream 0, both directions
$ badnet stream capture.pcap --id 0 --hex     # hex dump instead of text
$ badnet stream capture.pcap --id 0 --carve   # also carve embedded files
```

| Option | Description |
| --- | --- |
| `--id N` | Stream id to dump (omit to list every stream) |
| `--direction <c2s\|s2c\|both>` | Which side to dump (default `both`) |
| `--hex` | Show a hex dump instead of a text preview |
| `--carve` | Recover embedded files by magic bytes into `files/` |

A dump writes the reassembled bytes to the case `streams/` directory, and with
`--carve` recovers embedded files into `files/`, recording their hashes.

### `badnet search`

Sweep reassembled TCP payload **and** individual UDP/ICMP datagrams for a regex
or literal, recording every hit in `search.ndjson`.

```console
$ badnet search capture.pcap --regex 'flag\{[^}]+\}'
$ badnet search capture.pcap --literal -i -e 'FLAG{'
$ badnet search output/capture-516a10a3 --regex 'password|token'   # reuse a case
```

| Option | Description |
| --- | --- |
| `-e`, `--regex <STR>` | Pattern to search for (**required**) |
| `-F`, `--literal` | Treat the pattern as literal text (safest for hostile input) |
| `-i`, `--ignore-case` | Case-insensitive match |
| `--max-hits N` | Stop after N matches |

`target` is either a capture file **or** an existing case directory. TCP offsets
refer to the reassembled stream, so a hole left by a lost packet shifts later
offsets; UDP/ICMP hits are labelled per packet (`udp-packet-N` /
`icmp-packet-N`) with offsets relative to that datagram. `--literal` skips the
regex engine entirely and is the safe choice for untrusted input; patterns with
nested quantifiers are refused before they run.

### `badnet report`

Write a self-contained offline HTML report into the case.

```console
$ badnet report capture.pcap                  # analyse, then write report.html
$ badnet report output/capture-516a10a3       # rebuild from an existing case
$ badnet report capture.pcap --top 100        # more rows per section
```

| Option | Description |
| --- | --- |
| `--top N` | Maximum rows shown per section |

Produces `report.html` — loading no scripts, styles or images from the network —
plus `report.json`. Every value taken from the capture is HTML-escaped, so a
capture containing `<script>` renders as text, never as markup.

### `badnet config`

Show the effective configuration, or write a documented template.

```console
$ badnet config                       # print what is in effect
$ badnet config badnet.yaml           # write an editable template
```

### `badnet doctor`

Check which dependencies are present and what degrades without them. Run this
first whenever something behaves unexpectedly.

### `badnet version`

Print the BADNET version.

---

## Global options

Accepted by every command. Put them **after** the subcommand, e.g.
`badnet info --json capture.pcap`. (`badnet --json info capture.pcap` will
*not* work; use `badnet <command> --help` for the per-command list.)

| Option | Use it for |
| --- | --- |
| `--output-dir DIR` | Where case directories are created |
| `--case NAME` | Name the case yourself (default `<stem>-<hash>`) |
| `--force` | Re-analyse into an existing case (**appends**, never deletes) |
| `--max-packets N` | Quick pass over the first N packets of a huge capture |
| `--json` | Machine-readable output on stdout (no banner/progress) |
| `--limit N` | Maximum table rows to display (default 50) |
| `--verbose`, `-v` | Show unredacted secrets and INFO logs |
| `--no-color` | Plain text, for piping to a file |
| `--quiet`, `-q` | Only warnings and errors |
| `--debug` | Full tracebacks plus a log at `<case>/logs/badnet.log` |
| `--config FILE` | Load a YAML config file |

Common invocations:

```console
$ badnet info big.pcap --max-packets 5000      # fast recon
$ badnet analyze big.pcap --case first-look    # named case
$ badnet auto big.pcap --max-packets 50000     # triage a huge capture
$ badnet info capture.pcap --json > info.json  # save for scripting
```

---

## Typical workflows

### 1. First look

```console
$ badnet info challenge.pcap
```

Confirm the format, packet count and protocols. If the capture is enormous, add
`--max-packets 20000` for a representative slice.

### 2. Triage

```console
$ badnet auto challenge.pcap
```

Read the findings table top-down and paste the follow-up commands to pivot into
the raw data.

### 3. Hunt a specific pattern

```console
$ badnet search challenge.pcap --regex 'flag\{[^}]+\}'
$ badnet search challenge.pcap --literal -i -e 'password'
```

`--literal` is the safe default mode for hostile input.

### 4. Inspect an interesting stream

```console
$ badnet stream challenge.pcap --id 3 --carve
```

Dump both directions, preview the text, and carve any files embedded in it.

### 5. Deliver the result

```console
$ badnet report challenge.pcap
```

Hand over `report.html` — self-contained and safe to open offline.

---

## Case output layout

Every command that analyses writes (or reuses) a case directory:

```
output/<name>-<hash>/
├── metadata.json          # reproducibility: tools, config, options, run history
├── summary.txt            # plain-text summary (analyze/auto)
├── report.html            # offline report (report)
├── report.json            # machine-readable report (report)
├── connections.ndjson     # bidirectional conversations
├── findings.ndjson        # every detector finding
├── search.ndjson          # search hits (search)
├── packets.ndjson         # normalised packet rows (when written)
├── dns/dns.ndjson         # parsed DNS messages
├── http/http.ndjson       # parsed HTTP exchanges
├── streams/streams.ndjson # TCP stream table
├── files/                 # carved artifacts
├── hashes/                # hashes and strings (when enabled)
├── tls/                   # reserved (not yet populated)
├── nmap/                  # reserved (not yet populated)
└── logs/badnet.log        # present with --debug
```

**NDJSON** means one JSON object per line, so ordinary tools work:

```console
$ grep '"service": "ftp"' connections.ndjson
$ grep -E '"(http|https|ftp|ssh)"' connections.ndjson
$ head -1 streams/streams.ndjson | python -m json.tool
$ grep -ri 'flag' output/challenge-516a10a3/
```

Cases are **append-only**. Re-running with `--force` adds rows and records a new
entry in `metadata.json`; earlier evidence is never removed.

---

## Detection engine

Findings come from three sources, all bounded so a hostile capture cannot flood
you:

1. **Signatures** — YAML patterns compiled up front. The shipped set has **52
   patterns** in six categories: `secret` (20), `credential` (15), `metadata`
   (6), `endpoint` (5), `flag` (4), `encoding` (2).
2. **Explained heuristics** — protocol-aware rules such as DNS tunnelling.
3. **Decoding pass** — the `payload` phase tries base64, base64url, hex, URL
   percent-encoding and ROT13 (including nested combinations) on TCP payloads
   and UDP/ICMP datagrams, then re-scans the decoded text for flag-shaped
   matches. So a flag that only ever appears base64-wrapped in a body is still
   recovered. Recursion is capped by `limits.max_decode_depth` and each blob by
   `limits.max_decode_size`.

Every finding carries a **category**, a **severity** (`info`/`low`/`medium`/
`high`), a **confidence** (`low`/`medium`/`high`), a plain-English **explanation**
of *why* it fired, the **evidence** that matched, and a **source** (packet,
stream or file). Wording is deliberate: heuristics say *possible* or
*consistent with*, never "malicious" or "confirmed".

Add your own patterns by dropping a YAML file in the signature directory (or
point `signature_dir` at your own). Each pattern needs `id`, `title`, `regex`,
`severity`, `confidence` and `category`; a malformed pattern fails loudly at
load time rather than silently never matching.

---

## Configuration

### Precedence

```
built-in defaults
  < ~/.config/badnet/config.yaml   (or $XDG_CONFIG_HOME/badnet/config.yaml)
  < ./badnet.yaml                  (project config, current directory)
  < --config FILE
  < command-line flags
```

Generate an editable template with `badnet config badnet.yaml`, and inspect the
effective values with `badnet config`.

### Key reference

| Key | Default | Controls |
| --- | --- | --- |
| `output_dir` | `output` | Where case directories are created |
| `interesting_ports` | 17 ports | Ports highlighted in tables |
| `interesting_endpoints` | 29 paths | URI paths worth a look (`/admin`, `/.env`, `/backup`…) |
| `interesting_extensions` | 8 types | URI file types worth a look (`.sql`, `.zip`, `.key`…) |
| `dns.min_queries` | `20` | Queries to a parent before tunnelling is considered |
| `dns.high_unique_ratio` | `0.85` | Fraction of queries with a new subdomain |
| `dns.long_label_len` | `40` | Label length treated as "long" |
| `dns.high_entropy` | `3.5` | Bits/char above which a label looks encoded |
| `dns.encoded_label_ratio` | `0.5` | Fraction of encoded-looking labels to flag |
| `dns.min_query_rate` | `2.0` | Queries/second that count as a burst |
| `limits.max_artifact_size` | `67108864` | Largest artifact written (64 MiB) |
| `limits.max_body_preview` | `4096` | Bytes of an HTTP body kept for display/search |
| `limits.regex_timeout_ms` | `2000` | Wall-clock budget for regex execution |
| `output.top_n` | `20` | Table rows before an "N more" hint |
| `output.default_limit` | `50` | Default `--limit` for list commands |
| `output.redact_secrets` | `true` | Mask secrets unless `--verbose` |
| `signature_dir` | shipped set | Where signature YAML files live |
| `tshark_path` / `nmap_path` / `files_path` / `strings_path` | auto | External tool overrides |
| `use_libmagic` | `true` | Use python-magic, then `file`, then a built-in table |
| `run_nmap_scripts` | `true` | Allow `-sC` in the nmap `full` profile |
| `nmap_authorized` | `false` | Skip the interactive nmap authorisation prompt |
| `nmap_default_profile` | `quick` | `quick` or `full` |

### Minimal example

```yaml
# badnet.yaml
output_dir: cases
interesting_endpoints:
  - /admin
  - /.env
dns:
  min_queries: 15
output:
  redact_secrets: false
```

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Runtime error |
| `2` | Bad flags or configuration |
| `3` | Missing dependency |
| `130` | Interrupted (`Ctrl-C`) |

---

## Safety and legal

- **Authorised targets only.** Only analyse captures you own or are permitted to
  inspect.
- **Hostile input is expected.** Capture contents are never executed, imported or
  evaluated — only written to disk as data.
- **No shell, bounded output.** External tools run without a shell, with output
  and time limits; every generated path is checked to stay inside the case
  directory.
- **Offline by design.** The HTML report loads nothing from the network.
- **Interruption is safe.** `Ctrl-C` keeps partial results, marks the case
  incomplete, and exits `130`.

---

## Troubleshooting

**`badnet: command not found`** — the virtualenv is not active. Run
`source /path/to/badnet/.venv/bin/activate`, or call
`/path/to/badnet/.venv/bin/badnet` directly.

**`error: externally-managed-environment`** — you installed into system Python.
Create and activate a virtualenv, then `pip install -e .`.

**`no packet reader available`** — neither tshark nor scapy is available. Install
tshark and re-check with `badnet doctor`.

**tshark shows NOT FOUND but is installed** — confirm with `which tshark`
(Linux/macOS) or `where.exe tshark` (Windows). If it lives somewhere unusual, set
`tshark_path: /full/path/to/tshark` in your config.

**`error: input file not found`** — check the path and that you unzipped the
challenge. `ls` (or `dir`) to confirm the exact name, including `.pcap` vs
`.pcapng`.

**`error: permission denied` on the capture** — you unzipped as root earlier. Fix
ownership rather than reaching for sudo: `sudo chown -R "$USER":"$USER" ~/work`
(Linux/macOS).

**`--force` seems to duplicate rows** — that is intentional; rows accumulate and
`metadata.json` lists each run. Use a fresh `--case` for a clean count.

**Output looks empty or truncated** — tables default to 50 rows. Widen with
`--limit 200`; check whether an earlier `--max-packets` limited the run.

**Tables wrap badly in a narrow terminal** — widen the window or use
`--no-color` / `--json`.

**Non-ASCII characters show as `?`** — your locale is `C`/`POSIX`. BADNET still
completes, replacing what it cannot encode. To see it properly:
`export LANG=C.UTF-8`.

**A finding looks like a false positive** — read its `explanation` and
`confidence`. Heuristics are deliberately hedged; use `--verbose` to see the raw
evidence and decide yourself.

---

## Limitations and roadmap

**Not yet implemented:** the `tls` analyzer and TLS detector rules, and
automatic multi-file artifact extraction. The `tls/`, `hashes/` and `nmap/` case
subdirectories are created but stay empty until those land, and `artifacts`
stays `0` for the built-in `auto`/`analyze` path (use `stream --carve` today).

**By design:** BADNET will not decrypt TLS or open a password-protected archive
without the key - no tool can, absent the secret. It *does* automatically peel
common encodings (base64, base64url, hex, URL, ROT13, and nested combinations up
to `limits.max_decode_depth`). Encodings and compression it cannot or will not
decode are still flagged and their bytes surfaced so you can take over.

---

## Development

```console
$ source .venv/bin/activate
$ pip install -e ".[dev]"

$ pytest -q
168 passed

$ ruff check .
All checks passed!

$ ruff format --check .
73 files already formatted
```

Tests run the real pipeline against a freshly generated synthetic capture, so a
tshark upgrade that breaks a field name fails the suite instead of failing
silently.

### Try it without a real capture

A synthetic sample ships in `examples/sample.pcap` — no real traffic, no real
credentials:

```console
$ badnet info examples/sample.pcap
$ badnet auto examples/sample.pcap --case demo --force    # ranked findings incl. the flag
$ badnet stream examples/sample.pcap --case demo --force --id 0
$ badnet search examples/sample.pcap --case demo --force -e 'flag\{[^}]+\}'
$ badnet report examples/sample.pcap --case demo --force
```

211 packets, 7 TCP streams: HTTP, FTP with credentials, TLS, SMB2, DNS, DHCP —
including a deliberate DNS tunnelling burst. Regenerating it produces identical
bytes.

---

## License

MIT licensed. See [LICENSE](LICENSE).
