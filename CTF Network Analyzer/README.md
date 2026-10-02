# BADNET

Passive network forensics CLI for authorised CTFs and lab captures.
Give it a `.pcap` or `.pcapng`; it tells you what is inside.

**Authorised targets only.** Analyse systems you own or have written permission to test.

```console
$ badnet info capture.pcap        # quick look, writes nothing
$ badnet analyze capture.pcap     # full report into ./output/
$ badnet auto capture.pcap        # same analysis, plus ranked findings
```

---

## Install on Kali Linux

### 1. System tools

```console
$ sudo apt update
$ sudo apt install -y tshark nmap file binutils python3-venv python3-pip
```

`tshark` is the only one that really matters. While installing, apt asks:

> Should non-superusers be able to capture packets? **YES**

Pick **YES** if offered — it costs nothing, and avoids `Permission denied` if you
later point BADNET at a live interface. Reading a PCAP file never needs capture
privileges either way, so answering NO is not fatal.

`binutils` provides `strings`, `file` provides `file`, and `nmap` is optional.

### 2. BADNET itself

Kali marks system Python as externally managed (PEP 668), so `pip install`
against `/usr/bin/python3` fails with `error: externally-managed-environment`.
Use a virtualenv:

```console
$ cd badnet
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip install --upgrade pip
$ pip install -e .
```

Your prompt should change to `(.venv)`. If it did not, run
`source .venv/bin/activate` again — forgetting this is the most common cause of
`badnet: command not found`.

### 3. Check it

```console
$ badnet version
BADNET 1.0.0

$ badnet doctor
```

`doctor` lists every dependency with its version and what you lose without it.
You are fine if `tshark`, `nmap`, `file`, `strings` and `python` all show FOUND.
Everything marked NOT FOUND is optional and degrades gracefully.

### 4. Optional: libmagic

Only improves file-type detection. Skip it if you like.

```console
$ sudo apt install -y libmagic1
$ pip install python-magic
$ badnet doctor        # python-magic should now show FOUND
```

---

## Everyday use

Put the capture somewhere you own. CTF captures usually come from a zip:

```console
$ mkdir -p ~/work && cd ~/work
$ unzip challenge.zip          # often the pcap is inside
$ ls -la                       # find it: capture.pcap, traffic.pcap, *.pcapng
```

### Look before you analyse

```console
$ badnet info capture.pcap
```

Reads only, writes nothing. Prints file size, packet count, time span, protocol
breakdown, and top talkers:

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

### Full analysis

```console
$ badnet analyze capture.pcap
```

Writes a case directory to `./output/<name>-<hash>/` and prints a summary:

```
-------------------------------- What happened --------------------------------
capture      capture.pcap
packets      211
connections  78
streams      7
reader       tshark
elapsed      3.6s

--------------------------------- Case output ---------------------------------
  output/capture-516a10a3
```

Then read the interesting parts:

```console
$ cd output/capture-516a10a3

$ cat summary.txt              # the same numbers as plain text
$ head -2 connections.ndjson   # who talked to whom
$ head -2 streams/streams.ndjson  # TCP conversations
```

Both are NDJSON: one JSON object per line, so ordinary tools work.

```console
$ # every FTP connection, readable
$ grep '"proto": "TCP"' connections.ndjson | grep '"service": "ftp"'

$ # conversations on interesting ports
$ grep -E '"(service|server_port)": "(http|https|ftp|ssh)"' connections.ndjson

$ # pretty-print one stream
$ head -1 streams/streams.ndjson | python3 -m json.tool
```

### One-shot summary

```console
$ badnet auto capture.pcap
```

Runs the same analysis, then prints a ranked findings list and prints follow-up
commands you can paste straight into the shell. Best starting point when you have
no idea where to begin.

### Common flags

Available on every command — put them **after** the subcommand, e.g.
`badnet info --json capture.pcap`. (`badnet --json info capture.pcap` will *not*
work; use `badnet info --help` for the per-command list.)

| Flag | Use it for |
| --- | --- |
| `--case NAME` | Name the case yourself |
| `--force` | Re-analyse into an existing case (**appends**, never deletes) |
| `--max-packets N` | Quick pass over the first N packets of a huge capture |
| `--json` | Machine-readable output, no colours or banner |
| `--limit N` | Show more or fewer table rows (defaults to 50) |
| `--no-color` | Plain text, for piping to a file |
| `--quiet` / `-q` | Errors only |
| `--debug` | Tracebacks plus a log at `<case>/logs/badnet.log` |
| `--config FILE` | Load a YAML config |

Common invocations:

```console
$ badnet info big.pcap --max-packets 5000      # fast recon
$ badnet analyze big.pcap --case first-look    # named case
$ badnet auto big.pcap --max-packets 50000     # triage a huge capture
$ badnet info capture.pcap --json > info.json  # save for scripting
```

---

## Re-running without losing work

Re-running the same case refuses to overwrite:

```console
$ badnet analyze capture.pcap
error: case 'capture-516a10a3' already exists at output/capture-516a10a3
hint: choose another --case name, or pass --force to analyse again into it
```

Use `--force`. It **appends** — earlier rows are never removed, because they are
evidence. `metadata.json` records each run, so you can still tell them apart.

---

## Configuration

```console
$ badnet config                       # show what is in effect
$ badnet config badnet.yaml           # write an editable template
```

Edit `badnet.yaml` in your working directory and BADNET picks it up
automatically, or pass `--config path/to/file.yaml`.

Useful knobs:

| Key | Controls |
| --- | --- |
| `output_dir` | Where cases are written |
| `interesting_ports` | Ports highlighted in tables |
| `interesting_endpoints` | URI paths worth a look (`/admin`, `/.env`, `/backup`…) |
| `dns` | DNS-tunnelling detection thresholds |
| `limits` | Caps on artifact size, decompression, regex time |
| `output.redact_secrets` | `false` shows passwords and tokens in full |

Precedence: defaults → `~/.config/badnet/config.yaml` → `./badnet.yaml` →
`--config FILE` → command flags.

Secrets are redacted by default. Add `--verbose` to see raw values when you need
them on a capture you trust.

---

## What Phase 1 does and does not do

**Works today:** capture facts and timing, protocol breakdown, top talkers,
connection table, TCP stream table, TCP reassembly in both directions with
correct client/server orientation, YAML signature loading (52 patterns),
`doctor`, append-only case storage.

**Not yet:** `badnet stream`, `badnet search` and `badnet dns` do not exist, and
no `report.html` is generated. `auto` says so in its own output rather than
pretending. Artifact extraction lands next, so `analyze` and `auto` legitimately
report `artifacts 0` and `findings 0` for now. The `http/`, `dns/`, `tls/`,
`files/`, `hashes/` and `nmap/` case subdirectories are created but stay empty
until then.

Every follow-up `auto` prints is runnable as-is — it points at files that exist in
the case directory using plain `grep`, `less` and `python3 -m json.tool`.

No SQLite. Cases are plain NDJSON plus `metadata.json`, so you can read them with
any tool.

---

## Safety

Capture contents are treated as hostile input and are never executed, imported or
evaluated — only written to disk as data. All external tools run without a shell,
with bounded output and timeouts, and every generated path is checked to stay
inside the case directory.

`Ctrl-C` keeps partial results, marks the case incomplete, and exits `130`.

---

## Try it without a real capture

A synthetic sample ships in `examples/sample.pcap` — no real traffic, no real
credentials:

```console
$ badnet info examples/sample.pcap
$ badnet analyze examples/sample.pcap --case demo
$ badnet auto examples/sample.pcap --case demo --force
```

211 packets, 7 TCP streams: HTTP, FTP with credentials, TLS, SMB2, DNS, DHCP.
Regenerating it produces identical bytes.

---

## Troubleshooting

**`badnet: command not found`** — the virtualenv is not active. Run
`source /path/to/badnet/.venv/bin/activate`, or call
`/path/to/badnet/.venv/bin/badnet` directly.

**`error: externally-managed-environment`** — you installed into system Python.
Create and activate a virtualenv (step 2), then `pip install -e .`.

**`no packet reader available`** — no tshark and no scapy.
`sudo apt install tshark` and re-check with `badnet doctor`.

**tshark shows NOT FOUND but is installed** — confirm with
`which tshark`. If it is somewhere odd, set `tshark_path: /full/path/to/tshark`
in your config.

**`error: input file not found`** — check the path and that you unzipped the
challenge. `ls` to confirm the exact filename, including `.pcap` vs `.pcapng`.

**`error: permission denied` on the capture** — you unzipped as root earlier.
Fix ownership rather than reaching for sudo:
`sudo chown -R "$USER":"$USER" ~/work`

**`--force` seems to duplicate rows** — that is intentional; rows accumulate and
`metadata.json` lists each run. Use a fresh `--case` if you want a clean count.

**Output looks empty or truncated** — tables default to 50 rows. Widen them
with `--limit 200`, and add `--verbose` for INFO logging. If the capture itself
was cut short, check for a `--max-packets` you set earlier; the flag rejects `0`
with `--max-packets must be at least 1`.

**Tables wrap badly in a narrow terminal** — widen the window or use
`--no-color` and `--json`.

**Non-ASCII characters show as `?`** — your locale is `C`/`POSIX`, so the
terminal cannot render the text. BADNET still completes, replacing what it
cannot encode. To see it properly: `export LANG=C.UTF-8`.

**Exit codes:** `0` success, `1` error, `2` bad flags or config, `3` missing
dependency, `130` interrupted.

---

## Development

```console
$ source .venv/bin/activate
$ pip install -e ".[dev]"

$ pytest -q
78 passed

$ ruff check .
All checks passed!

$ ruff format --check .
51 files already formatted
```

Tests run the real pipeline against a freshly generated capture, so a tshark
upgrade that breaks a field name fails the suite instead of failing silently.

MIT licensed. See [LICENSE](LICENSE).