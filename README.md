<h1 align="center">DustIDS</h1>

<p align="center">
  <strong>A lean, signature-based intrusion detection system for industrial networks, written in Rust.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg"></a>
  <img alt="Status: unmaintained" src="https://img.shields.io/badge/status-unmaintained-lightgrey.svg">
  <img alt="Platform: Linux" src="https://img.shields.io/badge/platform-linux-informational.svg">
  <img alt="Language: Rust" src="https://img.shields.io/badge/language-rust-orange.svg">
</p>

> [!WARNING]
> **This project is not actively maintained.** DustIDS was developed by
> [Puffin Security](https://puffinsecurity.com) in 2024 and is published as-is for
> reference, research and education. We have no plans to continue development for
> now. Issues and pull requests may not get a response. It is an experimental
> prototype: do not rely on it to protect production OT/ICS environments.

---

## Table of contents

- [What is DustIDS?](#what-is-dustids)
- [Features](#features)
- [Architecture](#architecture)
- [Supported protocols and rules](#supported-protocols-and-rules)
- [Getting started](#getting-started)
  - [Requirements](#requirements)
  - [Build](#build)
  - [Run](#run)
  - [Command-line options](#command-line-options)
- [Alerts](#alerts)
- [Writing rules](#writing-rules)
- [Project layout](#project-layout)
- [Known limitations](#known-limitations)
- [Branches](#branches)
- [Authors](#authors)
- [License](#license)

## What is DustIDS?

DustIDS is a small network IDS focused on **industrial control systems (ICS/OT)**.
It captures traffic from a network interface, extracts the TCP and UDP payloads and
matches them against [YARA](https://virustotal.github.io/yara-x/) rules that
describe dangerous or suspicious operations in industrial protocols: a PLC being
stopped, firmware being uploaded, memory being written, passwords being changed,
known SCADA exploits, and so on.

The goal was a detector that is fast and easy to deploy on modest hardware, with
rules that security analysts can read and write without learning a new DSL.

## Features

- **Fast packet capture** through `AF_PACKET`, with experimental `AF_XDP` support
  for higher throughput.
- **YARA-based detection** using [YARA-X](https://github.com/VirusTotal/yara-x),
  the Rust rewrite of YARA. Rules are plain `.yar` files loaded from a directory.
- **228 ready-made rules** for 10 ICS/IoT protocols plus known ICS exploits, with
  each rule mapped to a NIST SP 800-82 control.
- **Multi-threaded analysis**: a bounded capture buffer feeds a configurable pool of
  analysis threads.
- **JSON alerts** in an EVE-style format (similar to Suricata), which include all the
  metadata from the rule that matched.
- **Syslog forwarding** (RFC 5424 over TCP) to send alerts to a SIEM.
- **Terminal UI** (built with [ratatui](https://ratatui.rs)) with live traffic
  graphs, drop counters and the latest alerts.

## Architecture

```text
               ┌────────────────────┐
  NIC ───────▶ │ Listener           │  AF_PACKET (default) or AF_XDP (-u)
               └─────────┬──────────┘
                         │ raw Ethernet frames
                         ▼
               ┌────────────────────┐
               │ Bounded buffer     │  --analysis-buffer-size (packets dropped when full)
               └─────────┬──────────┘
                         ▼
               ┌────────────────────┐
               │ Analysis threads   │  Ethernet → IPv4/IPv6 → TCP/UDP payload
               │ (YARA-X scanner)   │  scanned against the compiled rule set
               └─────────┬──────────┘
                         │ AlertMsg
                         ▼
               ┌────────────────────┐
               │ State / alerting   │  in-memory alert list, counters,
               │                    │  optional syslog, stdout or TUI
               └────────────────────┘
```

## Supported protocols and rules

The rules are in [`rules/`](rules/). [`tests/pcaps/`](tests/pcaps/) has sample
captures that trigger them.

| Rule file | Protocol / scope | Rules |
| --- | --- | ---: |
| [`modbus.yar`](rules/modbus.yar) | Modbus/TCP | 18 |
| [`DNP3.yar`](rules/DNP3.yar) | DNP3 | 10 |
| [`Siemens-S7.yar`](rules/Siemens-S7.yar) | Siemens S7comm | 13 |
| [`EIP.yar`](rules/EIP.yar) | EtherNet/IP (CIP) | 7 |
| [`FINS.yar`](rules/FINS.yar) | Omron FINS | 37 |
| [`SLMP.yar`](rules/SLMP.yar) | Mitsubishi SLMP | 38 |
| [`MCCONNECT.yar`](rules/MCCONNECT.yar) | Mitsubishi MC protocol | 46 |
| [`OPC-UA.yar`](rules/OPC-UA.yar) | OPC UA | 8 |
| [`OPC-DA.yar`](rules/OPC-DA.yar) | OPC DA (DCOM) | 3 |
| [`mtconnect.yar`](rules/mtconnect.yar) | MTConnect | 8 |
| [`ICS-Attacks.yar`](rules/ICS-Attacks.yar) | Known exploits against ICS/SCADA products (Rockwell, Schneider, Yokogawa, Iconics, IGSS, Wonderware, RealWin, …) | 40 |

## Getting started

### Requirements

- **Linux.** Capture is based on `AF_PACKET`/`AF_XDP`, so DustIDS does not run on
  macOS or Windows.
- A recent stable **Rust** toolchain ([rustup](https://rustup.rs)).
- Build dependencies for `libbpf` (needed by the AF_XDP backend). On
  Debian/Ubuntu, for example:

  ```sh
  sudo apt install build-essential clang pkg-config libelf-dev zlib1g-dev
  ```

- Root privileges, or the `CAP_NET_RAW` capability (plus `CAP_NET_ADMIN`/`CAP_BPF`
  for AF_XDP), to capture packets.

### Build

```sh
git clone https://github.com/PuffinSecurity/DustIDS.git
cd DustIDS
cargo build --release
```

The binary is written to `target/release/dust-ids`.

### Run

Scan an interface with the bundled rules and print stats to stdout:

```sh
sudo ./target/release/dust-ids scan eth0 --rules-dir rules/
```

Use the terminal UI with four analysis threads:

```sh
sudo ./target/release/dust-ids scan eth0 -r rules/ --analysis-threads 4 --tui
```

Forward alerts to a syslog server (TCP):

```sh
sudo ./target/release/dust-ids scan eth0 -r rules/ --syslog-server 10.0.0.10:514
```

To try it without industrial hardware, create a virtual Ethernet pair and replay
one of the sample captures with [tcpreplay](https://tcpreplay.appneta.com/):

```sh
sudo ip link add dust0 type veth peer name dust1
sudo ip link set dust0 up && sudo ip link set dust1 up

# Terminal 1
sudo ./target/release/dust-ids scan dust0 -r rules/

# Terminal 2
sudo tcpreplay -i dust1 tests/pcaps/modbus/force_listen_only_mode.pcap
```

### Command-line options

```text
dust-ids scan [OPTIONS] --rules-dir <RULES-DIR> <INTERFACE>

Arguments:
  <INTERFACE>                       Interface to scan

Options:
  -r, --rules-dir <RULES-DIR>                        Directory with YARA rules (*.yar)
      --syslog-server <SYSLOG-SERVER>                [IP:PORT] of a syslog server for alerts (TCP, RFC 5424)
      --analysis-threads <ANALYSIS-THREADS>          Number of analysis threads [default: 1]
      --analysis-buffer-size <ANALYSIS-BUFFER-SIZE>  Max packets buffered for analysis [default: 32768]
  -u, --use-afxdp                                    Use AF_XDP instead of AF_PACKET (experimental)
  -t, --tui                                          Use the terminal user interface
```

## Alerts

Each match generates an alert. The fields from the `meta` section of the rule are
copied into the `alert` object:

```json
{
  "timestamp": "2024-07-08-12:31:07",
  "event_type": "alert",
  "src_ip": "192.168.1.10",
  "src_port": 51234,
  "dst_ip": "192.168.1.20",
  "dst_port": 502,
  "proto": "TCP",
  "rule": "force_listen_only_mode",
  "alert": {
    "protocol": "MODBUS",
    "author": "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>",
    "description": "Enables forced listen only mode",
    "impact": "Places the device in listen only mode, preventing it from acting on commands",
    "lastUpdate": "2023-02-06T12:11:00+0100",
    "status": "stable",
    "ruleVersion": "v1.3.2",
    "uuid": "1e0af54bf2fd4e75aa985608f3a0c361",
    "standard": "NIST SP 800-82",
    "category": "AC",
    "category_name": "Access Control",
    "control": "AC-17",
    "control_description": "Remote Access: Prevents unauthorized remote access."
  }
}
```

## Writing rules

Rules are standard YARA, evaluated against the **transport-layer payload** of each
packet (TCP or UDP payload, without headers). Offsets in conditions are relative to
the start of that payload. Only string metadata values are copied into alerts.

```yara
rule force_listen_only_mode : modbus
{
  meta:
    protocol    = "MODBUS"
    description = "Enables forced listen only mode"
    impact      = "Places the device in listen only mode"
    uuid        = "1e0af54bf2fd4e75aa985608f3a0c361"
    standard    = "NIST SP 800-82"
    category    = "AC"
    control     = "AC-17"
  strings:
    $modbus_header = { 00 00 }      // Modbus/TCP protocol identifier
    $force_listen  = { 08 00 04 }   // Diagnostics (0x08), sub-function 0x0004
  condition:
    $modbus_header at 2 and $force_listen at 7
}
```

Drop new `.yar` files in the rules directory and restart DustIDS. Files that do not
compile are reported at startup and skipped.

## Project layout

```text
.
├── src/main.rs          # Entry point (panic handlers, logging, CLI dispatch)
├── cli/                 # Command-line parsing (clap) and terminal UI (ratatui)
├── core/                # Capture listeners, YARA analyzer, state, alerts, syslog
├── utils/               # Error type, logging and shared types
├── rules/               # Detection rules for ICS protocols
└── tests/
    ├── pcaps/           # Sample captures per protocol, used to test the rules
    └── test_rules/      # Minimal rules for development
```

## Known limitations

DustIDS was a research prototype and was never hardened for production use. Known
gaps include:

- Each packet is analysed alone. There is **no TCP stream reassembly** and no flow
  tracking, so payloads split across segments are not detected.
- Only Ethernet → IPv4/IPv6 → TCP/UDP is decoded. VLAN tags and other
  encapsulations are not handled. Capture on the loopback interface (`lo`) does not
  decode correctly on Linux, so use a real or `veth` interface.
- There is no rule hot-reloading, alert deduplication or rate-limiting.
- The analysis threads busy-poll the capture buffer, which keeps CPU cores busy
  even when there is no traffic.
- The AF_XDP backend is experimental and uses a single hardcoded RX queue.
- Error handling is minimal: many failures cause a panic instead of a clean error.
- The automated tests in `tests/test_cli.rs` are from the original project template
  and are out of date.

## Branches

- `main`: the most complete version of DustIDS (start here).
- `development`, `feature/*`, `feat/*`, `AFPacket`: historical work-in-progress
  branches, kept for reference.

## Authors

- Jose Ramon Palanco ([@jpalanco](https://github.com/jpalanco)): detection rules and
  protocol research
- Ricardo Stefanescu ([@ricardo-st](https://github.com/ricardo-st)): engine and
  tooling

Built at [Puffin Security](https://puffinsecurity.com).

## License

Copyright (C) 2024 Puffin Security.

DustIDS is free software: you can redistribute it and/or modify it under the terms
of the **GNU Affero General Public License v3.0**. See [LICENSE](LICENSE) for the full
text.

In short: you may use, study, modify and share DustIDS, including for commercial
purposes. If you distribute a modified version, **or let users interact with it over
a network**, you must publish your source code under the same license.

The initial project scaffolding came from
[rust-starter](https://github.com/rust-starter/rust-starter) (MIT License). See
[NOTICE](NOTICE) for the details.
