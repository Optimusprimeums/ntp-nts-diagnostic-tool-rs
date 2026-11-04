# NTP/NTS Diagnostic Tool

A diagnostic utility for testing **NTPv4** and **Network Time Security (NTS)** servers, plus a fault-injecting NTP responder for testing NTP clients and peers.

Version **3.0.0** is a rewrite in Rust. It ships as two self-contained executables with no runtime to install:

| Executable | Purpose |
|---|---|
| `NTP-NTS-Diagnostic-Tool.exe` | The windowed application |
| `ntpnts.exe` | A command-line tool for scripting and CI |

The client performs real NTS Key Establishment over TLS 1.3, negotiates `ntske/1`, derives client-to-server and server-to-client keys with the TLS exporter, exchanges NTS cookies, sends authenticated NTP requests with AEAD AES-SIV-CMAC-256, verifies authenticated replies, and reports offset, delay, server processing time, jitter and loss.

The Python 2.x releases remain at [Optimusprimeums/ntp-nts-diagnostic-tool](https://github.com/Optimusprimeums/ntp-nts-diagnostic-tool).

## Validated interoperability

3.0.0 completed repeated authenticated NTS exchanges against Cloudflare's public `time.cloudflare.com` service. The 2.x Python releases were also validated against an independent ESP32-P4 NTS server; re-check that pairing with 3.0.0.

## The window

The app has a light, dark or follow-system theme, and remembers its settings between launches. The sidebar holds the client, responder and Windows controls. The main area shows live counters, offset and delay charts, timing statistics, and a filterable, colour-coded log. Press Ctrl+Enter to start a run and Esc to stop it.

## Command line

```text
ntpnts query time.cloudflare.com --nts -n 10 -d 500
ntpnts query 192.168.1.50:4460 --nts --insecure      # lab server, self-signed cert
ntpnts query pool.ntp.org                            # plain NTPv4
ntpnts query 127.0.0.1:12300 -n 3                    # your own responder on another port
ntpnts respond --port 12300 --mode kod-deny          # fault-injecting responder
ntpnts self-test                                     # loopback regression suite
ntpnts modes                                         # list fault modes
```

`query` exits with code 1 if any request failed, so you can use it in scripts. Add `--log FILE` to any command to append the log to a file.

## Servers and ports

Enter the server as `host`, `host:port` or `[IPv6]:port`. With NTS on, the port is the NTS-KE port (default 4460); the NTP endpoint and port come from the server's negotiation records. With NTS off, the port is the NTP port (default 123).

## Security

TLS certificate verification is on by default. It trusts the Mozilla root set **and** the Windows certificate store, so a lab NTS server signed by a private CA works once that CA is installed in Windows. **Skip TLS certificate verification** is only for controlled development and certificate diagnostics. The application never logs derived NTS keys.

## Peer test responder

The responder answers NTP requests with deliberately faulty replies: Kiss-o'-Death RATE, DENY and RSTR codes, bad originate timestamps, truncated packets, wrong mode or version, zero timestamps, leap-indicator alarm, stratum 16, dropped requests, delayed replies, ±100 ms clock offset, 100 ms processing delay, duplicate T3, and verbatim replay. **Run self-test suite** checks every mode over loopback. Each check verifies the bytes on the wire and that this tool's own client accepts, rejects or flags the reply as expected.

On Windows, UDP/123 is usually held by the W32Time service (`net stop w32time`). You can also use any other port. The Windows section of the window shows whether the tool is running as Administrator. From there you can restart it elevated, and when elevated, add a firewall rule for the responder port.

## Building

Install Rust (<https://rustup.rs>), then:

```text
cargo test
cargo build --release
```

The executables are written to `target\release\`. `build_windows.bat` runs the same steps and copies the executables to `dist\`. GitHub Actions builds every push and attaches the executables to a release for every `v*` tag.

## Standards

- RFC 5905 — Network Time Protocol Version 4
- RFC 7822 — NTPv4 Extension Fields
- RFC 8915 — Network Time Security for the Network Time Protocol
- RFC 5297 — Synthetic Initialization Vector (SIV) authenticated encryption
- RFC 8446 / RFC 5705 — TLS 1.3 and keying-material exporters

## Timing note

Client T1/T4 are userspace timestamps, not NIC hardware timestamps. The tool is meant for protocol diagnostics and interoperability testing, not as a sub-microsecond reference.

## License

MIT.
