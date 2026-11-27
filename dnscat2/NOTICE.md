# dnscat2 implementation notes

This module implements the protocol documented by
[iagox86/dnscat2](https://github.com/iagox86/dnscat2), especially
`doc/protocol.md` and `doc/command_protocol.md`.

The packet and cryptography implementation was initially informed by the Go
client in `uetsymphonique/rce-and-c2/dnscat2/go-client`, which carries the
upstream dnscat2 BSD license. The implementation here is independently
structured for embedding into sing-box and includes a client-initiated
`TUNNEL_CONNECT` extension. That extension requires the companion server in
this directory and is not provided by the upstream interactive Ruby server.

No shell, exec, upload, download, persistence, or traffic-evasion features from
the C&C clients are included. The companion only handles ping and TCP tunnel
commands.
