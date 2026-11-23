# NekoBox for Android (podkop-engine core)

[![API](https://img.shields.io/badge/API-21%2B-brightgreen.svg?style=flat)](https://android-arsenal.com/api?level=21)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-orange.svg)](https://www.gnu.org/licenses/gpl-3.0)

**This is a fork of [NekoBox for Android](https://github.com/MatsuriDayo/NekoBoxForAndroid) whose
core is the extended [podkop-engine](https://github.com/podkop-net/podkop-engine) sing-box
(ITDog / podkop) instead of upstream sing-box.**

sing-box / universal proxy toolchain for Android, on the podkop core.

- Core: [podkop-net/sing-box](https://github.com/podkop-net/sing-box), branch
  `podkop-engine-1.14` (sing-box 1.14.4 + podkop patches, currently revision r27),
  with the NekoBox `nekoutils` hooks on top (see `buildScript/lib/core/patches/`).
- What the core adds over vanilla sing-box: Xray-consistent REALITY
  (X25519MLKEM768, Xray uTLS fingerprints), the **XHTTP transport**, **VLESS
  Encryption**, urltest fallback outbounds (`fallbacks`, `urls`, `mode`
  fastest/loss/balance), remote rule-sets that start empty instead of failing,
  compact geosite/geoip memory layout, DNS hardening, podkop's connection
  management and much more — see
  [docs/FEATURES.md](https://github.com/podkop-net/podkop-engine/blob/main/docs/FEATURES.md)
  upstream.
- The app understands podkop share links: `type=xhttp` with `mode`, `host`,
  `path` and the Xray `extra` JSON, and VLESS links with the `encryption`
  parameter. The GUI exposes XHTTP mode / extra JSON and the VLESS encryption
  key per profile.

Full technical details: [PORTING.md](PORTING.md).

一podkop (ITDog/podkop-engine, sing-box 1.14.4-pdk) Android.

## Downloads

Build artifacts are produced by the GitHub Actions workflows of this fork
(`Preview Build` and `Release Build`, run them manually from the Actions tab).
No prebuilt APKs are published here.

## Supported Proxy Protocols

* SOCKS (4/4a/5)
* HTTP(S)
* SSH
* Shadowsocks
* VMess
* Trojan
* VLESS (+ Xray XHTTP transport, + VLESS Encryption)
* AnyTLS
* ShadowTLS
* TUIC
* Hysteria 1/2
* WireGuard
* Trojan-Go (trojan-go-plugin)
* NaïveProxy (naive-plugin)
* Mieru (mieru-plugin)


## Supported Subscription Format

* (Shadowsocks, ClashMeta, v2rayN)
* sing-box 
* Some widely used formats (like Shadowsocks, ClashMeta and v2rayN)
* sing-box outbound

Only resolving outbound, i.e. nodes, is supported. Information such as diversion rules are ignored.
Core:

- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [podkop-net/podkop-engine](https://github.com/podkop-net/podkop-engine) — the extended
  sing-box of podkop (ITDog), the core of this fork
- [podkop-net/sing-box](https://github.com/podkop-net/sing-box) — the patched sing-box
  source the core is built from
- [itdoginfo/podkop](https://github.com/itdoginfo/podkop) — the podkop project itself

Android GUI:

- [shadowsocks/shadowsocks-android](https://github.com/shadowsocks/shadowsocks-android)
- [SagerNet/SagerNet](https://github.com/SagerNet/SagerNet)

Web Dashboard:

- [Yacd-meta](https://github.com/MetaCubeX/Yacd-meta)
