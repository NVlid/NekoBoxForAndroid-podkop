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

一款使用扩展 podkop 内核 (ITDog/podkop-engine, sing-box 1.14.4-pdk) 的 Android 通用代理软件.

## 下载 / Downloads

Build artifacts are produced by the GitHub Actions workflows of this fork
(`Preview Build` and `Release Build`, run them manually from the Actions tab).
No prebuilt APKs are published here.

**Google Play 版本自 2024 年 5 月起已被第三方控制，为非开源版本，请不要下载。**

**The Google Play version has been controlled by a third party since May 2024 and is a non-open
source version. Please do not download it.**

## 更新日志 & Telegram 发布频道 / Changelog & Telegram Channel

https://t.me/Matsuridayo

## 项目主页 & 文档 / Homepage & Documents

https://matsuridayo.github.io

## 支持的代理协议 / Supported Proxy Protocols

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

请到[这里](https://matsuridayo.github.io/nb4a-plugin/)下载插件以获得完整的代理支持.

Please visit [here](https://matsuridayo.github.io/nb4a-plugin/) to download plugins for full proxy
supports.

## 支持的订阅格式 / Supported Subscription Format

* 一些广泛使用的格式 (如 Shadowsocks, ClashMeta 和 v2rayN)
* sing-box 出站

仅支持解析出站，即节点。分流规则等信息会被忽略。

* Some widely used formats (like Shadowsocks, ClashMeta and v2rayN)
* sing-box outbound

Only resolving outbound, i.e. nodes, is supported. Information such as diversion rules are ignored.

## 捐助 / Donate

<details>

如果这个项目对您有帮助, 可以通过捐赠的方式帮助我们维持这个项目.

捐赠满等额 50 USD 可以在「[捐赠榜](https://mtrdnt.pages.dev/donation_list)」显示头像, 如果您未被添加到这里,
欢迎联系我们补充.

Donations of 50 USD or more can display your avatar on
the [Donation List](https://mtrdnt.pages.dev/donation_list). If you are not added here, please
contact us to add it.

USDT TRC20

`TRhnA7SXE5Sap5gSG3ijxRmdYFiD4KRhPs`

XMR

`49bwESYQjoRL3xmvTcjZKHEKaiGywjLYVQJMUv79bXonGiyDCs8AzE3KiGW2ytTybBCpWJUvov8SjZZEGg66a4e59GXa6k5`

</details>

## Credits

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
