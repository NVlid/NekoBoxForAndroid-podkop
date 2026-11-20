# Porting NekoBox for Android to the podkop-engine core

This fork replaces the sing-box core of NekoBox for Android with the extended
**podkop-engine** core from ITDog / podkop:

| | upstream NekoBox (main) | this fork |
|---|---|---|
| core source | `MatsuriDayo/sing-box` @ `aed32ee` (1.12.19-neko-1) | `podkop-net/sing-box` branch `podkop-engine-1.14` @ `337cfff5` (1.14.4-pdk, r27) |
| core features | vanilla sing-box + nekoutils hooks | 66 podkop patches: XHTTP transport, VLESS Encryption, Xray-consistent REALITY (X25519MLKEM768), urltest fallbacks, Xray uTLS fingerprints, compact rule-set memory, podkop connection management, … |
| app | VLESS ws/grpc/http/httpupgrade/quic | + **xhttp** (mode/host/path/Xray `extra` JSON), + **VLESS Encryption** key per profile |

## Layout of the changes

### 1. Core source & patches — `buildScript/lib/core/`

- `get_source_env.sh` pins the podkop branch commit and the core version string
  (`CORE_VERSION`, written into `constant/version.go` at checkout time, so
  `versionBox()` reports `sing-box: 1.14.4-pdk-r27-neko-1`).
- `get_source.sh` clones `https://github.com/podkop-net/sing-box.git`, checks
  out the pinned commit, applies the NekoBox hooks from
  `buildScript/lib/core/patches/` and stamps the version.
- `patches/0001-0003-*.patch` re-add the `nekoutils` package that the
  MatsuriDayo fork carried on 1.12 and that libcore needs:

  * `GetGeoIPHeadlessRules` / `GetGeoSiteHeadlessRules` — resolve the
    `geoip:` / `geosite:` local rule-sets (path prefix) from the APK-embedded
    databases, wired into `route/rule/rule_set_local.go`;
  * `Selector_OnProxySelected` — report selector changes to the app, wired
    into `protocol/group/selector.go`.

  The patches are forward-ports of the equivalent 1.12 code onto the 1.14
  line. To update the core, bump `COMMIT_SING_BOX` to a newer commit of the
  `podkop-engine-1.14` branch and re-check that the patches still apply
  (`get_source.sh` fails loudly when they do not).

### 2. libcore (Go) — `libcore/`

sing-box 1.13/1.14 removed several APIs that the 1.12-era libcore used. The
port replaces them with the 1.14 equivalents without changing the gomobile
API surface (the Kotlin code keeps working as-is):

- `box.go`
  * `boxapi.SbV2rayServer` → `experimental/v2rayapi.StatsService`
    (`v2rayapi.NewStatsService` + `GetStats`); stats counters keep the
    `outbound>>>tag>>>traffic>>>uplink/downlink` names and reset-on-read
    semantics.
  * `boxapi.CreateProxyHttpClient` → local `createProxyHttpClient` dialing
    through the default outbound with `dialer.NewDetour` (same behaviour as
    the removed boxapi).
  * `conntrack.Close()` (with_conntrack) → `adapter.NetworkManager.
    ResetNetwork(ctx)` (closes the box connections the podkop way and
    re-detects the network).
  * `box.Context(...)` now takes a certificate provider registry
    (`adapter/certificate.NewRegistry()`, empty — no ACME on Android).
  * platform registration moved to `adapter.PlatformInterface`
    (see `platform_box.go`).
- `box_include.go`
  * DNS transport registry uses the new generic
    `dns.RegisterTransport[option.LocalDNSServerOptions](...)` for the custom
    `local` transport; `transport.RegisterTCP/RegisterUDP/RegisterTLS/
    RegisterHTTPS`, `quic.RegisterTransport/RegisterHTTP3Transport`,
    `hosts.RegisterTransport`, `fakeip.RegisterTransport` are unchanged.
- `platform_box.go` — full rewrite of the wrapper against the (much larger)
  `adapter.PlatformInterface` of 1.14: `OpenInterface` (was `OpenTun`),
  `UsePlatformNetworkInterfaces`/`NetworkInterfaces`, `ReadWIFIState(ctx)`,
  `FindConnectionOwner(request)` (replaces `process.Searcher`), stubs for
  notification / neighbor / shell / bridge APIs.
- `interface_monitor.go` — `DefaultInterfaceMonitor` now requires
  `MyInterfaces() []string`.
- `certs.go` — the `//go:linkname` hack for `crypto/x509.systemRoots` is
  replaced with the Go ≥1.24 public API `x509.SetFallbackRoots` (the Go 1.25
  linker check would reject the linkname).
- `go.mod` — requirements follow the podkop branch (sing 0.9.7, sing-tun
  0.9.7, quic-go 0.61, …) and repeat podkop's `replace` directives
  (`podkop-net/quic-go`, `podkop-net/sing-quic`, `FiyeroT/sing-vmess`), which
  are ignored when they only live in the replaced module's own go.mod. The
  build runs `go mod tidy` before binding to keep `go.sum` consistent.
- `build.sh` — tags are now
  `with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,badlinkname`
  (no more `with_conntrack`), ldflags add `-checklinkname=0` so the
  `badlinkname`-tagged sing-box files (badtls read-wait, ktls, oom killer)
  link on Go 1.25/1.26.

### 3. App (Kotlin / Java) — `app/`

- `SingBoxOptions.java`
  * `V2RayTransportOptions_XHTTPOptions` + `XHTTPXmuxOptions`,
    `XHTTPDownloadOptions`, `XHTTPDownloadTLSOptions` (podkop JSON field
    names, ranges as strings);
  * `encryption` added to `VLESSOutboundOptions` and `Outbound_VLESSOptions`;
  * podkop urltest fields (`fallbacks`, `download_url`, `idle_timeout`,
    `urls`, `mode`, `loss_url`, `loss_interval`, `loss_threshold`,
    `balance_size`, `balance_idle`) added to `URLTestOutboundOptions` and
    `Outbound_URLTestOptions` so imported sing-box configs with them survive
    a parse/re-serialize round trip.
- `StandardV2RayBean.java` — kryo serialization bumped to version 5 with new
  fields `xhttpMode`, `xhttpExtra` (raw Xray extra JSON), `vlessEncryption`;
  `xhttp` participates in the transport switch like http/httpupgrade.
- `V2RayFmt.kt`
  * parses `type=xhttp` links (`host`, `path`, `mode`, `extra`) and VLESS
    `encryption` links;
  * `buildSingBoxOutboundStreamSettings` builds the xhttp transport and maps
    the Xray `extra` JSON onto the sing-box options (full mapping per
    podkop-engine's `docs/LINKS.md`, including `xmux`, `headers` and
    `downloadSettings`);
  * link export writes `mode`/`extra` and the VLESS encryption parameter.
- UI: `networks_value` gains `xhttp`; new preferences `xhttpMode`,
  `xhttpExtra`, `vlessEncryption` (`standard_v2ray_preferences.xml`,
  `StandardV2RaySettingsActivity`, `Constants.kt`), strings in `values/` and
  `values-ru/`.

### 4. CI — `.github/workflows/`

Both workflows build the core with Go `^1.26` (podkop-engine releases are
built with Go 1.26.x; the `go` line of the module is 1.25.5 and the toolchain
auto-upgrades if needed).

## Building

Exactly like upstream NekoBox, but the core is fetched from the podkop
repositories:

```sh
# prerequisites: Linux (x86_64), Go >= 1.25.5, Android SDK + NDK 25
./run init action gradle   # fetch source, install gomobile, init gradle
./run lib core             # clone podkop-net/sing-box + libneko, apply
                           # nekoutils patches, go mod tidy, gomobile bind
./gradlew app:assemblePreviewRelease   # or assembleOssRelease
```

Or run the `Preview Build` workflow of this repository on GitHub Actions —
it does all of the above and uploads the APKs as artifacts.

## Updating the podkop core

1. Pick a newer commit on
   [podkop-net/sing-box:podkop-engine-1.14](https://github.com/podkop-net/sing-box/commits/podkop-engine-1.14)
   and set it as `COMMIT_SING_BOX` in `buildScript/lib/core/get_source_env.sh`;
   adjust `CORE_VERSION` (see podkop-engine releases for the matching
   `-rNN` revision).
2. Rebase `buildScript/lib/core/patches/` if a hunk no longer applies.
3. If the go.mod of the branch changed, mirror the changed requirements and
   replace directives into `libcore/go.mod` (or just let `go mod tidy` fix
   requirements and only keep the `replace` block in sync).

## Known differences / caveats

- `Reset connections` now resets through the box `NetworkManager` — the
  global `conntrack` table of sing-box ≤1.12 no longer exists.
- Stats counters reset on read, as before (the app accumulates them).
- The podkop `podkop_slim` tag is not used: the Android build carries all
  outbounds like the `podkop-engine-full` OpenWrt package.
- The podkop engine reports its version as `1.14.4-pdk-r27-neko-1` — the
  `-pdk-` marker is how podkop-engine identifies itself to podkop on OpenWrt.
