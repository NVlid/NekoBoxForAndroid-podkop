#!/bin/bash

source ./env_java.sh || true
source ../buildScript/init/env_ndk.sh

BUILD=".build"

rm -rf $BUILD/android \
  $BUILD/java \
  $BUILD/javac-output \
  $BUILD/src

if [ -z "$GOPATH" ]; then
  GOPATH=$(go env GOPATH)
fi

# The core is the extended podkop-engine sing-box (branch podkop-engine-1.14),
# fetched and patched by ../buildScript/lib/core/get_source.sh.
# Reconcile go.mod/go.sum with the sing-box 1.14 line before binding.
go mod tidy || exit 1

# Compile and exercise registered adapters before the expensive mobile bind.
go test -ldflags='-checklinkname=0' ./dnscat2 ./sshuttle || exit 1

# podkop-engine build tags:
#   with_gvisor   tun gVisor stack
#   with_quic     QUIC transports (hysteria/tuic DNS, v2ray-quic)
#   with_wireguard
#   with_utls     uTLS fingerprinting
#   with_clash_api
#   badlinkname   sing-box 1.14 uses //go:linkname on Go 1.25/1.26 (badtls
#                 read-wait, ktls, oom killer); the tag selects those files
#                 and -checklinkname=0 allows linking them
# (with_conntrack no longer exists in sing-box 1.14; podkop tracks its own
#  connections and closes them through the NetworkManager.)
export GOBIND=gobind-matsuri
"$GOPATH"/bin/gomobile-matsuri bind -v -androidapi 21 -cache "$(realpath $BUILD)" -trimpath -ldflags='-s -w -checklinkname=0' -tags='with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,badlinkname' . || exit 1
rm -r libcore-sources.jar

proj=../app/libs
mkdir -p $proj
cp -f libcore.aar $proj
echo ">> install $(realpath $proj)/libcore.aar"
