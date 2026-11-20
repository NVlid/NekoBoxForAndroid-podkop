#!/bin/bash
set -e

source "buildScript/init/env.sh"
ENV_NB4A=1
source "buildScript/lib/core/get_source_env.sh"

REPO_ROOT="$(pwd)"
pushd ..

####
# Extended core: podkop-engine (ITDog), the sing-box fork used by podkop.
# https://github.com/podkop-net/sing-box (branch podkop-engine-1.14)
####

if [ ! -d "sing-box" ]; then
  git clone --no-checkout https://github.com/podkop-net/sing-box.git
fi
pushd sing-box
# Re-runs: drop the previously applied nekoutils patches and any leftovers so
# the checkout is clean and the patches below always apply.
git fetch origin "$COMMIT_SING_BOX" --depth 1 2>/dev/null || true
git checkout -f "$COMMIT_SING_BOX" 2>/dev/null || git checkout "$COMMIT_SING_BOX"
git clean -fdx 2>/dev/null || true
popd

# NekoBox-specific hooks (nekoutils): geoip:/geosite: rule-sets and
# selector callbacks used by libcore.
pushd sing-box
if git apply --check "$REPO_ROOT"/buildScript/lib/core/patches/*.patch 2>/dev/null; then
  git apply "$REPO_ROOT"/buildScript/lib/core/patches/*.patch
else
  # Re-applied? Only treat it as an error when the hook package is absent.
  if [ ! -f nekoutils/callback.go ]; then
    echo ">> failed to apply nekoutils patches"
    git apply --verbose "$REPO_ROOT"/buildScript/lib/core/patches/*.patch
    exit 1
  fi
  echo ">> nekoutils patches already applied"
fi
popd

# Write the core version, podkop-engine style:
# `sing-box version` will print "1.14.4-pdk-r27-neko-1".
pushd sing-box
perl -pi -e 's/var Version = "unknown"/var Version = "$ENV{CORE_VERSION}"/' constant/version.go
popd

####

if [ ! -d "libneko" ]; then
  git clone --no-checkout https://github.com/MatsuriDayo/libneko.git
fi
pushd libneko
git fetch origin "$COMMIT_LIBNEKO" --depth 1 2>/dev/null || true
git checkout -f "$COMMIT_LIBNEKO" 2>/dev/null || git checkout "$COMMIT_LIBNEKO"
popd

####

popd
