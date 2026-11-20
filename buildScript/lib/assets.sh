#!/bin/bash

set -e

DIR=app/src/main/assets/sing-box
rm -rf $DIR
mkdir -p $DIR
cd $DIR

# Download the latest asset without GitHub API (unauthenticated API calls are
# easy to rate-limit on shared Actions runners and return an empty tag).
download_latest() {
  repo="$1"
  asset="$2"
  final_url=$(curl -fLSs -o "$asset" -w '%{url_effective}' \
    "https://github.com/$repo/releases/latest/download/$asset")
  echo "$final_url" | sed -E 's#.*/download/([^/]+)/.*#\1#'
}

VERSION_GEOIP=$(download_latest "SagerNet/sing-geoip" "geoip.db")
echo VERSION_GEOIP=$VERSION_GEOIP
echo -n $VERSION_GEOIP > geoip.version.txt
xz -9 geoip.db

####
VERSION_GEOSITE=$(download_latest "SagerNet/sing-geosite" "geosite.db")
echo VERSION_GEOSITE=$VERSION_GEOSITE
echo -n $VERSION_GEOSITE > geosite.version.txt
xz -9 geosite.db
