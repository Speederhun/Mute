#!/bin/bash
# One-time setup for the iOS project (run on a Mac with Xcode):  cd ios && ./setup.sh
set -euo pipefail
cd "$(dirname "$0")"

command -v xcodegen >/dev/null || { echo "Install XcodeGen first:  brew install xcodegen"; exit 1; }
command -v pod >/dev/null || { echo "Install CocoaPods first:  brew install cocoapods"; exit 1; }
PY=python3
$PY -c 'import sys; assert sys.version_info >= (3, 9)' || { echo "Need python3 >= 3.9 on the Mac"; exit 1; }

PYVER="${PYVER:-3.13}"

# 1. Python runtime for iOS (BeeWare Python-Apple-support) -> Support/Python.xcframework
if [ ! -d Support/Python.xcframework ]; then
  echo "Looking for the newest Python $PYVER iOS support package..."
  # newest package for this Python version; the API call uses GH_TOKEN when there is one (the shared CI IPs hit the anonymous rate limit),
  # and a known-good package is the fallback if the API cannot be reached at all
  FALLBACK_URL="https://github.com/beeware/Python-Apple-support/releases/download/3.13-b18/Python-3.13-iOS-support.b18.tar.gz"
  URL=$($PY - "$PYVER" "${GH_TOKEN:-}" <<'PYEOF' || true
import json, sys, urllib.request
ver, token = sys.argv[1], sys.argv[2]
headers = {"User-Agent": "mute-setup"}
if token:
    headers["Authorization"] = "Bearer " + token
try:
    req = urllib.request.Request("https://api.github.com/repos/beeware/Python-Apple-support/releases?per_page=100", headers=headers)
    for rel in json.load(urllib.request.urlopen(req, timeout=60)):
        if not rel["tag_name"].startswith(ver + "-"):
            continue
        for a in rel["assets"]:
            if "iOS-support" in a["name"] and a["name"].endswith(".tar.gz"):
                print(a["browser_download_url"])
                sys.exit(0)
except Exception as e:
    print("release lookup failed: %s" % e, file=sys.stderr)
PYEOF
)
  if [ -z "$URL" ]; then
    if [ "$PYVER" = "3.13" ]; then
      echo "Using the known package $FALLBACK_URL"
      URL="$FALLBACK_URL"
    else
      echo "no iOS support package found for Python $PYVER"; exit 1
    fi
  fi
  echo "Downloading $URL"
  mkdir -p Support
  # download to a file first, with retries (GitHub sometimes answers 5xx), then unpack
  if ! curl -L --fail --retry 6 --retry-all-errors --retry-delay 10 -o Support/python-support.tar.gz "$URL"; then
    # the CDN sometimes keeps answering 5xx: fetch the same release asset through the GitHub API instead
    echo "curl failed - trying gh release download"
    TAG=$(printf '%s' "$URL" | sed -E 's#.*/download/([^/]+)/.*#\1#')
    gh release download "$TAG" -R beeware/Python-Apple-support -p "$(basename "$URL")" -O Support/python-support.tar.gz --clobber
  fi
  tar -xzf Support/python-support.tar.gz -C Support
  rm -f Support/python-support.tar.gz
fi

# 2. Python packages built for iOS (BeeWare publishes iOS wheels of cryptography and cffi)
for TARGET in iphoneos iphonesimulator; do
  DIR="app_packages.$TARGET"
  if [ ! -d "$DIR" ]; then
    case $TARGET in
      iphoneos) PLAT=ios_13_0_arm64_iphoneos ;;
      iphonesimulator) PLAT=ios_13_0_arm64_iphonesimulator ;;
    esac
    echo "Installing Python packages for $TARGET..."
    $PY -m pip install --upgrade pip >/dev/null
    $PY -m pip install --target "$DIR" \
      --platform "$PLAT" --python-version "${PYVER}" --implementation cp --only-binary=:all: \
      --extra-index-url https://pypi.anaconda.org/beeware/simple \
      "cryptography>=42" "noiseprotocol>=0.3.1" "PySocks>=1.7"
  fi
done

# 3. Xcode project + Tor pod (app/ and app_packages/ are filled by the build; they only have to exist for the project)
mkdir -p app app_packages
xcodegen generate
pod install
echo
echo "Done. Open ios/Mute.xcworkspace in Xcode, pick your iPhone and press Run."
