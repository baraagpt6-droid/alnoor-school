#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

ARCHIVE="alnoor-school-release-1.1.3.zip"
test -s "$ARCHIVE"
unzip -t "$ARCHIVE"
rm -rf site
mkdir -p site
unzip -q "$ARCHIVE" -d site
rm -rf site/.github

# Keep the live app shell and PWA metadata in sync with the current main branch.
cp index.html sw.js manifest.json bootstrap.html site/
test -s site/index.html
test -s site/styles.fixed.css
test -s site/manifest.json
test -s site/sw.js
test -s site/bootstrap.html

# Bundle runtime libraries locally so the PWA shell does not depend on CDNs at runtime.
mkdir -p site/vendor
curl --retry 3 --retry-delay 2 -fLsS https://unpkg.com/react@18.3.1/umd/react.production.min.js -o site/vendor/react.production.min.js
curl --retry 3 --retry-delay 2 -fLsS https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js -o site/vendor/react-dom.production.min.js
curl --retry 3 --retry-delay 2 -fLsS https://unpkg.com/@babel/standalone@7.26.10/babel.min.js -o site/vendor/babel.min.js
curl --retry 3 --retry-delay 2 -fLsS https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js -o site/vendor/three.min.js
curl --retry 3 --retry-delay 2 -fLsS https://unpkg.com/qrcode-generator@1.4.4/qrcode.js -o site/vendor/qrcode.min.js
for file in react.production.min.js react-dom.production.min.js babel.min.js three.min.js qrcode.min.js; do
  test -s "site/vendor/$file"
done

grep -q 'const APP_VERSION = "2.0.1";' site/index.html
grep -q 'alnoor-school-v2.0.1' site/sw.js
grep -q 'vendor/qrcode.min.js' site/index.html

echo "Netlify publish directory assembled and validated."
