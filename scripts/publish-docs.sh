#!/usr/bin/env bash
# Renders docs/site and docs/wiki for a release and copies them into checkouts
# of the public website repository and its wiki, ready to commit.
#
#   scripts/publish-docs.sh <public-repo-dir> <public-wiki-dir>
#
# Environment:
#   VERSION       release version, e.g. 3.1.0 (default: the VERSION file)
#   RELEASE_DATE  e.g. 2026-11-03 (default: the CHANGELOG.md heading, else today)
#   DOWNLOAD_URL  where the site's download buttons point (default: RELEASE_URL)
#   RELEASE_URL   the release notes page (default: the public repository's copy)
set -euo pipefail

pub=${1:?public repository checkout}
wiki=${2:?public wiki checkout}
here=$(cd "$(dirname "$0")/.." && pwd)

PUBLIC=optimusprime-nn/ntp-nts-diagnostic-tool
SITE_URL=https://optimusprime-nn.github.io/ntp-nts-diagnostic-tool
VERSION=${VERSION:-$(tr -d '[:space:]' < "$here/VERSION")}
# The date comes from the version's CHANGELOG.md heading, "## [3.1.0] - 2026-11-03".
RELEASE_DATE=${RELEASE_DATE:-$(sed -n "s/^## \[$VERSION\] - \([0-9-]*\).*/\1/p" "$here/CHANGELOG.md" | head -n 1)}
RELEASE_DATE=${RELEASE_DATE:-$(date -u +%Y-%m-%d)}
RELEASE_URL=${RELEASE_URL:-https://github.com/$PUBLIC/releases/tag/v$VERSION}
DOWNLOAD_URL=${DOWNLOAD_URL:-$RELEASE_URL}
WIKI_URL=https://github.com/$PUBLIC/wiki
REPO_URL=https://github.com/$PUBLIC
SOURCE_URL=https://github.com/Optimusprimeums/ntp-nts-diagnostic-tool-rs

fill() {
  sed -e "s#{{VERSION}}#$VERSION#g" \
      -e "s#{{DATE}}#$RELEASE_DATE#g" \
      -e "s#{{DOWNLOAD_URL}}#$DOWNLOAD_URL#g" \
      -e "s#{{RELEASE_URL}}#$RELEASE_URL#g" \
      -e "s#{{WIKI_URL}}#$WIKI_URL#g" \
      -e "s#{{REPO_URL}}#$REPO_URL#g" \
      -e "s#{{SOURCE_URL}}#$SOURCE_URL#g"
}

# The wiki wants page links without .md, and its pictures are served by the site.
wikify() {
  fill | sed -E \
    -e 's#\]\(([A-Za-z0-9.-]+)\.md(\#[^)]*)?\)#](\1\2)#g' \
    -e "s#\]\(\.\./site/screenshots/([^)]+)\)#]($SITE_URL/screenshots/\1)#g"
}

# --- website: served from docs/ on the public repository's main branch -----
mkdir -p "$pub/docs/screenshots"
fill < "$here/docs/site/index.html" > "$pub/docs/index.html"
cp "$here/docs/site/style.css" "$here/docs/site/icon.png" "$pub/docs/"
cp "$here"/docs/site/screenshots/*.png "$pub/docs/screenshots/"

# --- wiki source in the public repository, and the wiki itself ---------------
render_wiki() {
  local out=$1
  mkdir -p "$out"
  find "$out" -mindepth 1 -maxdepth 1 -type f -name '*.md' -delete
  for f in "$here"/docs/wiki/*.md; do
    wikify < "$f" > "$out/$(basename "$f")"
  done
  { echo "# Changelog"; echo; tail -n +2 "$here/CHANGELOG.md"; } | wikify > "$out/Changelog.md"
}
render_wiki "$pub/docs/wiki"
render_wiki "$wiki"

cat > "$pub/docs/RELEASING.md" <<EOF
# Releasing

Since 3.0 the tool is written in Rust and built from
[Optimusprimeums/ntp-nts-diagnostic-tool-rs]($SOURCE_URL). Its release workflow
publishes the installer there, copies the release to this repository, and
updates this website and the wiki. The last release published this way was
**$VERSION** ($RELEASE_DATE).

The Python 2.x sources and releases stay in this repository.
EOF

# Nothing may be left unfilled, and the wiki must use wiki-style links.
if grep -rn '{{[A-Z_]*}}' "$pub/docs" "$wiki" --include='*.md' --include='*.html'; then
  echo "::error::unfilled placeholders" >&2
  exit 1
fi
if grep -rnE '\]\([^)]*\.md([#)]|$)' "$wiki" "$pub/docs/wiki" --include='*.md'; then
  echo "::error::repository-style .md links left in the wiki" >&2
  exit 1
fi
for f in Home _Sidebar Installing Changelog; do
  test -s "$wiki/$f.md"
done
echo "Rendered site and wiki for $VERSION ($RELEASE_DATE)"
