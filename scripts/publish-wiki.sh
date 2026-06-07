#!/usr/bin/env bash
# Publish docs/wiki/ to this repo's GitHub Wiki (the separate <repo>.wiki.git repo).
#
# docs/wiki/ stays the source of truth (versioned with the code, CLAUDE.md §5.1); this
# mirrors it into the GitHub Wiki, transforming for GitHub-Wiki conventions:
#   - docs/wiki/README.md          -> Home.md            (the wiki landing page)
#   - intra-wiki links  (foo.md)   -> (foo)              (wiki page slugs carry no .md)
#   - cross-repo links  (../../x)  -> https://github.com/OWNER/REPO/blob/BRANCH/x
#                       (../x)     -> .../blob/BRANCH/docs/x
#   - generates _Sidebar.md navigation from each page's H1
#
# Usage:
#   ./scripts/publish-wiki.sh                  # derive the wiki remote from `origin`
#   WIKI_REMOTE=git@github.com:me/repo.wiki.git ./scripts/publish-wiki.sh
#   DRY_RUN=1 WIKI_REMOTE=... OWNER_REPO=me/repo ./scripts/publish-wiki.sh   # build, don't push
#
# Prereq: the repo's Wiki must be ENABLED (Settings > Features > Wikis) and INITIALIZED
# (create one page in the web UI once) so <repo>.wiki.git exists. The CI workflow
# (.github/workflows/publish-wiki.yml) runs this on every push to docs/wiki/.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT=$(pwd)
WIKI_SRC="$REPO_ROOT/docs/wiki"
BRANCH="${WIKI_SOURCE_BRANCH:-main}"

origin="${WIKI_ORIGIN:-$(git remote get-url origin 2>/dev/null || true)}"
wiki_remote="${WIKI_REMOTE:-}"
if [[ -z "$wiki_remote" ]]; then
  [[ -n "$origin" ]] || { echo "publish-wiki: no 'origin' remote and no WIKI_REMOTE set." >&2; exit 1; }
  wiki_remote="${origin%.git}.wiki.git"
fi
slug=$(printf '%s' "${OWNER_REPO:-$origin}" | sed -E 's#^git@[^:]+:##; s#^https?://[^/]+/##; s#\.git$##')
base_url="https://github.com/${slug}/blob/${BRANCH}"

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
echo "publish-wiki: wiki remote   = $wiki_remote"
echo "publish-wiki: cross-repo to = $base_url"

if git clone --depth 1 "$wiki_remote" "$work/wiki" 2>/dev/null; then
  echo "publish-wiki: cloned existing wiki."
else
  echo "publish-wiki: wiki repo not cloneable yet; initializing a fresh one."
  git init -q "$work/wiki"; git -C "$work/wiki" remote add origin "$wiki_remote"
fi
cd "$work/wiki"
git config user.name  "${GIT_AUTHOR_NAME:-wiki-bot}"
git config user.email "${GIT_AUTHOR_EMAIL:-wiki-bot@users.noreply.github.com}"

transform() {   # stdin -> stdout: rewrite Markdown links for GitHub Wiki ( | = sed delim )
  sed -E \
    -e "s|\]\(\.\./\.\./([^)]+)\)|](${base_url}/\1)|g" \
    -e "s|\]\(\.\./([^)]+)\)|](${base_url}/docs/\1)|g" \
    -e 's|\]\(README\.md(#[^)]*)?\)|](Home\1)|g' \
    -e 's|\]\(([A-Za-z0-9_-]+)\.md(#[^)]*)?\)|](\1\2)|g'
}

rm -f ./*.md
sidebar="$work/wiki/_Sidebar.md"
{ echo "## Common Lisp DDS wiki"; echo; echo "- [Home](Home)"; } > "$sidebar"

transform < "$WIKI_SRC/README.md" > Home.md
for f in "$WIKI_SRC"/*.md; do
  base=$(basename "$f" .md); [[ "$base" == "README" ]] && continue
  transform < "$f" > "$base.md"
  title=$(grep -m1 '^# ' "$f" | sed -E 's/^# +//; s/ *\(L[0-9]\)//')
  echo "- [${title:-$base}]($base)" >> "$sidebar"
done

git add -A
if git diff --cached --quiet; then echo "publish-wiki: wiki already up to date."; exit 0; fi
git commit -q -m "Sync wiki from docs/wiki @ ${BRANCH} ($(git -C "$REPO_ROOT" rev-parse --short HEAD))"

if [[ "${DRY_RUN:-0}" == "1" ]]; then
  echo "publish-wiki: DRY_RUN — built mirror (not pushed):"; git -C "$work/wiki" show --stat --oneline HEAD | head -20
  echo "--- _Sidebar.md ---"; cat "$sidebar"; exit 0
fi
if ! git push origin HEAD:master 2>/dev/null && ! git push origin HEAD:main 2>/dev/null; then
  echo "publish-wiki: PUSH FAILED. Enable the repo Wiki (Settings > Features > Wikis) and create one page in the web UI once to initialize it. In CI, set a PAT in secrets.WIKI_TOKEN if GITHUB_TOKEN lacks wiki write." >&2
  exit 1
fi
echo "publish-wiki: pushed docs/wiki -> $wiki_remote"
