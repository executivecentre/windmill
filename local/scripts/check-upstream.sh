#!/bin/sh
# Checks that the committed branch touches upstream exactly where local/PATCHES.md says, measured
# against <upstream-ref> (the upstream commit or tag the branch is based on):
#   1. every file outside local/ that differs from <upstream-ref> is a "Modified upstream files"
#      heading or an "Added files" entry in local/PATCHES.md, and every entry differs;
#   2. modified files exist in <upstream-ref>, added files do not;
#   3. the edition-limit sweep finds exactly the hits recorded in local/edition-limits.txt, so an
#      upstream release that adds a new cap shows up here instead of in production.
# Hits are recorded as "path: text" without line numbers, so they survive unrelated upstream
# edits. After reviewing a sweep difference, record the new state with
#   local/scripts/check-upstream.sh --print-limits > local/edition-limits.txt
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

PATTERN='without an enterprise license|maximum number of|(^|[^A-Z_])CE_MAX|check_nb_of|Community edition is limited|[Ll]imited to [0-9]+'

sweep() {
	git grep -I -E -e "$PATTERN" HEAD -- 'backend/*.rs' 'frontend/src/*.ts' 'frontend/src/*.svelte' |
		sed -e 's/^HEAD://' -e 's/:[[:space:]]*/: /' -e 's/[[:space:]]*$//' | LC_ALL=C sort
}

if [ "${1:-}" = "--print-limits" ]; then
	sweep
	exit 0
fi

ref=${1:?usage: check-upstream.sh <upstream-ref> | --print-limits}
git rev-parse --verify -q "$ref^{commit}" >/dev/null || {
	echo "check-upstream.sh: $ref is not a commit (git fetch origin --tags first?)" >&2
	exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
status=0

# Paths in backticks under "### `path`" (modified) and "- `path`" (added) in their sections.
entries() {
	awk -v want="$1" -v marker="$2" '
		/^## / { insec = ($0 == want); next }
		insec && index($0, marker) == 1 {
			p = substr($0, length(marker) + 1); sub(/`.*$/, "", p); print p
		}' local/PATCHES.md | LC_ALL=C sort
}
entries '## Modified upstream files' '### `' >"$tmp/modified"
entries '## Files added outside `local/`' '- `' >"$tmp/added"
LC_ALL=C sort "$tmp/modified" "$tmp/added" >"$tmp/recorded"
git diff --name-only "$ref" HEAD -- . ':(exclude)local' | LC_ALL=C sort >"$tmp/changed"

unrecorded=$(LC_ALL=C comm -23 "$tmp/changed" "$tmp/recorded")
unchanged=$(LC_ALL=C comm -13 "$tmp/changed" "$tmp/recorded")
if [ -n "$unrecorded" ]; then
	echo "FAIL changed vs $ref but not in local/PATCHES.md:"
	printf '  %s\n' $unrecorded
	status=1
fi
if [ -n "$unchanged" ]; then
	echo "FAIL in local/PATCHES.md but identical to $ref (patch lost, or upstream absorbed it):"
	printf '  %s\n' $unchanged
	status=1
fi
while IFS= read -r f; do
	git cat-file -e "$ref:$f" 2>/dev/null || {
		echo "FAIL modified entry $f does not exist in $ref (renamed or removed upstream)"
		status=1
	}
done <"$tmp/modified"
while IFS= read -r f; do
	if git cat-file -e "$ref:$f" 2>/dev/null; then
		echo "FAIL added entry $f now also exists in $ref"
		status=1
	fi
done <"$tmp/added"
[ "$status" -eq 0 ] && echo "ok   $(wc -l <"$tmp/changed" | tr -d ' ') files outside local/ match local/PATCHES.md"

sweep >"$tmp/limits"
if LC_ALL=C diff -u local/edition-limits.txt "$tmp/limits" >"$tmp/limits.diff"; then
	echo "ok   edition-limit sweep matches local/edition-limits.txt ($(wc -l <"$tmp/limits" | tr -d ' ') hits)"
else
	echo "FAIL edition-limit sweep differs from local/edition-limits.txt (+ new hit to review, - hit gone):"
	sed -n 's/^\([+-]\)\([^+-]\)/  \1 \2/p' "$tmp/limits.diff"
	status=1
fi
exit "$status"
