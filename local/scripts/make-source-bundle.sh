#!/bin/sh
# AGPLv3 §13: writes the Corresponding Source of the images a deployment runs to local/dist/,
# which the deployment's Caddy serves read-only at /source/. WINDMILL_IMAGE and
# ENTRA_GATEWAY_IMAGE name the images when they are not the local build.sh tags. One archive per distinct image revision, taken
# with `git archive` from that commit (local/ included), so git-ignored files can never be
# included. Run it after every build.sh.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

revs=""
images="${WINDMILL_IMAGE:-windmill-custom:local} ${ENTRA_GATEWAY_IMAGE:-windmill-entra:local}"
for img in $images; do
	rev=$(docker image inspect "$img" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null) || {
		echo "make-source-bundle.sh: image $img not found; run local/scripts/build.sh" >&2
		exit 1
	}
	case "$rev" in
	"" | *-dirty)
		echo "make-source-bundle.sh: $img has revision '$rev'; rebuild it from a clean commit" >&2
		exit 1
		;;
	esac
	if ! git cat-file -e "$rev^{commit}" 2>/dev/null; then
		echo "make-source-bundle.sh: $img was built from $rev, which is not in this repository" >&2
		exit 1
	fi
	revs="$revs $rev"
done

mkdir -p local/dist
for rev in $(printf '%s\n' $revs | sort -u); do
	out="local/dist/windmill-custom-src-$rev.tar.gz"
	if [ ! -s "$out" ]; then
		git archive --format=tar.gz --prefix="windmill-custom-$rev/" -o "$out.tmp" "$rev"
		mv "$out.tmp" "$out"
		echo "created  $out"
	else
		echo "keep     $out"
	fi
done

{
	echo "Source code of the modified Windmill server (GNU AGPLv3) running on this instance,"
	echo "and of its Entra sign-in gateway. Fork: https://github.com/executivecentre/windmill"
	echo "Upstream: https://github.com/windmill-labs/windmill"
	echo
	for img in $images; do
		rev=$(docker image inspect "$img" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
		echo "$img  built from commit $rev  ->  windmill-custom-src-$rev.tar.gz"
	done
} >local/dist/README.txt
if command -v sha256sum >/dev/null 2>&1; then
	sum="sha256sum"
else
	sum="shasum -a 256"
fi
(cd local/dist && $sum windmill-custom-src-*.tar.gz >SHA256SUMS)
echo "wrote    local/dist/README.txt and local/dist/SHA256SUMS"
