#!/bin/sh
# Builds windmill-custom:local (and windmill-entra:local when its sources exist) from this
# checkout. The previous image is kept as windmill-custom:prev for rollback.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

# Never build Enterprise code: these features pull in private sources or turn auth off.
features="oss_core,all_languages,jemalloc"
case ",$features," in
*,private,* | *,enterprise,* | *,no_auth,* | *,oss,*)
	echo "build.sh: refusing forbidden cargo feature in '$features'" >&2
	exit 1
	;;
esac

sha=$(git rev-parse HEAD)
if docker image inspect windmill-custom:local >/dev/null 2>&1; then
	docker tag windmill-custom:local windmill-custom:prev
fi

DOCKER_BUILDKIT=1 docker build \
	--build-arg features="$features" \
	--label "org.opencontainers.image.revision=$sha" \
	--label "org.opencontainers.image.source=https://github.com/windmill-labs/windmill" \
	-t windmill-custom:local .

if [ -f local/entra-gateway/Dockerfile ]; then
	if docker image inspect windmill-entra:local >/dev/null 2>&1; then
		docker tag windmill-entra:local windmill-entra:prev
	fi
	DOCKER_BUILDKIT=1 docker build \
		--label "org.opencontainers.image.revision=$sha" \
		-t windmill-entra:local local/entra-gateway
fi

docker image ls --filter reference='windmill-custom:*' --filter reference='windmill-entra:*'
