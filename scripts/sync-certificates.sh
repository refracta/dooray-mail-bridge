#!/bin/sh
# Run from the host after certificate renewal, as root (container UID is 10001).
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: $0 SOURCE_CERT_DIRECTORY [DESTINATION_CERT_DIRECTORY]" >&2
    exit 2
fi

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_dir=$1
destination_dir=${2:-"$project_dir/certs"}
test -r "$source_dir/fullchain.pem"
test -r "$source_dir/privkey.pem"

if cmp -s "$source_dir/fullchain.pem" "$destination_dir/fullchain.pem" &&
   cmp -s "$source_dir/privkey.pem" "$destination_dir/privkey.pem"; then
    exit 0
fi

umask 077
mkdir -p "$destination_dir"
temporary_dir=$(mktemp -d "$destination_dir/.renew.XXXXXX")
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM
cp -L "$source_dir/fullchain.pem" "$temporary_dir/fullchain.pem"
cp -L "$source_dir/privkey.pem" "$temporary_dir/privkey.pem"
openssl x509 -in "$temporary_dir/fullchain.pem" -noout -checkend 0 >/dev/null
openssl x509 -in "$temporary_dir/fullchain.pem" -pubkey -noout > "$temporary_dir/cert-public.pem"
openssl pkey -in "$temporary_dir/privkey.pem" -pubout > "$temporary_dir/key-public.pem"
cmp -s "$temporary_dir/cert-public.pem" "$temporary_dir/key-public.pem"
chown 10001:10001 "$destination_dir" "$temporary_dir/fullchain.pem" "$temporary_dir/privkey.pem"
chmod 700 "$destination_dir"
chmod 600 "$temporary_dir/fullchain.pem" "$temporary_dir/privkey.pem"
mv "$temporary_dir/fullchain.pem" "$destination_dir/fullchain.pem"
mv "$temporary_dir/privkey.pem" "$destination_dir/privkey.pem"

compose() {
    if [ -n "${DMB_COMPOSE_BIN:-}" ]; then
        "$DMB_COMPOSE_BIN" --project-directory "$project_dir" "$@"
    else
        "${DMB_DOCKER_BIN:-docker}" compose --project-directory "$project_dir" "$@"
    fi
}

if [ -n "$(compose ps -q bridge)" ]; then
    compose restart bridge
fi
echo "Dooray bridge TLS certificate copy updated."
