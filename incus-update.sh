#!/bin/sh
# Rebuild (update) Incus OCI containers from their registered remote.
# Usage: incus-oci-rebuild [container...|-a|--all]
set -e

die() { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARN:  $*" >&2; }
info() { echo "INFO:  $*"; }

# Build hostname->remote_name map from registered remotes
build_remote_map() {
    incus remote list --format json | python3 -c "
import sys, json, re
remotes = json.load(sys.stdin)
for name, v in remotes.items():
    addr = v.get('Addr','')
    # strip credentials from URL
    host = re.sub(r'https?://[^@]*@', 'https://', addr)
    host = re.sub(r'https?://', '', host).rstrip('/')
    if host and host != 'unix://':
        print(name, host)
"
}

# Given image.description like 'docker.io/foo/bar (OCI)', extract host
desc_to_host() {
    echo "$1" | sed 's| (OCI)||' | cut -d/ -f1
}

# Given image.description, extract the path portion (without registry host)
desc_to_path() {
    echo "$1" | sed 's| (OCI)||' | cut -d/ -f2-
}

# Find remote name for a given hostname
find_remote() {
    local host="$1"
    echo "$REMOTE_MAP" | awk -v h="$host" '$2 == h { print $1; exit }'
}

# Check if a tag contains version numbers (digits)
is_versioned_tag() {
    echo "$1" | grep -qE '[0-9]'
}

rebuild_container() {
    local ct="$1"

    local img_type img_desc img_id
    img_type=$(incus config show "$ct" | awk '/^  image\.type:/ { print $2 }')
    img_desc=$(incus config show "$ct" | awk '/^  image\.description:/ { sub(/^  image\.description: /, ""); print }')
    img_id=$(incus config show "$ct"   | awk '/^  image\.id:/          { print $2 }')

    if [ "$img_type" != "oci" ]; then
        info "$ct: skipping (not OCI, type=${img_type:-unknown})"
        return 0
    fi

    local host path tag remote
    host=$(desc_to_host "$img_desc")
    # img_id is like "repo/image:tag" or "image:tag"
    tag="${img_id##*:}"

    remote=$(find_remote "$host")
    if [ -z "$remote" ]; then
        warn "$ct: no registered remote found for host '$host' — skipping"
        return 1
    fi

    local full_ref="${remote}:${img_id}"

    if is_versioned_tag "$tag"; then
        warn "$ct: image tag '$tag' looks versioned (contains digits) — you may want to pin or bump it manually"
        warn "$ct: proceeding with rebuild using: $full_ref"
    else
        info "$ct: rebuilding from $full_ref"
    fi

    incus rebuild "$full_ref" "$ct" --force
    info "$ct: done"
}

# --- main ---

command -v incus >/dev/null 2>&1 || die "'incus' not found in PATH"
command -v python3 >/dev/null 2>&1 || die "'python3' not found in PATH"

REMOTE_MAP=$(build_remote_map)

if [ $# -eq 0 ]; then
    echo "Usage: $(basename "$0") <container> [container...] | -a|--all"
    echo ""
    echo "  -a, --all    Rebuild all running OCI containers"
    exit 1
fi

if [ "$1" = "-a" ] || [ "$1" = "--all" ]; then
    containers=$(incus list --format csv | cut -d, -f1)
else
    containers="$*"
fi

failed=0
for ct in $containers; do
    rebuild_container "$ct" || failed=$((failed + 1))
done

[ "$failed" -gt 0 ] && die "$failed container(s) failed to rebuild"
exit 0