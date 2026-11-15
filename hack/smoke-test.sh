#!/bin/sh
# Loads a built pam_oidc.so through a real PAM stack (hack/pamcheck.c) to prove it
# works on this libc: the library loads, the Go runtime starts, and the PAM
# calls (get user, get token, log) succeed. The issuer is unreachable on
# purpose, so authentication must fail with pam_oidc's own diagnostic rather
# than crashing or failing to load.
#
#   hack/smoke-test.sh /path/to/pam_oidc.so
set -eu

so=$(readlink -f "${1:?usage: smoke-test.sh /path/to/pam_oidc.so}")
here=$(dirname "$0")
pamcheck=$(mktemp)
cc -o "$pamcheck" "$here/pamcheck.c" -lpam
service=pam-oidc-smoke
log=$(mktemp)

mkdir -p /etc/pam.d # absent on minimal images such as Alpine
cat > "/etc/pam.d/$service" <<EOF
auth required $so issuer=http://127.0.0.1:9 aud=smoke
account required pam_permit.so
EOF

if "$pamcheck" "$service" smokeuser not-a-token 2> "$log"; then
	echo "FAIL: authentication succeeded against an unreachable issuer" >&2
	cat "$log" >&2
	exit 1
fi

if ! grep -q "pam_oidc: failed to discover authenticator" "$log"; then
	echo "FAIL: pam_oidc did not run (wrong libc? module failed to load?)" >&2
	cat "$log" >&2
	exit 1
fi

echo "OK: $so loads and runs under PAM"
