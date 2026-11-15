#!/bin/bash
# Integration test: PostgreSQL authenticating through pam_oidc, which runs
# in-process in the backend. Beyond the login itself it exercises backend
# features that rely on PostgreSQL's own signal handling (SIGURG latches,
# timeouts, cancellation, parallel workers, LISTEN/NOTIFY), since the Go runtime
# also uses SIGURG. Run via Dockerfile.pgtest: a stock PostgreSQL image with the
# module delivered as by the Dockerfile.module init container (PAM_OIDC_MODULE).
set -euo pipefail

fail() { echo "FAIL: $*" >&2; [ -f /tmp/pg.log ] && tail -20 /tmp/pg.log >&2; exit 1; }
pass() { echo "ok   $*"; }

export PGDATA=/tmp/pgdata
issuer=http://127.0.0.1:5556
/usr/local/bin/testissuer -addr 127.0.0.1:5556 -sub system:serviceaccount:apps:tester -aud postgres -out /tmp/token &
/usr/local/bin/testissuer -addr 127.0.0.1:5557 -sub system:serviceaccount:apps:tester -aud postgres -out /tmp/forged &
/usr/local/bin/testissuer -addr 127.0.0.1:5558 -sub system:serviceaccount:apps:tester -aud kubernetes -out /tmp/wrongaud &
for f in /tmp/token /tmp/forged /tmp/wrongaud; do
	for _ in $(seq 50); do [ -s "$f" ] && break; sleep 0.1; done
done
chown postgres /tmp/token /tmp/forged /tmp/wrongaud

cat > /etc/pam.d/pgtest <<EOF
auth required ${PAM_OIDC_MODULE:-pam_oidc.so} issuer=$issuer aud=postgres [user_template={{.Subject | trimPrefix "system:serviceaccount:"}}]
account required pam_permit.so
EOF

gosu postgres initdb -A trust -U postgres >/dev/null
cat > "$PGDATA/pg_hba.conf" <<EOF
local all all              trust
host  all all 127.0.0.1/32 pam pamservice=pgtest
EOF
gosu postgres pg_ctl -w -l /tmp/pg.log start >/dev/null

psql_admin() { gosu postgres psql -XAtq -v ON_ERROR_STOP=1 -c "$1"; }
psql_tok() { PGPASSWORD="$(cat "$1")" gosu postgres psql -XAtq -h 127.0.0.1 -U "$2" -d postgres -v ON_ERROR_STOP=1 "${@:3}"; }

psql_admin 'CREATE ROLE "apps:tester" LOGIN; CREATE ROLE "apps:other" LOGIN;'
psql_admin 'CREATE TABLE big AS SELECT g AS n FROM generate_series(1, 2000000) g; GRANT SELECT ON big TO "apps:tester";'

[ "$(psql_tok /tmp/token apps:tester -c 'SELECT current_user')" = "apps:tester" ] || fail "token login"
pass "login with token ($(wc -c </tmp/token) bytes)"

psql_tok /tmp/forged apps:tester -c 'SELECT 1' 2>/dev/null && fail "token from another issuer accepted"
pass "token from another issuer rejected"
psql_tok /tmp/token apps:other -c 'SELECT 1' 2>/dev/null && fail "token accepted for a different user"
pass "token for another user rejected"
psql_tok /tmp/wrongaud apps:tester -c 'SELECT 1' 2>/dev/null && fail "wrong-audience token accepted"
pass "token for another audience rejected"

psql_tok /tmp/token apps:tester -c 'SELECT pg_sleep(1.5)' >/dev/null || fail "latch wait (pg_sleep)"
pass "latch wait (pg_sleep) in a PAM-authenticated backend"

out=$(psql_tok /tmp/token apps:tester -c 'SET statement_timeout = 300' -c 'SELECT pg_sleep(5)' 2>&1) && fail "statement_timeout did not fire"
grep -q "statement timeout" <<<"$out" || fail "unexpected timeout error: $out"
pass "statement_timeout fires"

plan=$(psql_tok /tmp/token apps:tester \
	-c 'SET parallel_setup_cost = 0' -c 'SET parallel_tuple_cost = 0' \
	-c 'SET min_parallel_table_scan_size = 0' -c 'SET max_parallel_workers_per_gather = 2' \
	-c 'EXPLAIN (ANALYZE, COSTS OFF) SELECT count(*) FROM big')
grep -q "Workers Launched: [1-9]" <<<"$plan" || fail "parallel workers did not run: $plan"
pass "parallel query ($(grep -o 'Workers Launched: [0-9]*' <<<"$plan"))"

psql_tok /tmp/token apps:tester -c 'SELECT pg_sleep(30)' >/tmp/cancel.out 2>&1 &
sleeper=$!
for _ in $(seq 50); do
	[ "$(psql_admin "SELECT count(*) FROM pg_stat_activity WHERE usename = 'apps:tester' AND query LIKE 'SELECT pg_sleep(30)%'")" = 1 ] && break
	sleep 0.1
done
psql_admin "SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE usename = 'apps:tester' AND query LIKE 'SELECT pg_sleep(30)%'" >/dev/null
wait "$sleeper" && fail "cancelled query completed"
grep -q "canceling statement due to user request" /tmp/cancel.out || fail "cancel: $(cat /tmp/cancel.out)"
pass "query cancellation from another session"

(sleep 1; psql_admin "NOTIFY ch, 'hello'") &
notified=$(psql_tok /tmp/token apps:tester -c 'LISTEN ch' -c 'SELECT pg_sleep(2)' 2>&1)
grep -q 'notification "ch" with payload "hello"' <<<"$notified" || fail "LISTEN/NOTIFY: $notified"
pass "LISTEN/NOTIFY delivered"

# not_before revokes tokens issued before the cutoff. PostgreSQL re-reads the
# PAM config on every connection, so no restart is needed here.
cp /etc/pam.d/pgtest /tmp/pgtest.orig
sed -i "s|aud=postgres|aud=postgres not_before=$(( $(date +%s) + 3600 ))|" /etc/pam.d/pgtest
psql_tok /tmp/token apps:tester -c 'SELECT 1' 2>/dev/null && fail "token issued before not_before accepted"
grep -q "before not_before" /tmp/pg.log || fail "no not_before rejection in server log"
cp /tmp/pgtest.orig /etc/pam.d/pgtest
[ "$(psql_tok /tmp/token apps:tester -c 'SELECT current_user')" = "apps:tester" ] || fail "login after removing not_before"
pass "not_before revokes older tokens (and lifting it restores access)"

grep -qiE "terminated by signal|server process .* was terminated|PANIC" /tmp/pg.log && fail "backend crashed"
pass "no backend crashes in the server log"
grep -q 'pam_oidc: authenticated "apps:tester"' /tmp/pg.log || fail "no pam_oidc audit line in server log"
pass "pam_oidc logs to the server log"
echo "PASS: PostgreSQL + pam_oidc"
