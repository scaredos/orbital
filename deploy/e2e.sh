#!/usr/bin/env bash
# Milestone 1 end-to-end check against the docker compose stack.
# usage: deploy/e2e.sh            (builds + starts the stack, then runs every check)
#        KEEP=1 deploy/e2e.sh     (leave the stack running afterwards)
set -euo pipefail
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1 # Git Bash on Windows: don't rewrite /paths passed to docker
DC="docker compose"
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
as() { local u=$1; shift; $DC exec -T -e ORBITAL_HOME=/root/.orb-$u -e ORBITAL_NO_RELOGIN=1 client "$@"; }
retry() { local n=$1; shift; for _ in $(seq "$n"); do "$@" && return 0; sleep 2; done; return 1; }

mkdir -p secrets
[ -s secrets/kek ] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > secrets/kek

echo "== starting stack"
$DC up -d --build
healthy() { $DC exec -T client curl -sfk https://orchestrator:8443/healthz >/dev/null && $DC exec -T client curl -sfk https://orchestrator2:8443/healthz >/dev/null; }
retry 90 healthy || { $DC logs orchestrator | tail -50; fail "orchestrators not healthy"; }
$DC exec -T orchestrator cat /var/lib/orbital/ca.pem > secrets/ca.pem
for c in client host; do $DC exec -T $c sh -c 'cat > /ca.pem' < secrets/ca.pem; done
pass "stack up (2 replicas)"

echo "== logins (OIDC via Keycloak)"
for u in alice:alice-dev-pw carol:carol-dev-pw bob:bob-dev-pw; do
  as "${u%%:*}" sh /e2e/kc-login.sh "${u%%:*}" "${u#*:}" >/dev/null || fail "login ${u%%:*}"
done
pass "alice, carol, bob signed in"

echo "== policy"
as alice orbital policy /e2e/policy.json >/dev/null || fail "policy upload"
pass "policy uploaded"

echo "== enroll node"
cmd=$(as alice orbital node add 2>/dev/null)
dl=$(printf '%s' "$cmd" | grep -o "https://[^'?]*/dl/[^'?]*" | head -1)
[ -n "$dl" ] || fail "no download url in: $cmd"
$DC exec -T host sh -c "curl -fsS --cacert /ca.pem \"$dl?arch=\$(uname -m)\" -o /tmp/orbital-agent && chmod +x /tmp/orbital-agent && /tmp/orbital-agent install -y --name test --label env=dev --expose ssh=22" \
  || fail "agent install"
$DC exec -d host runuser -u orbital -- /opt/orbital/orbital-agent run
online() { as alice orbital ls | grep -E '^test +online'; }
retry 20 online >/dev/null || fail "node never came online"
pass "node 'test' enrolled and online"

echo "== orbital ssh"
out=$(as alice orbital ssh test --reason "e2e" -- whoami)
[ "$(echo "$out" | tr -d '\r')" = "alice" ] || fail "whoami returned: $out"
pass "orbital ssh test whoami -> alice"
sleep 1
sid=$(as alice orbital sessions | grep -o '"id": "[^"]*"' | head -1 | cut -d'"' -f4)
as alice orbital sessions | grep -q '"recording_sha256": "[0-9a-f]\{64\}"' || fail "no recording hash in session row"
$DC exec -T orchestrator test -s "/var/lib/orbital/recordings/$sid.cast" || fail "no asciicast file for $sid"
$DC exec -T orchestrator grep -q alice "/var/lib/orbital/recordings/$sid.cast" || fail "recording lacks output"
pass "audit row + asciicast recording ($sid.cast)"

echo "== denials"
if as bob orbital ssh test --reason "e2e" -- whoami 2>/tmp/orb-err; then fail "bob was allowed"; fi
pass "user without a matching group is denied"
if as alice orbital ssh root@test --reason "e2e" -- whoami 2>/dev/null; then fail "root allowed without explicit rule"; fi
pass "ssh root@test denied without explicit rule"

echo "== approval flow"
as alice sh -c 'orbital ssh deploy@test --reason "deploy hotfix" -- whoami > /tmp/deploy.out 2>/tmp/deploy.err' &
bg=$!
pending() { as carol orbital approvals | grep -o '"id": "[^"]*"' | head -1 | cut -d'"' -f4; }
gid=""; for _ in $(seq 20); do gid=$(pending || true); [ -n "$gid" ] && break; sleep 1; done
[ -n "$gid" ] || fail "approval request never appeared"
kill -0 $bg 2>/dev/null || fail "client did not block on approval"
if as alice orbital approve "$gid" >/dev/null 2>&1; then fail "self-approval allowed"; fi
as carol orbital approve "$gid" >/dev/null || fail "carol approve"
wait $bg || fail "approved ssh failed: $(as alice cat /tmp/deploy.err)"
[ "$(as alice cat /tmp/deploy.out | tr -d '\r')" = "deploy" ] || fail "deploy whoami: $(as alice cat /tmp/deploy.out)"
pass "approval-required rule blocked until carol approved (self-approval refused)"

echo "== sftp audit via orbital setup"
as alice sh -c 'HOME=/root orbital setup >/dev/null; printf "put /etc/os-release /tmp/uploaded.txt\nget /etc/hostname /tmp/got\n" > /tmp/batch'
as alice env ORBITAL_REASON="sftp e2e" sftp -q -b /tmp/batch alice@test.orbital >/dev/null || fail "sftp through Orbital"
sleep 1
as alice orbital sessions | grep -q '"path": "/tmp/uploaded.txt"' || fail "no file_ops row for the upload"
pass "sftp upload recorded as a file op"

echo "== agent budget"
size=$($DC exec -T host stat -c %s /opt/orbital/orbital-agent)
rss=$($DC exec -T host ps -o rss= -C orbital-agent | head -1 | tr -d ' ')
[ "$size" -lt 10485760 ] || fail "agent binary $size bytes"
[ "$rss" -lt 20480 ] || fail "agent RSS ${rss}KB"
pass "agent binary ${size}B (<10MB), RSS ${rss}KB (<20MB)"

echo "== HA: stop replica 1, ssh through replica 2"
$DC stop orchestrator >/dev/null
out=$(as alice env ORBITAL_URL=https://orchestrator2:8443 orbital ssh test --reason "ha" -- whoami) || fail "ssh via orchestrator2"
[ "$(echo "$out" | tr -d '\r')" = "alice" ] || fail "ha whoami: $out"
$DC start orchestrator >/dev/null
retry 30 healthy || fail "orchestrator did not come back"
pass "replica 2 served the session while replica 1 was down"

echo "== live revocation: remove alice from 'devs' mid-session"
redialed() { as alice orbital ssh test --reason "e2e" -- true; }
retry 20 redialed || fail "agent never re-dialed replica 1"
as alice sh -c 'orbital ssh test --reason "long running" -- sleep 300 > /tmp/long.out 2>&1' &
bg=$!
sleep 5
kc="$DC exec -T keycloak /opt/keycloak/bin/kcadm.sh"
$kc config credentials --server http://localhost:8080 --realm master --user admin --password admin >/dev/null
uid=$($kc get users -r orbital -q username=alice --fields id --format csv --noquotes)
gid=$($kc get groups -r orbital -q search=devs --fields id --format csv --noquotes | head -1)
$kc delete "users/$uid/groups/$gid" -r orbital
start=$(date +%s)
for _ in $(seq 90); do kill -0 $bg 2>/dev/null || break; sleep 1; done
elapsed=$(( $(date +%s) - start ))
kill -0 $bg 2>/dev/null && fail "session still alive after ${elapsed}s"
as alice orbital audit --kind session.killed --limit 1 | grep -q "access revoked" || fail "no session.killed audit event"
$kc update "users/$uid/groups/$gid" -r orbital -s realm=orbital -s userId="$uid" -s groupId="$gid" -n
pass "session killed ${elapsed}s after group removal"

echo "== node removal"
as carol orbital node rm test >/dev/null || fail "node rm"
rejected() { as carol orbital audit --kind node.handshake_rejected --limit 1 | grep -q serial; }
retry 15 rejected || fail "agent handshake was not rejected after removal"
pass "removed node's agent is rejected at handshake (cert serial on deny list)"

echo "== forged stream"
echo "(covered by orbital-agent unit test forged_stream_is_refused_and_logged)"

echo
pass "milestone 1 E2E complete"
[ -n "${KEEP:-}" ] || $DC down -v >/dev/null
