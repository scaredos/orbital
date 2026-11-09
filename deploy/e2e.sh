#!/usr/bin/env bash
# End-to-end check against the docker compose stack.
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

echo "== portal"
ORCH=https://orchestrator:8443
# pc <user> <curl args>: curl as that user's portal session (cookie jar from portal-login.sh)
pc() { local u=$1; shift; $DC exec -T client curl -sS --cacert /ca.pem -b "/tmp/jar-$u" "$@"; }
jq() { $DC exec -T client python3 /e2e/jq.py "$1"; }
LIVE_WEB='next((s["id"] for s in d if s["protocol"] == "ssh-web" and not s["ended_at"]), None)'
$DC exec -T client curl -sS -D /tmp/h --cacert /ca.pem $ORCH/ | grep -q '<div id="root">' || fail "portal index not served"
$DC exec -T client grep -qi '^content-security-policy:' /tmp/h || fail "portal index has no CSP header"
csrf_alice=$($DC exec -T client sh /e2e/portal-login.sh alice alice-dev-pw) && [ -n "$csrf_alice" ] || fail "portal login alice"
csrf_carol=$($DC exec -T client sh /e2e/portal-login.sh carol carol-dev-pw) && [ -n "$csrf_carol" ] || fail "portal login carol"
pc carol $ORCH/v1/me | grep -q '"username":"carol"' || fail "/v1/me with the session cookie"
$DC exec -T client grep -q 'orbital_session' /tmp/jar-carol || fail "no session cookie"
pass "portal served with CSP; alice and carol signed in via SSO (HttpOnly session cookie)"

as alice orbital revoke "$gid" >/dev/null || fail "revoke cached deploy grant" # else the CLI reuses it
as alice sh -c 'orbital ssh deploy@test --reason "portal approval" -- whoami > /tmp/deploy2.out 2>/tmp/deploy2.err' &
bg=$!
pgid=""; for _ in $(seq 20); do pgid=$(pc carol $ORCH/v1/approvals | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4 || true); [ -n "$pgid" ] && break; sleep 1; done
[ -n "$pgid" ] || fail "portal approval queue stayed empty"
code=$(pc carol -o /dev/null -w '%{http_code}' -X POST $ORCH/v1/grants/$pgid/approve)
[ "$code" = 403 ] || fail "approve without CSRF token returned $code"
code=$(pc carol -o /dev/null -w '%{http_code}' -X POST -H "x-orbital-csrf: wrong" $ORCH/v1/grants/$pgid/approve)
[ "$code" = 403 ] || fail "approve with a wrong CSRF token returned $code"
pc carol -f -X POST -H "x-orbital-csrf: $csrf_carol" $ORCH/v1/grants/$pgid/approve >/dev/null || fail "portal approve"
wait $bg || fail "portal-approved ssh failed: $(as alice cat /tmp/deploy2.err)"
[ "$(as alice cat /tmp/deploy2.out | tr -d '\r')" = "deploy" ] || fail "deploy whoami: $(as alice cat /tmp/deploy2.out)"
pass "carol approved from the portal (requests without the CSRF token refused)"

# browser SSH: same relay as the CLI, so it's recorded and audited the same way
grant() { pc alice -f -X POST -H "x-orbital-csrf: $csrf_alice" -H 'content-type: application/json' \
  -d "{\"node\":\"test\",\"reason\":\"$1\"}" $ORCH/v1/grants | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4; }
wg=$(grant "browser e2e") && [ -n "$wg" ] || fail "portal grant"
if $DC exec -T -e WS_ORIGIN=https://evil.example -e WS_SECS=5 client python3 /e2e/ws.py "/v1/terminal?grant=$wg" /tmp/jar-alice >/dev/null 2>&1; then
  fail "terminal websocket accepted a foreign Origin"
fi
$DC exec -T -e WS_SEND='echo hi-$((6*7)); sleep 8; echo done-$((40+2)); exit' -e WS_SECS=40 client \
  sh -c "python3 /e2e/ws.py '/v1/terminal?grant=$wg' /tmp/jar-alice > /tmp/term.out 2> /tmp/term.ctl" &
bg=$!
wsid=""; for _ in $(seq 20); do
  wsid=$(pc carol $ORCH/v1/sessions | jq "$LIVE_WEB" || true)
  [ -n "$wsid" ] && $DC exec -T client grep -q 'hi-42' /tmp/term.out && break; sleep 1
done
[ -n "$wsid" ] || fail "browser session never showed up as live (ctl: $($DC exec -T client cat /tmp/term.ctl))"
# live view: carol watches read-only
$DC exec -T -e WS_SECS=20 client python3 /e2e/ws.py "/v1/sessions/$wsid/live" /tmp/jar-carol > /tmp/live.out 2>/dev/null || true
wait $bg || fail "browser terminal client failed"
$DC exec -T client grep -q 'done-42' /tmp/term.out || fail "browser terminal output: $($DC exec -T client cat /tmp/term.out)"
grep -q 'done-42' /tmp/live.out || fail "live view did not stream the session: $(cat /tmp/live.out)"
$DC exec -T client grep -q '"viewers":\["carol"\]' /tmp/term.ctl || fail "alice was not told carol is watching"
$DC exec -T client grep -q 'carol is watching this session' /tmp/term.out || fail "no 'being viewed' notice in the terminal"
pass "browser SSH session; carol watched it live and alice saw the 'being viewed' banner"
sleep 1
sha=$(pc carol "$ORCH/v1/sessions" | jq "next(s['recording_sha256'] for s in d if s['id'] == '$wsid')" || true)
printf '%s' "$sha" | grep -qx '[0-9a-f]\{64\}' || fail "browser session has no recording hash: $sha"
$DC exec -T orchestrator grep -q 'done-42' "/var/lib/orbital/recordings/$wsid.cast" || fail "browser session recording lacks output"
pc carol "$ORCH/v1/audit?session=$wsid" | grep -q '"kind":"session.viewed_live"' || fail "no session.viewed_live audit event"
pass "browser session recorded ($wsid.cast) and the live view audited"

wg=$(grant "browser kill e2e") && [ -n "$wg" ] || fail "portal grant 2"
$DC exec -T -e WS_SEND='sleep 120' -e WS_SECS=60 client \
  sh -c "python3 /e2e/ws.py '/v1/terminal?grant=$wg' /tmp/jar-alice > /tmp/term2.out 2> /tmp/term2.ctl" &
bg=$!
ksid=""; for _ in $(seq 20); do
  ksid=$(pc carol $ORCH/v1/sessions | jq "$LIVE_WEB" || true)
  [ -n "$ksid" ] && break; sleep 1
done
[ -n "$ksid" ] || fail "second browser session never went live"
pc carol -f -X POST -H "x-orbital-csrf: $csrf_carol" "$ORCH/v1/sessions/$ksid/kill" >/dev/null || fail "kill from portal"
start=$(date +%s)
wait $bg || true
elapsed=$(( $(date +%s) - start ))
[ "$elapsed" -lt 15 ] || fail "killed browser session lingered ${elapsed}s"
$DC exec -T client grep -q 'killed by carol' /tmp/term2.out || fail "terminal did not show the kill reason: $($DC exec -T client cat /tmp/term2.out)"
pass "carol killed the live browser session from the portal (${elapsed}s)"

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
pass "E2E complete"
[ -n "${KEEP:-}" ] || $DC down -v >/dev/null
