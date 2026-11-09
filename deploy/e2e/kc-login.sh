#!/bin/sh
# Runs `orbital login` and completes the Keycloak browser flow with curl (no real browser in CI).
# usage: ORBITAL_HOME=... kc-login.sh <user> <password> [orchestrator url]
set -eu
url=${3:-https://orchestrator:8443}
log=/tmp/login-$1.log
ORBITAL_BROWSER=none orbital login "$url" --ca /ca.pem 2>"$log" &
pid=$!
login_url=""
for _ in $(seq 100); do
  login_url=$(grep -o 'https://[^ ]*cli_port=[^ ]*' "$log" || true)
  [ -n "$login_url" ] && break
  sleep 0.1
done
[ -n "$login_url" ] || { cat "$log"; exit 1; }
jar=$(mktemp)
page=$(curl -sS --cacert /ca.pem -c "$jar" -b "$jar" -L "$login_url")
action=$(printf '%s' "$page" | grep -o 'action="[^"]*"' | head -1 | sed 's/^action="//; s/"$//; s/&amp;/\&/g')
[ -n "$action" ] || { echo "no login form"; printf '%s' "$page" | head -50; exit 1; }
curl -sS --cacert /ca.pem -c "$jar" -b "$jar" -L -o /dev/null \
  --data-urlencode "username=$1" --data-urlencode "password=$2" "$action" || true
wait "$pid"
cat "$log" | tail -1
