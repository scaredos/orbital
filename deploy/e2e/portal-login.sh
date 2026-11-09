#!/bin/sh
# Portal SSO login with curl (no browser in CI): leaves the session cookie in /tmp/jar-<user>
# and prints the session's CSRF token.
# usage: portal-login.sh <user> <password> [orchestrator url]
set -eu
url=${3:-https://orchestrator:8443}
jar=/tmp/jar-$1
rm -f "$jar"
page=$(curl -sS --cacert /ca.pem -c "$jar" -b "$jar" -L "$url/v1/auth/login")
action=$(printf '%s' "$page" | grep -o 'action="[^"]*"' | head -1 | sed 's/^action="//; s/"$//; s/&amp;/\&/g')
[ -n "$action" ] || { echo "no login form" >&2; exit 1; }
curl -sS --cacert /ca.pem -c "$jar" -b "$jar" -L -o /dev/null \
  --data-urlencode "username=$1" --data-urlencode "password=$2" "$action"
curl -sS --cacert /ca.pem -b "$jar" "$url/v1/me" | sed -n 's/.*"csrf":"\([^"]*\)".*/\1/p'
