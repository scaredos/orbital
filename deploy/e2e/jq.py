#!/usr/bin/env python3
"""usage: ... | jq.py '<python expression over d>'  — prints the result; exits 1 if it is None/empty."""
import json, sys

r = eval(sys.argv[1], {"d": json.load(sys.stdin)})
if r in (None, "", []):
    sys.exit(1)
print(r if isinstance(r, str) else json.dumps(r))
