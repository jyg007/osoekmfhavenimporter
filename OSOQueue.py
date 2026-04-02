#!/usr/bin/env python3

import json
import sys

if len(sys.argv) != 2:
    print("Usage: ./convert.py pre|post")
    sys.exit(1)

mode = sys.argv[1]

if mode == "pre":
    input_file = "INPUTQUEUEMSGS"
elif mode == "post":
    input_file = "OUTPUTBRIDGEMSGS.bak"
else:
    print("Argument must be 'pre' or 'post'")
    sys.exit(1)

documents = []

with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:  # ignore empty lines
            documents.append(json.loads(line))

result = {
    "documents": documents,
    "count": len(documents)
}

print(json.dumps(result, indent=2))
