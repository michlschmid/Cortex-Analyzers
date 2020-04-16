#!/bin/bash
echo ""
echo "################### EXECUTING SCRIPT ###################"
python3 NSLookup_resolve.py "./fixtures"
echo ""
echo "Done."
echo ""

echo "################### GENERATED OUTPUT ###################"
cat ./fixtures/output/output.json | jq
echo ""
echo "Done."
