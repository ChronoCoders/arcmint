#!/bin/sh
set -e
echo "Starting lnd-init script"

# Wait for LND to be ready
until lncli --rpcserver=lnd:10009 --network=regtest getinfo > /dev/null 2>&1; do
  echo "Waiting for LND..."
  sleep 2
done

echo "LND is ready. Generating address..."
lncli --rpcserver=lnd:10009 --network=regtest newaddress p2wkh > /lnd-init/address.txt
ADDR=$(cat /lnd-init/address.txt | grep address | cut -d'"' -f4)
echo "Generated address: $ADDR"

echo "Mining blocks to fund LND..."
# Use curl because bitcoin-cli is not available in lnd image
# Using -f to fail on HTTP errors
curl -f -s --user arcmint:arcmintpass --data-binary "{\"jsonrpc\": \"1.0\", \"id\": \"curltest\", \"method\": \"generatetoaddress\", \"params\": [101, \"$ADDR\"]}" -H 'content-type: text/plain;' http://bitcoind:18443/

sleep 3
echo "LND init complete"
