#!/bin/sh
echo "Starting miner script"
ADDR=$(bitcoin-cli -regtest -rpcconnect=bitcoind -rpcuser=arcmint -rpcpassword=arcmintpass getnewaddress)
echo "Mining to address: $ADDR"
while true; do
  bitcoin-cli -regtest -rpcconnect=bitcoind -rpcuser=arcmint -rpcpassword=arcmintpass generatetoaddress 1 $ADDR
  sleep 10
done
