#!/bin/bash

source .env

forge script script/VemoVestingPoolFactoryUpgrade.s.sol:VemoVestingPoolFactoryUpgradeScript --ffi --sender $SENDER --rpc-url $RPC_URL --chain-id $CHAIN_ID --broadcast --verify --etherscan-api-key $ETHERSCAN_API_KEY -vvvv
