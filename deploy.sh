#!/bin/bash

source .env

forge script script/MoonsoonVestingPoolFactory.s.sol:MoonsoonVestingPoolFactoryScript --ffi --sender 0xA36001176122B25ec20C7F2F6adC3808D381AA89 --rpc-url $RPC_URL --chain-id $CHAIN_ID --broadcast --verify --etherscan-api-key $ETHERSCAN_API_KEY -vvvv
