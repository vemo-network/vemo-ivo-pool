#!/bin/bash

source .env

forge script script/MoonsoonVestingPoolFactoryUpgrade.s.sol:MoonsoonVestingPoolFactoryUpgradeScript --ffi --sender 0xd71ff475af81442AFe5288D45AE5E790c4828b75 --rpc-url $RPC_URL --chain-id $CHAIN_ID --broadcast --verify --etherscan-api-key $ETHERSCAN_API_KEY -vvvv
