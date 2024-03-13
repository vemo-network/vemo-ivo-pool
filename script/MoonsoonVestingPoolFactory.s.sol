// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import "../src/MoonsoonVestingPoolFactory.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract MoonsoonVestingPoolFactoryScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        address proxy = Upgrades.deployUUPSProxy(
            "MoonsoonVestingPoolFactory.sol",
            abi.encodeCall(MoonsoonVestingPoolFactory.initialize, (address(0xd71ff475af81442AFe5288D45AE5E790c4828b75), "MoonsoonVestingPoolFactory", "0.1"))
        );
        vm.stopBroadcast();
    }
}
