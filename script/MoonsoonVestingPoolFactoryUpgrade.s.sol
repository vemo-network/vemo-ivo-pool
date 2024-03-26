// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import "../src/MoonsoonVestingPoolFactoryV2.sol";
import {Upgrades, Options} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract MoonsoonVestingPoolFactoryUpgradeScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        Options memory opts;
        opts.referenceContract = "MoonsoonVestingPoolFactoryV2.sol";
        Upgrades.upgradeProxy(
            0x5ef5D34bcbCefdFa6442aD7672a4147A98C08698,
            "MoonsoonVestingPoolFactoryV3.sol",
            "",
            opts
        );
        vm.stopBroadcast();
    }
}
