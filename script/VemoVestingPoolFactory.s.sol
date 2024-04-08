// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import "../src/VemoVestingPoolFactory.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract VemoVestingPoolFactoryScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address owner = vm.envAddress("OWNER");

        vm.startBroadcast(deployerPrivateKey);
        address proxy = Upgrades.deployUUPSProxy(
            "VemoVestingPoolFactory.sol",
            abi.encodeCall(VemoVestingPoolFactory.initialize, (owner, "VemoVestingPoolFactory", "1.0"))
        );
        vm.stopBroadcast();
    }
}
