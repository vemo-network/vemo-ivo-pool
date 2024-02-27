// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import "../src/MoonsoonVestingPoolFactory.sol";

contract MoonsoonVestingPoolFactoryScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        MoonsoonVestingPoolFactory factory = new MoonsoonVestingPoolFactory("MoonsoonVestingPool", "0.1");
        vm.stopBroadcast();
    }
}
