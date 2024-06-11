// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import "../src/VemoPoolFactory.sol";
import {Upgrades, Options} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract PoolFactoryUpgradeScript is Script {
   function setUp() public {}

   function run() public {
       uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
       address proxyAddress = vm.envAddress("POOL_FACTORY");

       vm.startBroadcast(deployerPrivateKey);
        VemoPoolFactory proxy = VemoPoolFactory(payable(proxyAddress));
        VemoPoolFactory newImplementation = new VemoPoolFactory();

        bytes memory data;
        // Upgrade the implementation
        proxy.upgradeToAndCall(address(newImplementation), data);

       vm.stopBroadcast();
   }
}
