// // // SPDX-License-Identifier: UNLICENSED
// // pragma solidity ^0.8.13;

// // import {Script, console2} from "forge-std/Script.sol";
// // import "../src/VemoVestingPoolFactory.sol";
// // import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

// // contract VemoVestingPoolFactoryScript is Script {
// //     function setUp() public {}

// //     function run() public {
// //         uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
// //         address owner = vm.envAddress("OWNER");

// //         vm.startBroadcast(deployerPrivateKey);
// //         address proxy = Upgrades.upgradeProxy(
// //             "VemoVestingPoolFactory.sol",
// //             abi.encodeCall(VemoVestingPoolFactory.initialize, (owner, "VemoVestingPoolFactory", "1.0"))
// //         );
// //         vm.stopBroadcast();
// //     }
// // }



// /**
//  *  forge script script/Deploy.s.sol --rpc-url https://avalanche.drpc.org --private-key private_key  --broadcast  --verify --chain-id 43114 --ffi --etherscan-api-key 

//  */

// pragma solidity ^0.8.13;

// import "forge-std/Script.sol";
// import "../src/VemoVestingPoolFactory.sol";

// import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

// contract DeployVemoSC is Script {
  
//     function run() public {
//         vm.startBroadcast();
//         VemoVestingPoolFactory factory = new VemoVestingPoolFactory();
//         vm.stopBroadcast();
//     }
// }
