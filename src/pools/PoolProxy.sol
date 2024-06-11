// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/proxy/Proxy.sol";
import "../utils/Errors.sol";

contract PoolProxy is Proxy {
    address immutable implementation;

    constructor(address _implementation) {
        if (_implementation == address(0)) {
            revert InvalidImplementation();
        }
        implementation = _implementation;
    }

    function _implementation() internal view override returns (address) {
        return implementation;
    }

     /**
     * @dev Fallback function that delegates calls to the address returned by `_implementation()`. Will run if no other
     * function in the contract matches the call data.
     */
    fallback() external payable override virtual {
        _fallback();
    }
}
