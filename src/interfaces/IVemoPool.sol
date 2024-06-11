// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface IVemoPool {
    function token0() external returns (address);
    function token1() external returns (address);
    function version() external returns (address);
}
