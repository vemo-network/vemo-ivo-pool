// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPoolImplManager {
    function addImpl(address strategy) external;

    function removeImpl(address strategy) external;

    function isImplWhitelisted(address strategy) external view returns (bool);

    function viewWhitelistedImpls(uint256 cursor, uint256 size) external view returns (address[] memory, uint256);

    function viewCountWhitelistedImpls() external view returns (uint256);
}
