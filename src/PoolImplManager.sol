// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IPoolImplManager} from "./interfaces/IPoolImplManager.sol";

/**
 * @notice It allows adding/removing pool implementations to use in PoolFactory.
 */
contract PoolImplManager is
    IPoolImplManager,
    UUPSUpgradeable,
    OwnableUpgradeable
{
    using EnumerableSet for EnumerableSet.AddressSet;

    EnumerableSet.AddressSet private _whitelistedImpls;

    event ImplRemoved(address indexed implementation);
    event ImplWhitelisted(address indexed implementation);

    function initialize(address owner) public initializer {
        __Ownable_init(owner);
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address newImplementation) internal override {}

    /**
     * @notice Add an execution implementation in the system
     * @param implementation address of the implementation to add
     */
    function addImpl(address implementation)
        external
        override
        onlyOwner
    {
        require(
            !_whitelistedImpls.contains(implementation),
            "Impl: Already whitelisted"
        );
        _whitelistedImpls.add(implementation);

        emit ImplWhitelisted(implementation);
    }

    /**
     * @notice Remove an execution implementation from the system
     * @param implementation address of the implementation to remove
     */
    function removeImpl(address implementation)
        external
        override
        onlyOwner
    {
        require(
            _whitelistedImpls.contains(implementation),
            "Impl: Not whitelisted"
        );
        _whitelistedImpls.remove(implementation);

        emit ImplRemoved(implementation);
    }

    /**
     * @notice Returns if an execution implementation is in the system
     * @param implementation address of the implementation
     */
    function isImplWhitelisted(address implementation)
        external
        view
        override
        returns (bool)
    {
        return _whitelistedImpls.contains(implementation);
    }

    /**
     * @notice View number of whitelisted strategies
     */
    function viewCountWhitelistedImpls()
        external
        view
        override
        returns (uint256)
    {
        return _whitelistedImpls.length();
    }

    /**
     * @notice See whitelisted strategies in the system
     * @param cursor cursor (should start at 0 for first request)
     * @param size size of the response (e.g., 50)
     */
    function viewWhitelistedImpls(uint256 cursor, uint256 size)
        external
        view
        override
        returns (address[] memory, uint256)
    {
        uint256 length = size;

        if (length > _whitelistedImpls.length() - cursor) {
            length = _whitelistedImpls.length() - cursor;
        }

        address[] memory whitelistedImpls = new address[](length);

        for (uint256 i = 0; i < length; i++) {
            whitelistedImpls[i] = _whitelistedImpls.at(cursor + i);
        }

        return (whitelistedImpls, cursor + length);
    }
}
