// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin-contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin-contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import "./interfaces/VestingPool.sol";
import {MoonsoonVestingPool} from "./MoonsoonVestingPool.sol";
import "./MoonsoonVestingPool.sol";
import "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

contract MoonsoonVestingPoolFactory is EIP712 {
    using SafeERC20 for IERC20;

    /*------------------------------------------------------------------------------------------------------
    Factory metadata
    ------------------------------------------------------------------------------------------------------*/

    // Contract deployer address
    address private immutable _deployer;

    // Operator address
    address private _operator;

    // Vemo Voucher Factory
    address private _voucher;

    // Mapping from pool hash to pool address
    mapping(bytes32 => address) private _poolByHash;

    constructor(string memory name_, string memory version_) EIP712(name_, version_) {
        _deployer = msg.sender;
        _operator = _deployer;
    }

    /**
     * @dev set the operator address
     * @notice Only allow 1 operator at a time
     */
    function setOperatorAddress(address _operator_address) public {
        require(msg.sender == _deployer || msg.sender == _operator, "Only deployer/operator can set voucher factory address");
        _operator = _operator_address;
    }

    /**
     * @dev set the voucher factory address
     * @notice Only allow 1 voucher factory at a time
     */
    function setVoucherAddress(address voucherAddress) public {
        require(msg.sender == _deployer || msg.sender == _operator, "Only deployer/operator can set operator address");
        _voucher = voucherAddress;
    }

    /**
   * @dev return the pools by their hashes
   * @param hash - bytes32 hash of (poolId,token0,token1)
   */
    function getPoolByHash(bytes32 hash) external view returns (address) {
        return _poolByHash[hash];
    }

    /**
     * @dev publish a vesting pool
     * @param params - see {CreateVestingPoolParams}
     * @notice The function first validate the signature of the whole params, which should be signed
     * using the moonsoon operator address.
     *
     * - A new {Voucher} is deployed by sending `voucherData` params to {VoucherFactory} address
     * - {MoonsoonVestingPool.VestingPool} from `params` will be sent to {MoonsoonVestingPool}
     *   to create a new MoonsoonVestingPool
     * - The Factory will take the `tokenAmount` of `token0` from sender, and send them to the new
     *   created vesting pool
     *
     * @return vestingPool - address of the deployed vesting pool
    */
    function createVestingPool(CreateVestingPoolParams calldata params) external payable returns (address payable) {
        require(params.token0 != address(0x0), 'token0 should not be zero');

        bytes32 poolHash = keccak256(abi.encodePacked(params.poolId, params.token0, params.token1));
        require(_poolByHash[poolHash] == address(0), "Vesting Pool Factory: pool is already deployed.");

        // Create a new vesting pool
        MoonsoonVestingPool.VestingPool memory _pool = MoonsoonVestingPool.VestingPool(
            params.token0,
            params.tokenAmount,
            params.token1,
            params.price,
            params.poolType,
            params.flexibleAllocation,
            params.maxAllocationPerWallet,
            params.startAt,
            _voucher,
            params.root,
            params.schedules,
            params.fee
        );
        MoonsoonVestingPool vestingPool = new MoonsoonVestingPool(_pool, msg.sender);

        IERC20(params.token0).safeTransferFrom(
            msg.sender, address(this), params.tokenAmount
        );

        IERC20(params.token0).safeTransfer(
            address(vestingPool), params.tokenAmount
        );

        _poolByHash[poolHash] = address(vestingPool);

        return payable(address(vestingPool));
    }
}
