// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin-contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin-contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import "./interfaces/VestingPool.sol";
import {MoonsoonVestingPool} from "./MoonsoonVestingPool.sol";
import "./MoonsoonVestingPool.sol";
import "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract MoonsoonVestingPoolFactory is EIP712Upgradeable, UUPSUpgradeable {
    using SafeERC20 for IERC20;

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        //directly from EOA owner, or through the account itself (which gets redirected through execute())
        require(msg.sender == owner || msg.sender == address(this), "only owner");
    }

    /*------------------------------------------------------------------------------------------------------
    Factory metadata
    ------------------------------------------------------------------------------------------------------*/

    // Contract deployer address
    address public owner;

    // Vemo Voucher Factory
    address private _voucher;

    // Mapping from pool hash to pool address
    mapping(bytes32 => address) private _poolByHash;

    // VestingPoolCreated Event
    event VestingPoolCreated(
        address owner,
        address indexed pool,
        uint256 poolId,
        bytes32 poolHash,
        address indexed token0,
        address indexed token1,
        uint256 token0Amount,
        uint256 expectedtoken1Amount
    );

    function initialize(address anOwner, string memory name_, string memory version_) public virtual initializer {
        __EIP712_init(name_, version_);
        _initialize(anOwner);
    }

    function _initialize(address anOwner) internal virtual {
        owner = anOwner;
    }

    /**
     * @dev get the voucher address
     */
    function getVoucherAddress() public view returns (address) {
        return _voucher;
    }

    /**
     * @dev set the voucher address
     * @notice Only allow 1 voucher at a time
     */
    function setVoucherAddress(address voucherAddress) public {
        require(msg.sender == owner, "Only deployer/operator can set operator address");
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
     * - The Factory will take the `token0Amount` of `token0` from sender, and send them to the new
     *   created vesting pool
     *
     * @return vestingPool - address of the deployed vesting pool
    */
    function createVestingPool(CreateVestingPoolParams calldata params) external payable returns (address payable) {
        require(params.token0 != address(0x0), 'token0 should not be zero');
        require(params.token0Amount > params.maxAllocationPerWallet, 'token0Amount should be greater than maxAllocationPerWallet');

        bytes32 poolHash = keccak256(abi.encodePacked(params.poolId, params.token0, params.token1));
        require(_poolByHash[poolHash] == address(0), "Vesting Pool Factory: pool is already deployed.");

        // Create a new vesting pool
        MoonsoonVestingPool.VestingPool memory _pool = MoonsoonVestingPool.VestingPool(
            params.token0,
            params.token0Amount,
            params.token1,
            params.expectedToken1Amount,
            params.poolType,
            params.flexibleAllocation,
            params.maxAllocationPerWallet,
            params.royaltyRate,
            params.startAt,
            params.endAt,
            _voucher,
            params.root,
            params.schedules,
            params.fee
        );
        MoonsoonVestingPool vestingPool = new MoonsoonVestingPool(_pool, msg.sender);

        IERC20(params.token0).safeTransferFrom(
            msg.sender, address(this), params.token0Amount
        );

        IERC20(params.token0).safeTransfer(
            address(vestingPool), params.token0Amount
        );

        _poolByHash[poolHash] = address(vestingPool);

        emit VestingPoolCreated(
            msg.sender,
            address(vestingPool),
            params.poolId,
            poolHash,
            params.token0,
            params.token1,
            params.token0Amount,
            params.expectedToken1Amount
        );

        return payable(address(vestingPool));
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlyOwner();
    }
}
