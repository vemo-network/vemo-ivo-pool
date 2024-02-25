// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin-contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin-contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin-contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import "@openzeppelin-contracts/token/ERC20/ERC20.sol";
import "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import "vemo-data-registry/interfaces/IVemoVoucher.sol";
import "./interfaces/VestingPool.sol";

// @title Moonsoon VestingPool
contract MoonsoonVestingPool {
    using SafeERC20 for IERC20;

    using MerkleProof for bytes32[];
    /*------------------------------------------------------------------------------------------------------
    Contract metadata
    ------------------------------------------------------------------------------------------------------*/

    // Operator address
    address private _operator;

    // Mapping address to bought Amount;
    mapping(address => uint256) private _boughtAmount;

    // Address of the voucher which will be issued by this pool
    address private _voucherAddress;

    // Address of the voucher implementation
    address private _voucherImplementationAddress;

    // Vemo voucher
    IVemoVoucher private _vemoVoucher;

    // Start time of the pool
    uint256 private _startTime;

    // Address of the token locked inside this pool
    address private _token0;

    // Address of the token used to buy from this vesting pool
    address private _token1;

    // price of the token0 to token1
    uint256 private _price;

    // Type of this vesting pool
    uint256 private _poolType;
    uint256 private constant POOL_TYPE_WHITELIST = 0;
    uint256 private constant POOL_TYPE_NON_WHITELIST = 1;

    // If this pool allows flexible allocation
    bool private _flexibleAllocation;

    // Max allocation per wallet
    uint256 private _maxAllocationPerWallet;

    // Vesting Metadata
    VestingMetadata private _vestingMetadata;

    // Vesting Metadata
    RoyaltyInfo private _royaltyInfo;

    // proof
    bytes32[] private _proof;

    // root
    bytes32 private _root;

    uint256[] private _vestingUnlockTimestamps;
    uint256[] private _vestingUnlockAmounts;

    function vestingUnlockTimestamps() public view returns (uint256[] memory) {
        return _vestingUnlockTimestamps;
    }

    function vestingUnlockAmounts() public view returns (uint256[] memory) {
        return _vestingUnlockAmounts;
    }

    // VestingPool initial params
    struct VestingPool {
        address token0;
        uint256 tokenAmount;
        address token1;
        uint256 price;
        uint256 poolType;
        bool flexibleAllocation;
        uint256 maxAllocationPerWallet;
        uint256 startAt;
        address voucherAddress;
        address voucherImplementationAddress;
        bytes32[] proof;
        bytes32 root;
        VestingMetadata vestingMetadata;
        RoyaltyInfo royaltyInfo;
    }

    constructor(VestingPool memory vestingPool, address operator) {
        _operator = operator;

        require(block.timestamp < vestingPool.startAt, "start time is in the pass");

        _token0 = vestingPool.token0;
        _token1 = vestingPool.token1;
        _price = vestingPool.price;
        _poolType = vestingPool.poolType;
        _flexibleAllocation = vestingPool.flexibleAllocation;
        _maxAllocationPerWallet = vestingPool.maxAllocationPerWallet;
        _startTime = vestingPool.startAt;
        _voucherAddress = vestingPool.voucherAddress;
        _voucherImplementationAddress = vestingPool.voucherImplementationAddress;
        _vemoVoucher = IVemoVoucher(_voucherAddress);
        _royaltyInfo = vestingPool.royaltyInfo;
        _proof = vestingPool.proof;
        _root = vestingPool.root;
        _vestingMetadata.feeBps = vestingPool.vestingMetadata.feeBps;
        _vestingMetadata.tokenFeeAddress = vestingPool.vestingMetadata.tokenFeeAddress;
        _vestingMetadata.feeReceiver = vestingPool.vestingMetadata.feeReceiver;
        for (uint8 i = 0; i < vestingPool.vestingMetadata.vestingSchedule.length; i++) {
            VestingSchedule memory vestingSchedule = vestingPool.vestingMetadata.vestingSchedule[i];

            _vestingMetadata.vestingSchedule.push(VestingSchedule(
                vestingSchedule.option,
                vestingSchedule.ratio,
                vestingSchedule.startTime,
                vestingSchedule.period,
                vestingSchedule.duration
            ));
        }
    }

    /**
     * @dev allow operator to claim the funds of this vesting pool
     * @param token address of the token to claim fund from
     */
    function claim(address token) public {
        require(msg.sender == _operator, "only operator can claim the funds");

        _doTransferERC20(token, address(this), msg.sender, _getBalance(token, address(this)));
    }

    /**
     * @dev set the operator address
     * @notice Only allow 1 operator at a time
     */
    function setOperatorAddress(address _operator_address) public {
        require(msg.sender == _operator, "Only operator can set operator address");
        _operator = _operator_address;
    }

    bytes32 public constant REMITTANCE_HASH = keccak256(
        "Remittance(string credentialType,string credential,address sender,uint256 amount,address token,uint256 expiredAt,uint256 salt,bytes signature)"
    );

    bytes32 public constant CLAIM_REQUEST_HASH = keccak256(
        'ClaimRequest(bytes32[] remittances,address receiver,uint256 expiredAt)'
    );

    /**
     * @notice function to buy in a whitelist pool
     *          - The buyer should retrieve a voucher which contains locked token
     * @param amount the amount buyer want to buy
     * @param allocation the allocation to the buyer
     * @param leaf the proof that buyer is allowed to buy that allocation, verified by merkle proof
     */
    function buyWhitelist(uint256 amount, uint256 allocation, bytes32 leaf) external payable {
        require(_boughtAmount[msg.sender] + amount <= allocation, "bought amount exceeds allocation for this wallet");
        require(_poolType == POOL_TYPE_WHITELIST, "pool type is not whitelist, use buy instead");
        require(_proof.verify(_root, leaf), "wrong proof of whitelist data");

        _buy(amount);
        _createVoucher(amount);
    }

    /**
     * @notice function to buy in a non whitelist pool
     *          - The buyer should retrieve a voucher which contains locked token
     * @param amount the amount buyer want to buy
     */
    function buy(uint256 amount) external payable {
        require(_boughtAmount[msg.sender] + amount <= _maxAllocationPerWallet, "bought amount exceeds max allocation.");
        require(_poolType == POOL_TYPE_NON_WHITELIST, "pool type is not non-whitelist, use buyWhitelist instead");

        _buy(amount);
        _createVoucher(amount);
    }

    /**
     * @notice internal function to buy
     *          - transfer the amount of `token1` to this pool
     *          - increase the allocation info of the buyer
     * @param amount the amount buyer want to buy
     */
    function _buy(uint256 amount) internal {
        uint256 _token1Amount = token1Amount(amount);

        _doTransferERC20(_token1, msg.sender, address(this), _token1Amount);

        _boughtAmount[msg.sender] = _boughtAmount[msg.sender] + amount;
    }

    /**
     * @notice internal function to create a Vemo voucher
     *          - calculate vesting schedule
     *          - call to _vemoVoucher.createVoucher to create Vemo voucher
     * @param amount the amount buyer want to buy
     */
    function _createVoucher(uint256 amount) private {
        calculateVestingData(amount);
        IVemoVoucher.Balance memory balance = IVemoVoucher.Balance(
            _token0,
            amount
        );
        IVemoVoucher.VestingSchedule memory schedule = IVemoVoucher.VestingSchedule(
            _vestingUnlockTimestamps,
            _vestingUnlockAmounts
        );
        IVemoVoucher.RedemptionFee memory redemptionFee = IVemoVoucher.RedemptionFee(
            _vestingMetadata.feeReceiver,
            _vestingMetadata.tokenFeeAddress,
            _vestingMetadata.feeBps
        );
        IVemoVoucher.RoyaltyInfo memory royaltyInfo = IVemoVoucher.RoyaltyInfo(
            _royaltyInfo.royaltyReceiver,
            _royaltyInfo.royaltyRate
        );

        IVemoVoucher.CreateVoucherParams memory params = IVemoVoucher.CreateVoucherParams(
            msg.sender,
            balance,
            schedule,
            redemptionFee,
            royaltyInfo
        );
        _vemoVoucher.create(params);

        delete _vestingUnlockTimestamps;
        delete _vestingUnlockAmounts;
    }

    /**
     * @notice internal function to calculate vesting schedule
     *          - support calculate `_vestingUnlockTimestamps` & `_vestingUnlockAmounts`
     *            for the input amount & vesting schedule of the pool
     * @param amount an uint256 amount to indicates the vesting voucher's total amount
     */
    function calculateVestingData(uint256 amount) public {
        uint256 totalRatio = 0;
        uint256 totalRatioAmount = 0;
        for (uint8 i = 0; i < _vestingMetadata.vestingSchedule.length; i++) {
            VestingSchedule memory vestingSchedule = _vestingMetadata.vestingSchedule[i];
            totalRatio += vestingSchedule.ratio;

            if (vestingSchedule.option == 0) {
                _vestingUnlockTimestamps.push(vestingSchedule.startTime);
                if (i == _vestingMetadata.vestingSchedule.length - 1) {
                    _vestingUnlockAmounts.push(amount - totalRatioAmount);
                    totalRatioAmount = amount;
                } else {
                    _vestingUnlockAmounts.push(amount * vestingSchedule.ratio / 10000);
                    totalRatioAmount += amount * vestingSchedule.ratio / 10000;
                }
            } else {
                uint256 count = 0;
                uint256 start = vestingSchedule.startTime;
                uint256 ratioAmount = amount * vestingSchedule.ratio / 10000;
                if (i == _vestingMetadata.vestingSchedule.length - 1) {
                    ratioAmount = amount - totalRatioAmount;
                }

                while (start <= vestingSchedule.startTime + vestingSchedule.period) {
                    _vestingUnlockTimestamps.push(start);
                    start += vestingSchedule.duration;
                    count++;
                }

                uint256 totalAmount = 0;
                for (uint8 j = 0; j < count; j++) {
                    if (j < count - 1) {
                        _vestingUnlockAmounts.push(ratioAmount / count);
                        totalAmount += ratioAmount / count;
                    } else {
                        require(totalAmount < ratioAmount, "wrong linear vesting data");
                        _vestingUnlockAmounts.push(ratioAmount - totalAmount);
                    }
                }

                require(_vestingUnlockAmounts.length == _vestingUnlockTimestamps.length, "_vestingUnlockAmounts and _vestingUnlockTimestamps must have the same length");

                totalRatioAmount += ratioAmount;
            }
        }

        require(totalRatio == 10000, "total unlock ratio greater/less than 100%");
        require(totalRatioAmount == amount, "total amount bought is wrong calculated");
    }

    /**
     * @notice public function to calculate amount of `token1` used to buy
     *         - it's public for testing purpose
     * @param amount an uint256 amount of `token0` that buyer wants to buy
     */
    function token1Amount(uint256 amount) public returns (uint256){
        if (_isNative(_token1)) {
            uint256 _token1Amount = _price * (10 ** 18) * (amount / (10 ** ERC20(_token0).decimals()));
            return _token1Amount;
        } else {
            uint256 _token1Amount = _price * (10 ** ERC20(_token1).decimals()) * (amount / (10 ** ERC20(_token0).decimals()));
            return _token1Amount;
        }
    }

    /**
     * @notice get balance of an ERC20 token for the address `account`
     *         - if the token address = 0x0 -> query native balance
     *         - else use `balanceOf` function
     * @param token address of the token
     * @param account address of the account
     */
    function _getBalance(address token, address account) internal view returns (uint256) {
        if (_isNative(token)) {
            return account.balance;
        } else {
            return IERC20(token).balanceOf(account);
        }
    }

    /**
     * @notice determine if an address is a native token (0x0)
     * @param token address of the token
     */
    function _isNative(address token) internal pure returns (bool) {
        return (token == address(0));
    }

    /**
     * @notice transfer ERC20 token from an address to another, including native if the `token` address is 0x0
     * @param token address of the token
     * @param from address of the sender
     * @param to address of the receiver
     * @param amount amount to be sent
     */
    function _doTransferERC20(
        address token,
        address from,
        address to,
        uint256 amount
    ) internal {
        require(from != to, 'sender != recipient');
        if (amount > 0) {
            if (_isNative(token)) {
                if (from == address(this)) _safeTransferNative(to, amount);
            } else {
                if (from == address(this)) {
                    IERC20(token).safeTransfer(
                        to, amount
                    );
                } else {
                    IERC20(token).safeTransferFrom(
                        from, to, amount
                    );

                }
            }
        }
    }

    /**
     * @notice safely transfer native token from this address
     * @param to address of the receiver
     * @param value amount to be sent
     */
    function _safeTransferNative(address to, uint256 value) internal {
        if (value == 0) return;
        (bool success,) = to.call{value: value}(new bytes(0));
        require(success, 'TransferHelper: ETH_TRANSFER_FAILED');
    }

    receive() external payable {}
}
