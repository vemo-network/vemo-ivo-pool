// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin-contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin-contracts/utils/math/Math.sol";
import "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin-contracts/token/ERC721/ERC721.sol";
import "@openzeppelin-contracts/token/ERC721/IERC721Receiver.sol";
import "../interfaces/IVemoFixedStakingPool.sol";
import "../interfaces/IVoucherFactory.sol";

// @title Moonsoon VestingPool
contract VemoFixedStakingPool is IERC721Receiver, IVemoFixedStakingPool {
    using SafeERC20 for IERC20;

    // Operator address
    address public operator;

    // Voucher base url
    string public baseUrl;

    // Vemo voucher
    IVoucherFactory public vemoVoucherFactory;

    // Start/end time of the pool
    uint256 public startTime;
    uint256 public endTime;
    uint256 public rewardCliffTime;

    // the staking token and reward token address
    address public principalToken;
    address public rewardToken;

    // expect total amount of token1
    uint256[] public maxAllocations;

    // Max allocation per wallet
    uint256[] public maxAllocationPerWallets;

    uint256[] public stakingPeriods;  // ie [1 month, 3 months, 6 months, 2 years] by seconds
    uint256[] public rewardRates;  // ie [1e17, 2e18, 5e18, 1e18] ~ 0.1 , 2, 5, 10 per year

    mapping(address => uint256) private _stakedAmount;

    constructor(FixedStakingPool memory vestingPool, address _voucherFactory, address _operator) {
        operator = _operator;

        require(block.timestamp < vestingPool.startAt, "start time is in the past");
        require(vestingPool.startAt < vestingPool.endAt, "end time is in the past");
        require(vestingPool.principalToken != address(0), "staking native token is not supported");
        require(vestingPool.rewardToken != address(0), "staking native token is not supported");

        principalToken = vestingPool.principalToken;
        rewardToken = vestingPool.rewardToken;
        maxAllocations = vestingPool.maxAllocations;
        maxAllocationPerWallets = vestingPool.maxAllocationPerWallets;
        startTime = vestingPool.startAt;
        endTime = vestingPool.endAt;
        vemoVoucherFactory = IVoucherFactory(_voucherFactory);
        baseUrl = vestingPool.baseUrl;
        rewardRates = vestingPool.rewardRates;
        stakingPeriods = vestingPool.stakingPeriods;

    }


    /**
     * @dev set the operator address
     * @notice Only allow 1 operator at a time
     */
    function setOperatorAddress(address _operator_address) external {
        require(msg.sender == operator, "Only operator can set operator address");
        operator = _operator_address;
    }

    /**
     * @notice public function to return the amount staked by a staker
     * @param staker address of the staker
     */
    function stakedAmount(address staker) external view override returns (uint256){
        return _stakedAmount[staker];
    }


    /**
     * @notice function to stake principal token
     *          - The staker should retrieve a 2 vouchers - pVoucher contains locked token and yVoucher to claim the yield
     * @param amount the amount staker want to stake
     * @param pTokenUri the token uri used for the principal voucher.
     * @param yTokenUri the token uri used for the yield voucher.
     */
    function stake(uint256 amount, uint8 periodIndex,  string memory pTokenUri, string memory yTokenUri) external {
        require(periodIndex < stakingPeriods.length, "FIXED_STAKING_POOL: out of range");
        require(block.timestamp <= endTime, "FIXED_STAKING_POOL: the staking pool has ended");
        require(block.timestamp >= startTime, "FIXED_STAKING_POOL: the staking pool has not started yet");
        require(amount > 0, "FIXED_STAKING_POOL: staking amount is zero");
        require(_stakedAmount[msg.sender] + amount <= maxAllocationPerWallets[periodIndex], "FIXED_STAKING_POOL: staked amount exceeds max allocation.");
        
        _stake(amount, periodIndex, pTokenUri, yTokenUri);

        emit Deposit(
            msg.sender,
            address(this),
            amount
        );
    }

    /**
     * @notice internal function to stake
     *          - transfer the amount of `token1` to this pool
     *          - increase the allocation info of the staker
     * @param amount the amount staker want to stake
     * @param periodIndex the lock duration index 
     */
    function _stake(uint256 amount, uint8 periodIndex, string memory pTokenUri, string memory yTokenUri) internal returns (uint256){
        uint256 rewardAmount = reward(amount, periodIndex);

        IERC20(principalToken).safeTransferFrom(msg.sender, address(this), amount);
        (address pVoucher, address yVoucher) = _createStakingVouchers(amount, rewardAmount, periodIndex, pTokenUri, yTokenUri);

        _stakedAmount[msg.sender] = _stakedAmount[msg.sender] + amount;

        return rewardAmount;
    }

    function reward(uint256 amount, uint8 _periodIndex) public returns (uint256) {
        return (amount * rewardRates[_periodIndex] * stakingPeriods[_periodIndex]) / (365 days);
    }

    function _createStakingVouchers(uint256 amount, uint256 rewardAmount, uint8 periodIndex, string memory ptokenUri, string memory ytokenUri) private returns (address, address){
        uint256 period = stakingPeriods[periodIndex];
        IVoucherFactory.VestingSchedule[] memory schedules = new IVoucherFactory.VestingSchedule[](1);
        IVoucherFactory.VestingFee memory voucherFee = IVoucherFactory.VestingFee(
            0,
            address(0),
            address(0),
            0,
            0
        );

        // create principal voucher
        schedules[0] = IVoucherFactory.VestingSchedule(
                amount,
                2, // linear: 1 | staged: 2
                1, // day: 1 | week: 2 | month: 3 | quarter: 4
                block.timestamp + period,
                block.timestamp + period,
                0,
                amount
        );

        IVoucherFactory.Vesting memory vesting = IVoucherFactory.Vesting(
            amount,
            schedules,
            voucherFee
        );

        string[] memory tokenUris = new string[](1);
        tokenUris[0] = string.concat(baseUrl, ptokenUri);
        
        IERC20(principalToken).approve(address(vemoVoucherFactory), amount);

        (address pVoucher, uint256 pVoucherId) = vemoVoucherFactory.createFor(principalToken, vesting, msg.sender);
        
        // create yield voucher
        schedules[0] = IVoucherFactory.VestingSchedule(
                amount,
                1, // linear: 1
                1, // day: 1 | week: 2 | month: 3 | quarter: 4
                block.timestamp + rewardCliffTime,
                block.timestamp + rewardCliffTime + period,
                0,
                amount
        );

        vesting = IVoucherFactory.Vesting(
            rewardAmount,
            schedules,
            voucherFee
        );

        tokenUris = new string[](1);
        tokenUris[0] = string.concat(baseUrl, ytokenUri);
        IERC20(rewardToken).approve(address(vemoVoucherFactory), rewardAmount);
        (address yVoucher, uint256 yVoucherId) = vemoVoucherFactory.createFor(rewardToken, vesting, msg.sender);
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

    /**
   * @dev allow the project to receive an {AssetOwnership} token
   * @return the solidity selector
   */
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }
}
