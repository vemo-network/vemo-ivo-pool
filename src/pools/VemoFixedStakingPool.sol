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
    uint256[] public _maxAllocations;
    uint256[] public _stakedAmounts;

    // Max allocation per wallet
    uint256[] public _maxAllocationPerWallets;

    uint256[] public _stakingPeriods;  // ie [1 month, 3 months, 6 months, 2 years] by seconds
    uint256[] public _rewardRates;  // ie [1e17, 2e18, 5e18, 1e18] ~ 0.1 , 2, 5, 10 per year

    mapping(uint8 => mapping(address => uint256)) private _userStaked;

    constructor(FixedStakingPool memory vestingPool, address _voucherFactory, address _operator) {
        operator = _operator;

        require(block.timestamp < vestingPool.startAt, "start time is in the past");
        require(vestingPool.startAt < vestingPool.endAt, "end time is in the past");
        require(vestingPool.principalToken != address(0), "staking native token is not supported");
        require(vestingPool.rewardToken != address(0), "staking native token is not supported");

        _stakedAmounts = new uint256[](vestingPool.maxAllocations.length);
        principalToken = vestingPool.principalToken;
        rewardToken = vestingPool.rewardToken;
        _maxAllocations = vestingPool.maxAllocations;
        _maxAllocationPerWallets = vestingPool.maxAllocationPerWallets;
        startTime = vestingPool.startAt;
        endTime = vestingPool.endAt;
        vemoVoucherFactory = IVoucherFactory(_voucherFactory);
        baseUrl = vestingPool.baseUrl;
        _rewardRates = vestingPool.rewardRates;
        _stakingPeriods = vestingPool.stakingPeriods;

    }

    modifier onlyOperator() {
        _onlyOperator();
        _;
    }

    function _onlyOperator() internal view {
        require(msg.sender == operator || msg.sender == address(this), "only operator");
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
    function staked(uint8 periodIndex, address staker) external view override returns (uint256){
        return _userStaked[periodIndex][staker];
    }


    /**
     * @notice function to stake principal token
     *          - The staker should retrieve a 2 vouchers - pVoucher contains locked token and yVoucher to claim the yield
     * @param amount the amount staker want to stake
     * @param pTokenUri the token uri used for the principal voucher.
     * @param yTokenUri the token uri used for the yield voucher.
     */
    function stake(uint256 amount, uint8 periodIndex,  string memory pTokenUri, string memory yTokenUri) external {
        require(periodIndex < _stakingPeriods.length, "FIXED_STAKING_POOL: out of range");
        require(block.timestamp <= endTime, "FIXED_STAKING_POOL: the staking pool has ended");
        require(block.timestamp >= startTime, "FIXED_STAKING_POOL: the staking pool has not started yet");
        require(amount > 0, "FIXED_STAKING_POOL: staking amount is zero");
        require(_stakedAmounts[periodIndex] + amount <= _maxAllocations[periodIndex], "FIXED_STAKING_POOL: staked amount exceeds max allocation");
        require(_userStaked[periodIndex][msg.sender] + amount <= _maxAllocationPerWallets[periodIndex], "FIXED_STAKING_POOL: staked amount exceeds max allocation");
        
        (address pVoucher, address yVoucher) = _stake(amount, periodIndex, pTokenUri, yTokenUri);

        emit Deposit(
            msg.sender,
            address(this),
            amount,
            pVoucher,
            yVoucher
        );
    }

    /**
     * @notice internal function to stake
     *          - transfer the amount of `token1` to this pool
     *          - increase the allocation info of the staker
     * @param amount the amount staker want to stake
     * @param periodIndex the lock duration index 
     */
    function _stake(uint256 amount, uint8 periodIndex, string memory pTokenUri, string memory yTokenUri) internal returns (address pVoucher, address yVoucher){
        uint256 rewardAmount = reward(amount, periodIndex);

        IERC20(principalToken).safeTransferFrom(msg.sender, address(this), amount);
        (pVoucher, yVoucher) = _createStakingVouchers(amount, rewardAmount, periodIndex, pTokenUri, yTokenUri);

        _stakedAmounts[periodIndex] = _stakedAmounts[periodIndex] + amount;
        _userStaked[periodIndex][msg.sender] = _userStaked[periodIndex][msg.sender] + amount;
    }

    /**
     * @dev calculate the reward need to pay,
     * the rewardRate is decimal 18 we have to divide to 18
     * @param amount the staking token amout in decimals
     * @param periodIndex staking period index
     */    
    function reward(uint256 amount, uint8 periodIndex) public view returns (uint256) {
        return (amount * _rewardRates[periodIndex]) * IERC20Extented(rewardToken).decimals() / 1e18 / IERC20Extented(principalToken).decimals();
    }

    /**
     * @dev lock the staking tokens and yield tokens into vouchers called pVoucher and yVoucher respectively
     * 
     * @param amount staking tokens amount
     * @param rewardAmount expected reward amount
     * @param periodIndex staking period index
     * @param ptokenUri ptokenUri
     * @param ytokenUri ytokenUri
     * @return pVoucher tba address
     * @return yVoucher tba address
     */
    function _createStakingVouchers(uint256 amount, uint256 rewardAmount, uint8 periodIndex, string memory ptokenUri, string memory ytokenUri) private returns (address, address){
        uint256 period = _stakingPeriods[periodIndex];
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

        return (pVoucher,  yVoucher);
    }

    function adjustAllocation(uint8 periodIndex, uint256 newAllo) public onlyOperator {
        require(newAllo >= _stakedAmounts[periodIndex], "FIXED_STAKING_POOL: allocation is lower than staked amount");
        uint256 currentReward = reward(_maxAllocations[periodIndex], periodIndex);
        uint256 newReward = reward(newAllo, periodIndex);

        // deposit more reward
        if (newAllo > _maxAllocations[periodIndex]) {
            IERC20(rewardToken).safeTransferFrom(
                msg.sender, address(this), newReward - currentReward
            );
        } else {
            IERC20(rewardToken).safeTransfer(
                msg.sender, currentReward - newReward
            );
        }

        _maxAllocations[periodIndex] = newAllo;

        emit UpdatePoolAllocation(periodIndex, newAllo);
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
