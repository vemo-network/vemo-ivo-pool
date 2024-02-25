// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

/**
 * CreateVestingPoolParams struct
 * @param token0                - The address of locked token inside the vault
 * @param tokenAmount           - Locked Amount
 * @param token1                - The expected token used for buying, 0x0 means native token
 * @param price                 - Price of the token0/token1
 * @param poolType              - 0: whitelist, 1: non-whitelist
 * @param flexibleAllocation    - true/false to indicate if the user can buy all
 * @param voucherData           - encoded data to create a new voucher address for this project
 * @param vestingMetadata       - metadata for vesting schedule & fee
 * @param voucherImplementation - implementation address of the voucher, used to create its token bound account
 * @param proof                 - Merkle Tree Proof of the whitelisted users
 * @param startAt               - Start time of the vault
 * @param signature             - We may not want this vault to be used not though moonsoon console
*/
    struct CreateVestingPoolParams {
        address token0;
        uint256 tokenAmount;
        address token1;
        uint256 price;
        uint256 poolType;
        bool flexibleAllocation;
        uint256 maxAllocationPerWallet;
        bytes voucherData;
        VestingMetadata vestingMetadata;
        RoyaltyInfo royaltyInfo;
        address voucherImplementation;
        bytes32[] proof;
        bytes32 root;
        uint256 startAt;
        bytes signature;
    }

/**
 * Royalty info
 * @param royaltyReceiver       - Address of the royalty receiver
 * @param royaltyRate           - Royalty Rate in bps
*/
    struct RoyaltyInfo {
        address royaltyReceiver;
        uint96 royaltyRate;
    }

/**
 * VestingMetadata struct
 * @param tokenFeeAddress       - Address of the token that fee will be collected on
 * @param feeBps                - Fee percentage on bps
 * @param feeReceiver           - Address of the fee receiver
 * @param VestingSchedule       - A list of vesting conditions that are applied to the voucher
*/
    struct VestingMetadata {
        address tokenFeeAddress;
        uint256 feeBps;
        address feeReceiver;
        VestingSchedule[] vestingSchedule;
    }

/**
 * VestingSchedule struct
 * @param option                - 0: exact, unlock all tokens at a specific time
 *                                1: linear, unlock tokens based on time & duration
 * @param ratio                 - unlock ration, applied to this batch
 * @param startTime             - time to unlock
 *                                with `exact` option, all tokens will be unlock at this time
 *                                with `linear` option, this batch of token will start to be unlocked at this time
 * @param period                - only work with `linear` option, indicates how long will this batch of token
 * @param duration              - only work with `linear` option, indicates duration between each time the token is unlocked
*/
    struct VestingSchedule {
        uint256 option;
        uint256 ratio;
        uint256 startTime;
        uint256 period;
        uint256 duration;
    }
