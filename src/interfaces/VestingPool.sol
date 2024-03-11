// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

import "../IVoucher.sol";

/**
 * CreateVestingPoolParams struct
 * @param token0                    - The address of locked token inside the vault
 * @param token0Amount              - Locked Amount
 * @param token1                    - The expected token used for buying, 0x0 means native token
 * @param expectedToken1Amount      - Expected Amount of token1
 * @param poolType                  - 0: whitelist, 1: non-whitelist
 * @param flexibleAllocation        - true/false to indicate if the user can buy a portion of allocation
 * @param maxAllocationPerWallet    - max allocation (bought) amount that a wallet can participate in this pool
 * @param royaltyRate               - royalty rate of the vesting voucher
 * @param vestingMetadata           - metadata for vesting schedule & fee
 * @param schedules                 - vesting schedule information
 * @param fee                       - vesting fee
 * @param voucherImplementation     - implementation address of the voucher, used to create its token bound account
 * @param root                      - Merkle Tree Root, proof of the whitelisted users (only used for the whitelist pool)
 * @param startAt                   - Start time of the vesting pool
 * @param endAt                     - End time of the vesting pool
*/
    struct CreateVestingPoolParams {
        bytes32 hashes;
        uint256 poolId;
        address token0;
        uint256 token0Amount;
        address token1;
        uint256 expectedToken1Amount;
        uint8 poolType;
        bool flexibleAllocation;
        uint256 maxAllocationPerWallet;
        uint96 royaltyRate;
        IVoucher.VestingSchedule[] schedules;
        IVoucher.VestingFee fee;
        bytes32 root;
        uint256 startAt;
        uint256 endAt;
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
