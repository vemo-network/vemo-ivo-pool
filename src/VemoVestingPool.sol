// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin-contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin-contracts/utils/math/Math.sol";
import "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin-contracts/token/ERC721/ERC721.sol";
import "@openzeppelin-contracts/token/ERC721/IERC721Receiver.sol";
import "./interfaces/VestingPool.sol";
import "./IVoucher.sol";

// @title Moonsoon VestingPool
contract VemoVestingPool is IERC721Receiver {
    using SafeERC20 for IERC20;

    using MerkleProof for bytes32[];
    /*------------------------------------------------------------------------------------------------------
    Contract metadata
    ------------------------------------------------------------------------------------------------------*/

    // VestingPoolCreated Event
    event TokenBought(
        address indexed buyer,
        address indexed pool,
        address indexed token0,
        address token1,
        uint256 token0amount,
        uint256 token1Amount
    );

    // Operator address
    address private _operator;

    // Voucher base url
    string private _baseUrl;

    // Mapping address to bought Amount;
    mapping(address => uint256) private _boughtAmount;

    // Address of the voucher which will be issued by this pool
    address private _voucherAddress;

    // Vemo voucher
    IVoucher private _vemoVoucher;

    // Start/end time of the pool
    uint256 private _startTime;
    uint256 private _endTime;

    // Address of the token locked inside this pool
    address private _token0;
    uint256 private _token0Amount;

    // Address of the token used to buy from this vesting pool
    address private _token1;

    // expect total amount of token1
    uint256 private _expectedToken1Amount;

    // Type of this vesting pool
    uint256 private _poolType;
    uint256 private constant POOL_TYPE_WHITELIST = 0;
    uint256 private constant POOL_TYPE_NON_WHITELIST = 1;

    // If this pool allows flexible allocation
    bool private _flexibleAllocation;

    // Max allocation per wallet
    uint256 private _maxAllocationPerWallet;

    // Royalty rate for voucher created from this vesting pool
    uint96 private _royaltyRate;

    // Vesting Metadata
    IVoucher.VestingSchedule[] private _vestingSchedules;
    IVoucher.VestingFee private _fee;

    // root
    bytes32 private _root;

    // VestingPool initial params
    struct VestingPool {
        address token0;
        uint256 token0Amount;
        address token1;
        uint256 expectedToken1Amount;
        uint8 poolType;
        bool flexibleAllocation;
        uint256 maxAllocationPerWallet;
        uint96 royaltyRate;
        uint256 startAt;
        uint256 endAt;
        address voucherAddress;
        string baseUrl;
        bytes32 root;
        IVoucher.VestingSchedule[] schedules;
        IVoucher.VestingFee fee;
    }

    constructor(VestingPool memory vestingPool, address operator) {
        _operator = operator;

        require(block.timestamp < vestingPool.startAt, "start time is in the pass");
        require(vestingPool.royaltyRate <= 10000, "royalty rate is too high");

        _token0 = vestingPool.token0;
        _token0Amount = vestingPool.token0Amount;
        _token1 = vestingPool.token1;
        _expectedToken1Amount = vestingPool.expectedToken1Amount;
        _poolType = vestingPool.poolType;
        _flexibleAllocation = vestingPool.flexibleAllocation;
        _maxAllocationPerWallet = vestingPool.maxAllocationPerWallet;
        _royaltyRate = vestingPool.royaltyRate;
        _startTime = vestingPool.startAt;
        _endTime = vestingPool.endAt;
        _voucherAddress = vestingPool.voucherAddress;
        _vemoVoucher = IVoucher(_voucherAddress);
        _root = vestingPool.root;
        _fee = vestingPool.fee;
        _baseUrl = vestingPool.baseUrl;

        uint256 scheduleLength = vestingPool.schedules.length;
        for (uint8 i = 0; i < scheduleLength; i++) {
            IVoucher.VestingSchedule memory vestingSchedule = vestingPool.schedules[i];

            _vestingSchedules.push(vestingSchedule);
        }

    }

    /**
     * @dev allow operator to claim the funds of this vesting pool
     * @param token address of the token to claim fund from
     */
    function claim(address token) external {
        require(msg.sender == _operator, "only operator can claim the funds");

        _doTransferERC20(token, address(this), msg.sender, _getBalance(token, address(this)));
    }

    /**
     * @dev allow operator to update the root of the merkle tree
     * @param root the new root
     */
    function setRoot(bytes32 root) public {
        require(msg.sender == _operator, "only operator can claim the funds");

        _root = root;
    }

    /**
     * @dev return the current root of the merkle tree
     */
    function getRoot(bytes32 root) public returns (bytes32) {
        return _root;
    }

    /**
     * @dev set the operator address
     * @notice Only allow 1 operator at a time
     */
    function setOperatorAddress(address _operator_address) external {
        require(msg.sender == _operator, "Only operator can set operator address");
        _operator = _operator_address;
    }

    /**
     * @dev get voucher address
     */
    function getVoucherAddress() external view returns (address) {
        return _voucherAddress;
    }

    /**
     * @dev get start time of this vesting pool
     */
    function startTime() external view returns (uint256) {
        return _startTime;
    }

    /**
     * @dev get end time of this vesting pool
     */
    function endTime() external view returns (uint256) {
        return _endTime;
    }

    /**
     * @dev get voucher's base url of this vesting pool
     */
    function baseUrl() external view returns (string memory) {
        return _baseUrl;
    }

    /**
     * @notice public function to return the amount bought by a buyer
     * @param buyer address of the buyer
     */
    function boughtAmount(address buyer) external view returns (uint256){
        return _boughtAmount[buyer];
    }

    /**
     * @dev get max allocation per wallet
     */
    function maxAllocationPerWallet() external view returns (uint256) {
        return _maxAllocationPerWallet;
    }

    /**
     * @dev get pool type
     */
    function poolType() external view returns (uint256) {
        return _poolType;
    }

    /**
     * @dev get royalty rate
     */
    function royaltyRate() external view returns (uint96) {
        return _royaltyRate;
    }

    /**
     * @dev get vesting schedule
     */
    function vestingSchedules() external view returns (IVoucher.VestingSchedule[] memory) {
        return _vestingSchedules;
    }

    /**
     * @dev get vesting fee
     */
    function vestingFee() external view returns (IVoucher.VestingFee memory) {
        return _fee;
    }

    /**
     * @dev is flexible allocation pool
     */
    function isFlexibleAllocationPool() external view returns (bool) {
        return _flexibleAllocation;
    }

    /**
     * @dev check if buyer is whitelisted
     */
    function isWhitelist(address buyer, uint256 allocation, bytes32[] memory proof) external view returns (bool) {
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(buyer, allocation))));
        return MerkleProof.verify(proof, _root, leaf);
    }

    /**
     * @notice function to buy in a whitelist pool
     *          - The buyer should retrieve a voucher which contains locked token
     * @param amount the amount buyer want to buy
     * @param allocation the allocation to the buyer
     * @param proof the proof that buyer is allowed to buy that allocation, verified by merkle proof
     * @param tokenUri the token uri used for the voucher created.
     */
    function buyWhitelist(uint256 amount, uint256 allocation, bytes32[] memory proof, string memory tokenUri) external payable {
        require(block.timestamp <= _endTime, "the vesting pool has ended");
        require(block.timestamp >= _startTime, "the vesting pool has not started yet");
        require(_boughtAmount[msg.sender] + amount <= allocation, "bought amount exceeds allocation for this wallet");
        require(_poolType == POOL_TYPE_WHITELIST, "pool type is not whitelist, use buy instead");
        require(msg.value >= (_isNative(_token1) ? token1Amount(amount) : 0), 'Invalid msg.value');

        if (!_flexibleAllocation) {
            require(amount == allocation, "must buy all allocation because _flexibleAllocation == false");
        }

        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(msg.sender, allocation))));
        require(MerkleProof.verify(proof, _root, leaf), "wrong proof of whitelist data");

        uint256 _token1Amount = _buy(amount);
        _createVoucher(amount, _token1Amount, tokenUri);

        emit TokenBought(
            msg.sender,
            address(this),
            _token0,
            _token1,
            amount,
            _token1Amount
        );
    }

    /**
     * @notice function to buy in a non whitelist pool
     *          - The buyer should retrieve a voucher which contains locked token
     * @param amount the amount buyer want to buy
     * @param tokenUri the token uri used for the voucher created.
     */
    function buy(uint256 amount, string memory tokenUri) external payable {
        require(block.timestamp <= _endTime, "the vesting pool has ended");
        require(block.timestamp >= _startTime, "the vesting pool has not started yet");
        require(_boughtAmount[msg.sender] + amount <= _maxAllocationPerWallet, "bought amount exceeds max allocation.");
        require(_poolType == POOL_TYPE_NON_WHITELIST, "pool type is not non-whitelist, use buyWhitelist instead");
        require(msg.value >= (_isNative(_token1) ? token1Amount(amount) : 0), 'Invalid msg.value');

        if (!_flexibleAllocation) {
            require(amount == _maxAllocationPerWallet, "must buy all allocation because _flexibleAllocation == false");
        }

        uint256 _token1Amount = _buy(amount);
        _createVoucher(amount, _token1Amount, tokenUri);

        emit TokenBought(
            msg.sender,
            address(this),
            _token0,
            _token1,
            amount,
            _token1Amount
        );

        uint256 balance = _getBalance(_token1, address(this));
    }

    /**
     * @notice internal function to buy
     *          - transfer the amount of `token1` to this pool
     *          - increase the allocation info of the buyer
     * @param amount the amount buyer want to buy
     */
    function _buy(uint256 amount) internal returns (uint256){
        uint256 _token1Amount = token1Amount(amount);

        _doTransferERC20(_token1, msg.sender, address(this), _token1Amount);

        _boughtAmount[msg.sender] = _boughtAmount[msg.sender] + amount;

        return _token1Amount;
    }

    /**
     * @notice internal function to create a Vemo voucher
     *          - calculate vesting schedule
     *          - call to _vemoVoucher.createVoucher to create Vemo voucher
     * @param amount the amount buyer want to buy
     * @param amountToken1 the amount buyer needs to pay
     */
    function _createVoucher(uint256 amount, uint256 amountToken1, string memory tokenUri) private {
        uint256 feeAmount = Math.mulDiv(amount, _fee.totalFee, _token0Amount, Math.Rounding.Floor);

        IVoucher.VestingFee memory voucherFee = IVoucher.VestingFee(
            _fee.isFee,
            _fee.feeTokenAddress,
            _fee.receiverAddress,
            feeAmount,
            0
        );

        IVoucher.VestingSchedule[] memory schedules = new IVoucher.VestingSchedule[](_vestingSchedules.length);

        uint256 scheduleLength = _vestingSchedules.length;
        for (uint8 i = 0; i < scheduleLength; i++) {
            uint256 vestingAmount = Math.mulDiv(amount, _vestingSchedules[i].amount, _token0Amount, Math.Rounding.Floor);
            IVoucher.VestingSchedule memory schedule = IVoucher.VestingSchedule(
                vestingAmount,
                _vestingSchedules[i].vestingType,
                _vestingSchedules[i].linearType,
                _vestingSchedules[i].startTimestamp,
                _vestingSchedules[i].endTimestamp,
                _vestingSchedules[i].isVested,
                vestingAmount
            );

            schedules[i] = schedule;
        }

        IVoucher.Vesting memory params = IVoucher.Vesting(
            amount,
            schedules,
            voucherFee
        );

        string[] memory tokenUris = new string[](1);
        tokenUris[0] = string.concat(_baseUrl, tokenUri);
        IVoucher.BatchVesting memory batchVesting = IVoucher.BatchVesting(
            params,
            1,
            tokenUris
        );

        IERC20(_token0).approve(address(_vemoVoucher), amount);
        (address voucher, uint256 startId, uint256 endId) = _vemoVoucher.createBatch(_token0, batchVesting, _royaltyRate);

        for (uint256 i = startId; i <= endId; i++)
            ERC721(voucher).transferFrom(address(this), msg.sender, i);
    }

    /**
     * @notice public function to calculate amount of `token1` used to buy
     *         - it's public for testing purpose
     * @param amount an uint256 amount of `token0` that buyer wants to buy
     */
    function token1Amount(uint256 amount) public view returns (uint256){
        return _expectedToken1Amount == 0 ? 0 : Math.mulDiv(_expectedToken1Amount, amount, _token0Amount, Math.Rounding.Floor);
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
