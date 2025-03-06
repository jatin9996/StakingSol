// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

contract Vesting {
        
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title SingleTokenVesting
 * @notice A contract allowing anyone to create vesting schedules for themselves with a globally set token
 */
contract SingleTokenVesting is ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    struct VestingSchedule {
        uint256 totalAllocation; // Total amount to vest
        uint256 claimedAmount;   // How much has been claimed
        uint256 startTime;       // When vesting began
        uint256[] depositTimes;  // Times of token deposits
        uint256[] depositAmounts; // Amounts of each deposit
    }

    // Global token for all vestings
    IERC20 public token;

    // Vesting parameters
    uint256 public constant DURATION = 360 days;
    uint256 public constant PERIOD = 30 days;
    uint256 public constant TOTAL_PERIODS = DURATION / PERIOD;

    // Mapping from user to vesting details
    mapping(address => VestingSchedule) public vestingSchedules;

    // Events
    event TokenSet(address indexed token);
    event VestingCreated(address indexed user, uint256 amount, uint256 startTime);
    event VestingIncreased(address indexed user, uint256 additionalAmount);
    event TokensClaimed(address indexed user, uint256 amount);
    event VestingBatchCreated(address[] users, uint256[] amounts);

    /**
     * @notice Initializes the contract with the deployer as the owner
     */
    constructor() Ownable(msg.sender) {}

    /**
     * @notice Sets the token used for all vestings
     * @param _token The ERC20 token address
     */
    function setToken(IERC20 _token) external onlyOwner {
        require(address(_token) != address(0), "Token cannot be zero address");
        token = _token;
        emit TokenSet(address(_token));
    }

    /**
     * @notice Creates or increases a vesting schedule
     * @param _amount Total amount to vest
     */
    function createOrIncreaseVesting(uint256 _amount) external nonReentrant {
        require(address(token) != address(0), "Token not set");
        require(_amount > 0, "Amount must be positive");

        VestingSchedule storage schedule = vestingSchedules[msg.sender];

        if (schedule.totalAllocation == 0) {
            // First vesting schedule
            schedule.startTime = block.timestamp;
            schedule.totalAllocation = _amount;
            schedule.depositTimes.push(block.timestamp);
            schedule.depositAmounts.push(_amount);
            emit VestingCreated(msg.sender, _amount, block.timestamp);
        } else {
            // Increase existing vesting
            schedule.totalAllocation += _amount;
            schedule.depositTimes.push(block.timestamp);
            schedule.depositAmounts.push(_amount);
            emit VestingIncreased(msg.sender, _amount);
        }

        // Transfer tokens from creator to contract
        token.safeTransferFrom(msg.sender, address(this), _amount);
    }

    /**
     * @notice Claims vested tokens
     */
    function claim() external nonReentrant {
        VestingSchedule storage schedule = vestingSchedules[msg.sender];
        require(schedule.totalAllocation > 0, "No vesting schedule found");

        uint256 vested = vestedAmount(msg.sender);
        uint256 claimable = vested - schedule.claimedAmount;
        require(claimable > 0, "Nothing to claim");

        schedule.claimedAmount += claimable;
        token.safeTransfer(msg.sender, claimable);

        emit TokensClaimed(msg.sender, claimable);
    }

    /**
     * @notice Calculates vested amount for a user
     * @param _user The user address
     * @return The vested amount
     */
    function vestedAmount(address _user) public view returns (uint256) {
        VestingSchedule memory schedule = vestingSchedules[_user];
        if (schedule.totalAllocation == 0) {
            return 0;
        }

        uint256 elapsedTime = block.timestamp - schedule.startTime;
        uint256 periodsPassed = elapsedTime / PERIOD;

        if (periodsPassed >= TOTAL_PERIODS) {
            return schedule.totalAllocation;
        }

        return (schedule.totalAllocation * periodsPassed) / TOTAL_PERIODS;
    }

    /**
     * @notice Returns claimable amount for a user
     * @param _user The user address
     * @return The claimable amount
     */
    function claimableAmount(address _user) external view returns (uint256) {
        VestingSchedule storage schedule = vestingSchedules[_user];
        if (schedule.totalAllocation == 0) {
            return 0;
        }
        uint256 vested = vestedAmount(_user);
        return vested - schedule.claimedAmount;
    }

    function batchCreateVesting(
    address[] calldata users, 
    uint256[] calldata amounts
) external onlyOwner nonReentrant {
    require(address(token) != address(0), "Token not set");
    require(users.length == amounts.length, "Array length mismatch");
    
    uint256 totalAmount;
    for (uint256 i = 0; i < users.length; i++) {
        require(amounts[i] > 0, "Amount must be positive");
        totalAmount += amounts[i];
    }

    // Transfer total tokens needed
    token.safeTransferFrom(msg.sender, address(this), totalAmount);

    // Create vesting schedules
    for (uint256 i = 0; i < users.length; i++) {
        address user = users[i];
        uint256 amount = amounts[i];

        VestingSchedule storage schedule = vestingSchedules[user];
        
        if (schedule.totalAllocation == 0) {
            // Create new vesting
            schedule.startTime = block.timestamp;
            schedule.totalAllocation = amount;
            schedule.depositTimes.push(block.timestamp);
            schedule.depositAmounts.push(amount);
            emit VestingCreated(user, amount, block.timestamp);
        } else {
            // Increase existing vesting
            schedule.totalAllocation += amount;
            schedule.depositTimes.push(block.timestamp);
            schedule.depositAmounts.push(amount);
            emit VestingIncreased(user, amount);
        }
    }
    
    emit VestingBatchCreated(users, amounts);
}
}

