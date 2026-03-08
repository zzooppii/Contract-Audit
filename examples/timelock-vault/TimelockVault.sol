// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title TimelockVault - Vulnerable timelock + vesting contract
/// @notice This contract contains intentional vulnerabilities for audit testing
contract TimelockVault {
    struct Transaction {
        address target;
        uint256 value;
        bytes data;
        uint256 eta;
        bool executed;
    }

    struct VestingSchedule {
        uint256 totalAmount;
        uint256 startTime;
        uint256 cliff;
        uint256 duration;
        uint256 released;
    }

    IERC20 public token;
    address public admin;

    // VULN 1: delay is zero
    uint256 public delay = 0;

    uint256 public txCount;
    mapping(uint256 => Transaction) public transactions;
    mapping(address => VestingSchedule) public vestingSchedules;

    event TransactionQueued(uint256 indexed txId, address target, uint256 eta);
    event TransactionExecuted(uint256 indexed txId);
    event TransactionCancelled(uint256 indexed txId);

    constructor(address _token) {
        token = IERC20(_token);
        admin = msg.sender;
    }

    function queueTransaction(
        address target,
        uint256 value,
        bytes calldata data
    ) external returns (uint256) {
        require(msg.sender == admin, "Not admin");

        uint256 txId = txCount++;
        uint256 eta = block.timestamp + delay;

        transactions[txId] = Transaction({
            target: target,
            value: value,
            data: data,
            eta: eta,
            executed: false
        });

        emit TransactionQueued(txId, target, eta);
        return txId;
    }

    // VULN 2: execute does not check if transaction was queued
    function executeTransaction(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable {
        require(msg.sender == admin, "Not admin");

        // Missing: require(queued[txHash], "Not queued");
        // Missing: require(block.timestamp >= eta, "Not ready");

        (bool success, ) = target.call{value: value}(data);
        require(success, "Tx failed");
    }

    // VULN 3: cancel has no access control
    function cancelTransaction(uint256 txId) external {
        // Missing: require(msg.sender == admin, "Not admin");
        Transaction storage txn = transactions[txId];
        require(!txn.executed, "Already executed");

        delete transactions[txId];
        emit TransactionCancelled(txId);
    }

    // VULN 4: setDelay has no minimum check
    function setDelay(uint256 _delay) external {
        require(msg.sender == admin, "Not admin");
        delay = _delay;
    }

    // Vesting functions

    function createVestingSchedule(
        address beneficiary,
        uint256 amount,
        uint256 cliff,
        uint256 duration
    ) external {
        require(msg.sender == admin, "Not admin");
        require(vestingSchedules[beneficiary].totalAmount == 0, "Already exists");

        vestingSchedules[beneficiary] = VestingSchedule({
            totalAmount: amount,
            startTime: block.timestamp,
            cliff: cliff,
            duration: duration,
            released: 0
        });

        token.transferFrom(msg.sender, address(this), amount);
    }

    // VULN 5: withdraw does not check cliff period
    function withdraw() external {
        VestingSchedule storage schedule = vestingSchedules[msg.sender];
        require(schedule.totalAmount > 0, "No schedule");

        // Missing: require(block.timestamp >= schedule.startTime + schedule.cliff, "Cliff not reached");

        uint256 elapsed = block.timestamp - schedule.startTime;
        uint256 vested = (schedule.totalAmount * elapsed) / schedule.duration;
        uint256 releasable = vested - schedule.released;

        require(releasable > 0, "Nothing to release");
        schedule.released += releasable;
        token.transfer(msg.sender, releasable);
    }

    // VULN 6: timestamp-dependent unlock
    function emergencyUnlock(address beneficiary) external {
        require(msg.sender == admin, "Not admin");
        VestingSchedule storage schedule = vestingSchedules[beneficiary];
        uint256 unlockTime = schedule.startTime + schedule.duration;
        require(block.timestamp >= unlockTime, "Not unlocked yet");

        uint256 remaining = schedule.totalAmount - schedule.released;
        schedule.released = schedule.totalAmount;
        token.transfer(beneficiary, remaining);
    }

    receive() external payable {}
}
