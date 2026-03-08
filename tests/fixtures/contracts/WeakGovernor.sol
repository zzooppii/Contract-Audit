// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVotingToken {
    function balanceOf(address account) external view returns (uint256);
    function getPastVotes(address account, uint256 blockNumber) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

/// @title WeakGovernor
/// @notice Governance contract with multiple attack surfaces
/// @dev DO NOT USE IN PRODUCTION
contract WeakGovernor {
    IVotingToken public token;
    address public admin;

    struct Proposal {
        address target;
        bytes data;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
    }

    Proposal[] public proposals;

    // VULN-1: Very low quorum (1%)
    uint256 public quorumThreshold = 0.01e18; // 1%

    // VULN-2: No timelock
    // uint256 public timelockDelay = 0; // No delay at all

    // VULN-3: Zero proposal threshold
    uint256 public proposalThreshold = 0; // Anyone can propose

    constructor(address _token) {
        token = IVotingToken(_token);
        admin = msg.sender;
    }

    // VULN-4: Uses balanceOf instead of getPastVotes (flash loan voting)
    function castVote(uint256 proposalId, bool support) external {
        uint256 votes = token.balanceOf(msg.sender); // Should use getPastVotes
        Proposal storage proposal = proposals[proposalId];

        if (support) {
            proposal.forVotes += votes;
        } else {
            proposal.againstVotes += votes;
        }
    }

    function propose(address target, bytes calldata data) external returns (uint256) {
        // VULN-3: No threshold check
        proposals.push(Proposal({
            target: target,
            data: data,
            forVotes: 0,
            againstVotes: 0,
            executed: false
        }));
        return proposals.length - 1;
    }

    function execute(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(!proposal.executed, "Already executed");
        require(proposal.forVotes > proposal.againstVotes, "Did not pass");

        // VULN: No timelock delay before execution
        proposal.executed = true;
        (bool success,) = proposal.target.call(proposal.data);
        require(success, "Execution failed");
    }

    // VULN-5: Centralized admin control over sensitive function
    function setQuorum(uint256 newQuorum) external onlyOwner {
        quorumThreshold = newQuorum;
    }

    function setFee(uint256 newFee) external onlyOwner {
        // Can change protocol fees without governance
    }

    modifier onlyOwner() {
        require(msg.sender == admin, "Not admin");
        _;
    }
}
