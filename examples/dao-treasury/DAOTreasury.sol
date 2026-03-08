// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface IVotingToken {
    function balanceOf(address) external view returns (uint256);
    function getPastVotes(address, uint256) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function delegates(address) external view returns (address);
}

/// @title DAOTreasury - DAO governance and treasury with multiple vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract DAOTreasury {
    struct Proposal {
        uint256 id;
        address proposer;
        address[] targets;
        uint256[] values;
        bytes[] calldatas;
        string description;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 startBlock;
        uint256 endBlock;
        bool executed;
        bool cancelled;
    }

    IVotingToken public govToken;
    address public guardian;

    Proposal[] public proposals;

    // ============ VULN-1: Dangerously low quorum (0.5%) ============
    uint256 public quorumNumerator = 50; // 0.5% — should be 4%+
    uint256 public constant QUORUM_DENOMINATOR = 10000;

    // ============ VULN-2: No timelock ============
    // Proposals can be executed immediately after voting ends
    uint256 public timelockDelay = 0; // BUG: Should be >= 2 days

    // ============ VULN-3: Zero proposal threshold ============
    uint256 public proposalThreshold = 0; // BUG: Anyone can propose

    uint256 public votingPeriod = 100; // ~100 blocks, very short

    mapping(uint256 => mapping(address => bool)) public hasVoted;

    event ProposalCreated(uint256 indexed id, address proposer, string description);
    event VoteCast(uint256 indexed proposalId, address voter, bool support, uint256 weight);
    event ProposalExecuted(uint256 indexed id);
    event ProposalCancelled(uint256 indexed id);

    constructor(address _govToken) {
        govToken = IVotingToken(_govToken);
        guardian = msg.sender;
    }

    // ============ VULN-4: Uses balanceOf instead of getPastVotes ============
    function castVote(uint256 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];
        require(block.number >= proposal.startBlock, "Not started");
        require(block.number <= proposal.endBlock, "Ended");
        require(!hasVoted[proposalId][msg.sender], "Already voted");

        // BUG: Uses current balance — flash loan voting attack
        uint256 weight = govToken.balanceOf(msg.sender);
        require(weight > 0, "No voting power");

        hasVoted[proposalId][msg.sender] = true;

        if (support) {
            proposal.forVotes += weight;
        } else {
            proposal.againstVotes += weight;
        }

        emit VoteCast(proposalId, msg.sender, support, weight);
    }

    // ============ VULN-5: No quorum check in execute ============
    function execute(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(!proposal.executed, "Already executed");
        require(!proposal.cancelled, "Cancelled");
        require(block.number > proposal.endBlock, "Voting active");
        require(proposal.forVotes > proposal.againstVotes, "Not passed");

        // BUG: No quorum check — 1 vote could pass a proposal
        // Missing: require(proposal.forVotes >= quorum(), "Quorum not reached")

        // BUG: No timelock delay
        // Missing: require(block.timestamp >= proposal.endBlock + timelockDelay)

        proposal.executed = true;

        for (uint256 i = 0; i < proposal.targets.length; i++) {
            // BUG: Unbounded loop with external calls
            (bool success,) = proposal.targets[i].call{value: proposal.values[i]}(
                proposal.calldatas[i]
            );
            require(success, "Execution failed");
        }

        emit ProposalExecuted(proposalId);
    }

    // ============ VULN-6: Guardian has excessive power ============
    function guardianCancel(uint256 proposalId) external {
        require(msg.sender == guardian, "Not guardian");
        // BUG: Guardian can cancel any proposal — centralization risk
        proposals[proposalId].cancelled = true;
        emit ProposalCancelled(proposalId);
    }

    function guardianExecute(
        address target,
        uint256 value,
        bytes calldata data
    ) external returns (bytes memory) {
        require(msg.sender == guardian, "Not guardian");
        // BUG: Guardian can execute arbitrary calls — bypasses governance entirely
        (bool success, bytes memory result) = target.call{value: value}(data);
        require(success, "Call failed");
        return result;
    }

    function setGuardian(address newGuardian) external {
        require(msg.sender == guardian, "Not guardian");
        // BUG: No timelock on guardian transfer — instant takeover
        guardian = newGuardian;
    }

    // ============ Safe functions ============
    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description
    ) external returns (uint256) {
        require(targets.length == values.length && values.length == calldatas.length, "Length mismatch");
        require(targets.length > 0, "Empty proposal");

        uint256 id = proposals.length;
        Proposal storage p = proposals.push();
        p.id = id;
        p.proposer = msg.sender;
        p.targets = targets;
        p.values = values;
        p.calldatas = calldatas;
        p.description = description;
        p.startBlock = block.number + 1;
        p.endBlock = block.number + 1 + votingPeriod;

        emit ProposalCreated(id, msg.sender, description);
        return id;
    }

    function quorum() public view returns (uint256) {
        return (govToken.totalSupply() * quorumNumerator) / QUORUM_DENOMINATOR;
    }

    receive() external payable {}
}
