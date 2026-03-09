// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IProtocol.sol";
import "./Token.sol";
import "./Pool.sol";
import "./Oracle.sol";

contract Governance {
    ProtocolToken public govToken;
    LendingPool public pool;
    PriceOracle public oracle;
    address public admin;

    uint256 public constant PROPOSAL_THRESHOLD = 1000e18;
    // Vulnerability: voting period too short
    uint256 public constant VOTING_PERIOD = 1 days;
    // Vulnerability: no timelock delay
    uint256 public constant EXECUTION_DELAY = 0;
    uint256 public constant QUORUM = 5000e18;

    struct Proposal {
        address proposer;
        address target;
        bytes callData;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 startTime;
        uint256 endTime;
        bool executed;
        mapping(address => bool) hasVoted;
    }

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;

    event ProposalCreated(uint256 indexed id, address indexed proposer, address target);
    event Voted(uint256 indexed id, address indexed voter, bool support, uint256 weight);
    event ProposalExecuted(uint256 indexed id);

    constructor(address _govToken, address _pool, address _oracle) {
        govToken = ProtocolToken(_govToken);
        pool = LendingPool(_pool);
        oracle = PriceOracle(_oracle);
        admin = msg.sender;
    }

    function propose(address target, bytes calldata callData) external returns (uint256) {
        // Vulnerability: uses current balance, not snapshot — flash loan governance attack
        require(govToken.balanceOf(msg.sender) >= PROPOSAL_THRESHOLD, "Below threshold");

        uint256 id = proposalCount++;
        Proposal storage p = proposals[id];
        p.proposer = msg.sender;
        p.target = target;
        p.callData = callData;
        p.startTime = block.timestamp;
        p.endTime = block.timestamp + VOTING_PERIOD;

        emit ProposalCreated(id, msg.sender, target);
        return id;
    }

    function vote(uint256 proposalId, bool support) external {
        Proposal storage p = proposals[proposalId];
        require(block.timestamp <= p.endTime, "Voting ended");
        require(!p.hasVoted[msg.sender], "Already voted");

        // Vulnerability: voting weight from current balance, not snapshot
        uint256 weight = govToken.balanceOf(msg.sender);
        require(weight > 0, "No voting power");

        p.hasVoted[msg.sender] = true;

        if (support) {
            p.forVotes += weight;
        } else {
            p.againstVotes += weight;
        }

        emit Voted(proposalId, msg.sender, support, weight);
    }

    // Vulnerability: no timelock, immediate execution
    // Vulnerability: arbitrary call to any target — can drain pool/oracle
    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(block.timestamp > p.endTime, "Voting not ended");
        require(!p.executed, "Already executed");
        require(p.forVotes > p.againstVotes, "Not passed");
        require(p.forVotes >= QUORUM, "Quorum not reached");

        p.executed = true;

        // Vulnerability: unchecked low-level call to arbitrary target
        (bool success,) = p.target.call(p.callData);
        require(success, "Execution failed");

        emit ProposalExecuted(proposalId);
    }

    // Vulnerability: admin bypass — can execute anything without vote
    function emergencyExecute(address target, bytes calldata callData) external {
        require(msg.sender == admin, "Not admin");
        (bool success,) = target.call(callData);
        require(success, "Failed");
    }
}
