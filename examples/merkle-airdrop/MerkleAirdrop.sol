// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title MerkleAirdrop - Vulnerable Merkle airdrop implementation
/// @notice This contract contains intentional vulnerabilities for audit testing
contract MerkleAirdrop {
    IERC20 public token;
    bytes32 public merkleRoot;
    address public owner;

    // VULN 1: No claimed mapping - users can claim multiple times

    event Claimed(address indexed account, uint256 amount);

    constructor(address _token, bytes32 _merkleRoot) {
        token = IERC20(_token);
        merkleRoot = _merkleRoot;
        owner = msg.sender;
    }

    // VULN 2: abi.encodePacked hash collision risk
    // VULN 3: No expiry/deadline mechanism
    // VULN 4: msg.sender not bound in leaf - front-running risk
    function claim(
        address account,
        uint256 amount,
        bytes32[] calldata proof
    ) external {
        // VULN 2: Using encodePacked instead of encode
        bytes32 leaf = keccak256(abi.encodePacked(account, amount));

        require(MerkleProof.verify(proof, merkleRoot, leaf), "Invalid proof");

        // VULN 1: No check for already claimed
        // Missing: require(!claimed[account], "Already claimed");
        // Missing: claimed[account] = true;

        token.transfer(account, amount);
        emit Claimed(account, amount);
    }

    // VULN 5: setMerkleRoot has no access control
    function setMerkleRoot(bytes32 _newRoot) external {
        merkleRoot = _newRoot;
    }

    function depositTokens(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
    }
}
