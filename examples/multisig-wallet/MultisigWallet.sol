// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @title MultisigWallet - Multi-signature wallet with multiple vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract MultisigWallet {
    struct Transaction {
        address to;
        uint256 value;
        bytes data;
        bool executed;
        uint256 confirmations;
    }

    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public required;

    Transaction[] public transactions;
    mapping(uint256 => mapping(address => bool)) public isConfirmed;

    uint256 public nonce;

    event SubmitTransaction(uint256 indexed txIndex, address indexed owner, address to, uint256 value);
    event ConfirmTransaction(uint256 indexed txIndex, address indexed owner);
    event ExecuteTransaction(uint256 indexed txIndex);
    event RevokeConfirmation(uint256 indexed txIndex, address indexed owner);

    modifier onlyOwner() {
        require(isOwner[msg.sender], "Not owner");
        _;
    }

    modifier txExists(uint256 txIndex) {
        require(txIndex < transactions.length, "Tx does not exist");
        _;
    }

    modifier notExecuted(uint256 txIndex) {
        require(!transactions[txIndex].executed, "Already executed");
        _;
    }

    constructor(address[] memory _owners, uint256 _required) {
        require(_owners.length > 0, "No owners");
        require(_required > 0 && _required <= _owners.length, "Invalid required");

        for (uint256 i = 0; i < _owners.length; i++) {
            address o = _owners[i];
            // BUG: No duplicate check — same address can be added multiple times
            // effectively reducing the actual threshold
            require(o != address(0), "Invalid owner");
            isOwner[o] = true;
            owners.push(o);
        }
        required = _required;
    }

    // ============ VULN-1: Signature replay across chains ============
    function executeWithSignatures(
        address to,
        uint256 value,
        bytes memory data,
        bytes[] memory signatures
    ) external {
        // BUG: No chain ID in hash — signatures can be replayed on other chains
        // BUG: No nonce — same transaction can be replayed
        bytes32 txHash = keccak256(abi.encodePacked(to, value, data));

        uint256 validSigs = 0;
        address lastSigner = address(0);

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = recoverSigner(txHash, signatures[i]);
            // BUG: No check that signer > lastSigner — same signature can be reused
            require(isOwner[signer], "Not owner");
            require(signer > lastSigner, "Duplicate signer");
            lastSigner = signer;
            validSigs++;
        }

        require(validSigs >= required, "Not enough signatures");

        // BUG: No nonce increment — same signatures can execute again
        (bool success,) = to.call{value: value}(data);
        require(success, "Execution failed");
    }

    // ============ VULN-2: ecrecover without zero check ============
    function recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) public pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // BUG: No check for s-malleability (s should be in lower half)
        // BUG: ecrecover returns address(0) for invalid signatures — not checked
        return ecrecover(hash, v, r, s);
    }

    // ============ VULN-3: Missing access control on owner management ============
    function addOwner(address newOwner) external {
        // BUG: Anyone can add themselves as owner
        require(newOwner != address(0), "Invalid");
        isOwner[newOwner] = true;
        owners.push(newOwner);
    }

    function removeOwner(address ownerToRemove) external {
        // BUG: Anyone can remove any owner
        isOwner[ownerToRemove] = false;
        // BUG: Does not remove from owners array — ghost entries
        // BUG: Does not check if remaining owners >= required
    }

    function setRequired(uint256 newRequired) external {
        // BUG: Anyone can change the threshold
        // BUG: No check that newRequired <= owners.length
        required = newRequired;
    }

    // ============ VULN-4: Reentrancy in execute ============
    function submitTransaction(
        address to,
        uint256 value,
        bytes memory data
    ) public onlyOwner returns (uint256) {
        uint256 txIndex = transactions.length;
        transactions.push(Transaction({
            to: to,
            value: value,
            data: data,
            executed: false,
            confirmations: 0
        }));

        emit SubmitTransaction(txIndex, msg.sender, to, value);
        return txIndex;
    }

    function confirmTransaction(uint256 txIndex)
        public
        onlyOwner
        txExists(txIndex)
        notExecuted(txIndex)
    {
        require(!isConfirmed[txIndex][msg.sender], "Already confirmed");
        Transaction storage txn = transactions[txIndex];
        txn.confirmations += 1;
        isConfirmed[txIndex][msg.sender] = true;
        emit ConfirmTransaction(txIndex, msg.sender);
    }

    function executeTransaction(uint256 txIndex)
        public
        onlyOwner
        txExists(txIndex)
        notExecuted(txIndex)
    {
        Transaction storage txn = transactions[txIndex];
        require(txn.confirmations >= required, "Not enough confirmations");

        // BUG: External call before state update — reentrancy
        (bool success,) = txn.to.call{value: txn.value}(txn.data);
        require(success, "Execution failed");

        txn.executed = true;
        emit ExecuteTransaction(txIndex);
    }

    // ============ VULN-5: Token rescue without proper auth ============
    function rescueTokens(address token, uint256 amount) external {
        // BUG: Anyone can drain any ERC20 token from the wallet
        IERC20(token).transfer(msg.sender, amount);
    }

    function rescueETH() external {
        // BUG: Anyone can drain all ETH
        (bool sent,) = msg.sender.call{value: address(this).balance}("");
        require(sent, "Transfer failed");
    }

    // ============ VULN-6: Denial of service via unbounded loop ============
    function getOwnerCount() public view returns (uint256 count) {
        // BUG: Iterates full array including removed (ghost) owners
        for (uint256 i = 0; i < owners.length; i++) {
            if (isOwner[owners[i]]) {
                count++;
            }
        }
    }

    // ============ Safe function ============
    function revokeConfirmation(uint256 txIndex)
        public
        onlyOwner
        txExists(txIndex)
        notExecuted(txIndex)
    {
        require(isConfirmed[txIndex][msg.sender], "Not confirmed");
        Transaction storage txn = transactions[txIndex];
        txn.confirmations -= 1;
        isConfirmed[txIndex][msg.sender] = false;
        emit RevokeConfirmation(txIndex, msg.sender);
    }

    receive() external payable {}
}
