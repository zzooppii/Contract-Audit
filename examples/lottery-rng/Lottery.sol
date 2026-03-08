// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

/// @title Lottery - Lottery/raffle with randomness and NFT callback vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract Lottery {
    struct Round {
        uint256 prizePool;
        uint256 ticketPrice;
        uint256 endBlock;
        address winner;
        bool settled;
        address[] participants;
    }

    IERC20 public paymentToken;
    IERC721 public prizeNFT;
    address public operator;

    Round[] public rounds;
    uint256 public currentRound;
    uint256 public operatorFee = 500; // 5%

    mapping(address => uint256) public pendingRewards;

    event TicketPurchased(uint256 indexed roundId, address indexed buyer);
    event RoundSettled(uint256 indexed roundId, address winner, uint256 prize);
    event NFTPrizeClaimed(address indexed winner, uint256 tokenId);

    constructor(address _paymentToken, address _prizeNFT) {
        paymentToken = IERC20(_paymentToken);
        prizeNFT = IERC721(_prizeNFT);
        operator = msg.sender;
    }

    // ============ VULN-1: Weak randomness using block variables ============
    function settleLottery(uint256 roundId) external {
        Round storage round = rounds[roundId];
        require(block.number > round.endBlock, "Not ended");
        require(!round.settled, "Already settled");
        require(round.participants.length > 0, "No participants");

        // BUG: Predictable randomness — miners can manipulate block.timestamp
        // and block.prevrandao (formerly block.difficulty)
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.prevrandao,
            block.number,
            msg.sender
        )));

        uint256 winnerIndex = random % round.participants.length;
        round.winner = round.participants[winnerIndex];
        round.settled = true;

        // Calculate prize
        uint256 fee = (round.prizePool * operatorFee) / 10000;
        uint256 prize = round.prizePool - fee;

        pendingRewards[round.winner] += prize;
        pendingRewards[operator] += fee;

        emit RoundSettled(roundId, round.winner, prize);
    }

    // ============ VULN-2: blockhash only works for last 256 blocks ============
    function settleWithBlockhash(uint256 roundId) external {
        Round storage round = rounds[roundId];
        require(block.number > round.endBlock, "Not ended");
        require(!round.settled, "Already settled");

        // BUG: blockhash returns 0 for blocks older than 256
        // If no one calls settle within 256 blocks, randomness = 0 → predictable
        bytes32 bhash = blockhash(round.endBlock);
        uint256 random = uint256(keccak256(abi.encodePacked(bhash, roundId)));

        uint256 winnerIndex = random % round.participants.length;
        round.winner = round.participants[winnerIndex];
        round.settled = true;

        uint256 fee = (round.prizePool * operatorFee) / 10000;
        uint256 prize = round.prizePool - fee;
        pendingRewards[round.winner] += prize;
        pendingRewards[operator] += fee;

        emit RoundSettled(roundId, round.winner, prize);
    }

    // ============ VULN-3: ERC721 safeTransferFrom callback reentrancy ============
    function claimNFTPrize(uint256 roundId, uint256 nftTokenId) external {
        Round storage round = rounds[roundId];
        require(round.winner == msg.sender, "Not winner");

        // BUG: safeTransferFrom calls onERC721Received on the recipient
        // If recipient is a contract, it gets a callback BEFORE state is finalized
        // Attacker can re-enter during the callback
        prizeNFT.safeTransferFrom(address(this), msg.sender, nftTokenId);

        // State update after external call with callback
        round.winner = address(0);

        emit NFTPrizeClaimed(msg.sender, nftTokenId);
    }

    // ============ VULN-4: Unbounded array in participants ============
    function buyTicket(uint256 roundId, uint256 quantity) external {
        Round storage round = rounds[roundId];
        require(block.number <= round.endBlock, "Round ended");
        require(quantity > 0, "Zero quantity");

        uint256 cost = round.ticketPrice * quantity;
        paymentToken.transferFrom(msg.sender, address(this), cost);
        round.prizePool += cost;

        // BUG: Unbounded push — if too many tickets, settle will run out of gas
        // because winner selection accesses participants.length
        for (uint256 i = 0; i < quantity; i++) {
            round.participants.push(msg.sender);
        }

        emit TicketPurchased(roundId, msg.sender);
    }

    // ============ VULN-5: Missing access control ============
    function setOperatorFee(uint256 newFee) external {
        // BUG: Anyone can set fee to 100%
        operatorFee = newFee;
    }

    function setOperator(address newOperator) external {
        // BUG: Anyone can become operator and collect fees
        operator = newOperator;
    }

    // ============ VULN-6: Reward claim with reentrancy ============
    function claimRewards() external {
        uint256 amount = pendingRewards[msg.sender];
        require(amount > 0, "No rewards");

        // BUG: External call before state update
        paymentToken.transfer(msg.sender, amount);

        // State update after external call
        pendingRewards[msg.sender] = 0;
    }

    // ============ Safe functions ============
    function createRound(uint256 ticketPrice, uint256 duration) external {
        require(msg.sender == operator, "Not operator");
        require(ticketPrice > 0, "Zero price");

        rounds.push();
        Round storage newRound = rounds[rounds.length - 1];
        newRound.ticketPrice = ticketPrice;
        newRound.endBlock = block.number + duration;

        currentRound = rounds.length - 1;
    }

    function getParticipants(uint256 roundId) external view returns (address[] memory) {
        return rounds[roundId].participants;
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }
}
