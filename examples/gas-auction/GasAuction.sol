// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @title GasAuction - Auction/distribution contract with gas griefing vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract GasAuction {
    struct Auction {
        address seller;
        address highestBidder;
        uint256 highestBid;
        uint256 endTime;
        bool settled;
    }

    struct Distribution {
        address token;
        uint256 totalAmount;
        address[] recipients;
        uint256[] amounts;
        bool distributed;
    }

    IERC20 public paymentToken;
    address public admin;

    Auction[] public auctions;
    Distribution[] public distributions;

    mapping(address => uint256) public pendingRefunds;
    mapping(uint256 => address[]) public auctionBidders;

    event AuctionCreated(uint256 indexed auctionId, address seller);
    event BidPlaced(uint256 indexed auctionId, address bidder, uint256 amount);
    event AuctionSettled(uint256 indexed auctionId, address winner);
    event Distributed(uint256 indexed distId);
    event RefundClaimed(address indexed user, uint256 amount);

    constructor(address _paymentToken) {
        paymentToken = IERC20(_paymentToken);
        admin = msg.sender;
    }

    function createAuction(uint256 duration) external {
        auctions.push(Auction({
            seller: msg.sender,
            highestBidder: address(0),
            highestBid: 0,
            endTime: block.timestamp + duration,
            settled: false
        }));
        emit AuctionCreated(auctions.length - 1, msg.sender);
    }

    // ============ VULN-1: Unbounded loop over bidders ============
    function settleAuction(uint256 auctionId) external {
        Auction storage auction = auctions[auctionId];
        require(block.timestamp > auction.endTime, "Not ended");
        require(!auction.settled, "Already settled");

        auction.settled = true;

        // BUG: Iterates over ALL bidders — if many bids were placed,
        // this loop will exceed the block gas limit, making settlement
        // impossible (permanent DoS)
        address[] storage bidders = auctionBidders[auctionId];
        for (uint256 i = 0; i < bidders.length; i++) {
            if (bidders[i] != auction.highestBidder) {
                // Refund losing bidders
                pendingRefunds[bidders[i]] += auction.highestBid;
            }
        }

        // Transfer winning bid to seller
        paymentToken.transfer(auction.seller, auction.highestBid);

        emit AuctionSettled(auctionId, auction.highestBidder);
    }

    // ============ VULN-2: External calls inside loop (push payment) ============
    function distributeRewards(uint256 distId) external {
        Distribution storage dist = distributions[distId];
        require(!dist.distributed, "Already distributed");

        dist.distributed = true;

        // BUG: External call (transfer) inside a loop
        // If ANY recipient is a contract that reverts, the entire
        // distribution fails — one malicious recipient blocks everyone
        for (uint256 i = 0; i < dist.recipients.length; i++) {
            IERC20(dist.token).transfer(dist.recipients[i], dist.amounts[i]);
        }

        emit Distributed(distId);
    }

    // ============ VULN-3: Unbounded array growth ============
    function placeBid(uint256 auctionId, uint256 amount) external {
        Auction storage auction = auctions[auctionId];
        require(block.timestamp <= auction.endTime, "Auction ended");
        require(amount > auction.highestBid, "Bid too low");

        paymentToken.transferFrom(msg.sender, address(this), amount);

        // BUG: Every bid pushes to array without limit
        // Attacker can place thousands of minimum-increment bids
        // to grow the array, causing settleAuction to run out of gas
        auctionBidders[auctionId].push(msg.sender);

        if (auction.highestBidder != address(0)) {
            pendingRefunds[auction.highestBidder] += auction.highestBid;
        }

        auction.highestBidder = msg.sender;
        auction.highestBid = amount;

        emit BidPlaced(auctionId, msg.sender, amount);
    }

    // ============ VULN-4: Missing access control ============
    function createDistribution(
        address token,
        address[] memory recipients,
        uint256[] memory amounts
    ) external {
        // BUG: Anyone can create a distribution — should be admin only
        require(recipients.length == amounts.length, "Length mismatch");

        uint256 total = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            total += amounts[i];
        }

        distributions.push();
        Distribution storage dist = distributions[distributions.length - 1];
        dist.token = token;
        dist.totalAmount = total;
        dist.distributed = false;

        for (uint256 i = 0; i < recipients.length; i++) {
            dist.recipients.push(recipients[i]);
            dist.amounts.push(amounts[i]);
        }
    }

    function setAdmin(address newAdmin) external {
        // BUG: Anyone can become admin
        admin = newAdmin;
    }

    // ============ VULN-5: Reentrancy in refund claim ============
    function claimRefund() external {
        uint256 amount = pendingRefunds[msg.sender];
        require(amount > 0, "No refund");

        // BUG: External call before state update
        paymentToken.transfer(msg.sender, amount);

        // State update after external call
        pendingRefunds[msg.sender] = 0;

        emit RefundClaimed(msg.sender, amount);
    }

    // ============ VULN-6: Block gas limit DoS via return data bomb ============
    function batchSettle(uint256[] memory auctionIds) external {
        // BUG: No limit on batch size — attacker can pass huge array
        // to exhaust gas, and combined with the unbounded inner loop
        // in settleAuction, this becomes a gas bomb
        for (uint256 i = 0; i < auctionIds.length; i++) {
            Auction storage auction = auctions[auctionIds[i]];
            if (!auction.settled && block.timestamp > auction.endTime) {
                auction.settled = true;

                // Inner loop over bidders — double unbounded iteration
                address[] storage bidders = auctionBidders[auctionIds[i]];
                for (uint256 j = 0; j < bidders.length; j++) {
                    if (bidders[j] != auction.highestBidder) {
                        pendingRefunds[bidders[j]] += auction.highestBid;
                    }
                }

                paymentToken.transfer(auction.seller, auction.highestBid);
                emit AuctionSettled(auctionIds[i], auction.highestBidder);
            }
        }
    }

    // ============ Safe functions ============
    function getAuctionBidders(uint256 auctionId) external view returns (address[] memory) {
        return auctionBidders[auctionId];
    }

    function getDistributionRecipients(uint256 distId) external view returns (address[] memory) {
        return distributions[distId].recipients;
    }
}
