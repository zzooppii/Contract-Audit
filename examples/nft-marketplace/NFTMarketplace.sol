// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @title NFTMarketplace - NFT marketplace with multiple vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract NFTMarketplace {
    struct Listing {
        address seller;
        address nftContract;
        uint256 tokenId;
        uint256 price;
        address paymentToken; // address(0) = ETH
        bool active;
    }

    struct Auction {
        address seller;
        address nftContract;
        uint256 tokenId;
        uint256 highestBid;
        address highestBidder;
        uint256 endTime;
        bool settled;
    }

    mapping(uint256 => Listing) public listings;
    mapping(uint256 => Auction) public auctions;
    mapping(address => uint256) public pendingWithdrawals;
    uint256 public nextListingId;
    uint256 public nextAuctionId;

    address public owner;
    address public feeRecipient;
    uint256 public feeBasisPoints = 250; // 2.5%

    event Listed(uint256 indexed listingId, address seller, uint256 price);
    event Sold(uint256 indexed listingId, address buyer, uint256 price);
    event AuctionCreated(uint256 indexed auctionId, uint256 endTime);
    event BidPlaced(uint256 indexed auctionId, address bidder, uint256 amount);

    constructor() {
        owner = msg.sender;
        feeRecipient = msg.sender;
    }

    // ============ VULN-1: Reentrancy in buy (ETH refund before state update) ============
    function buyWithETH(uint256 listingId) external payable {
        Listing storage listing = listings[listingId];
        require(listing.active, "Not active");
        require(listing.paymentToken == address(0), "ETH only");
        require(msg.value >= listing.price, "Insufficient payment");

        // BUG: State update AFTER external calls
        uint256 fee = (listing.price * feeBasisPoints) / 10000;
        uint256 sellerAmount = listing.price - fee;

        // External calls before state update
        (bool sent1,) = listing.seller.call{value: sellerAmount}("");
        require(sent1, "Seller payment failed");

        (bool sent2,) = feeRecipient.call{value: fee}("");
        require(sent2, "Fee payment failed");

        // Refund excess
        if (msg.value > listing.price) {
            (bool refund,) = msg.sender.call{value: msg.value - listing.price}("");
            require(refund, "Refund failed");
        }

        // BUG: State update after all external calls — reentrancy window
        listing.active = false;

        IERC721(listing.nftContract).transferFrom(address(this), msg.sender, listing.tokenId);
        emit Sold(listingId, msg.sender, listing.price);
    }

    // ============ VULN-2: Front-running on auction bids ============
    function placeBid(uint256 auctionId) external payable {
        Auction storage auction = auctions[auctionId];
        require(block.timestamp < auction.endTime, "Auction ended");
        // BUG: No minimum bid increment — easy to front-run by 1 wei
        require(msg.value > auction.highestBid, "Bid too low");

        // Refund previous bidder
        if (auction.highestBidder != address(0)) {
            // BUG: Potential DoS — if highestBidder is a contract that reverts
            (bool sent,) = auction.highestBidder.call{value: auction.highestBid}("");
            require(sent, "Refund failed");
        }

        auction.highestBid = msg.value;
        auction.highestBidder = msg.sender;
        emit BidPlaced(auctionId, msg.sender, msg.value);
    }

    // ============ VULN-3: Unchecked ERC20 transfer ============
    function buyWithToken(uint256 listingId) external {
        Listing storage listing = listings[listingId];
        require(listing.active, "Not active");
        require(listing.paymentToken != address(0), "Token only");

        uint256 fee = (listing.price * feeBasisPoints) / 10000;
        uint256 sellerAmount = listing.price - fee;

        listing.active = false;

        // BUG: Return values not checked — silent failure with non-standard tokens
        IERC20(listing.paymentToken).transferFrom(msg.sender, listing.seller, sellerAmount);
        IERC20(listing.paymentToken).transferFrom(msg.sender, feeRecipient, fee);

        IERC721(listing.nftContract).transferFrom(address(this), msg.sender, listing.tokenId);
        emit Sold(listingId, msg.sender, listing.price);
    }

    // ============ VULN-4: Missing access control ============
    function setFeeRecipient(address newRecipient) external {
        // BUG: Anyone can redirect all marketplace fees
        feeRecipient = newRecipient;
    }

    function setFeeBasisPoints(uint256 newFee) external {
        // BUG: Anyone can set fee to 100% and steal all payments
        feeBasisPoints = newFee;
    }

    // ============ VULN-5: tx.origin for authentication ============
    function emergencyDelist(uint256 listingId) external {
        require(tx.origin == owner, "Not owner");
        listings[listingId].active = false;
    }

    // ============ Safe functions ============
    function createListing(
        address nftContract,
        uint256 tokenId,
        uint256 price,
        address paymentToken
    ) external returns (uint256) {
        require(price > 0, "Zero price");
        IERC721(nftContract).transferFrom(msg.sender, address(this), tokenId);

        uint256 id = nextListingId++;
        listings[id] = Listing({
            seller: msg.sender,
            nftContract: nftContract,
            tokenId: tokenId,
            price: price,
            paymentToken: paymentToken,
            active: true
        });

        emit Listed(id, msg.sender, price);
        return id;
    }

    receive() external payable {}
}
