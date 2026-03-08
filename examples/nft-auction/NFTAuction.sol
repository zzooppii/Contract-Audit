// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/**
 * @title NFTAuction
 * @notice NFT marketplace with auction functionality — contains NFT-specific bugs.
 *         Used for testing the nft_detector.
 */
contract NFTAuction is ERC721 {
    uint256 public nextTokenId;
    mapping(uint256 => address) public highestBidder;
    mapping(uint256 => uint256) public highestBid;
    mapping(uint256 => bool) public auctionActive;
    mapping(uint256 => string) private _tokenURIs;

    constructor() ERC721("AuctionNFT", "ANFT") {}

    // BUG 1: Uses _mint() instead of _safeMint()
    function mintNFT(address to) external returns (uint256) {
        uint256 tokenId = nextTokenId++;
        _mint(to, tokenId);
        return tokenId;
    }

    // BUG 2: State change after _safeMint (callback reentrancy)
    function safeMintAndStartAuction(address to, uint256 startPrice) external {
        uint256 tokenId = nextTokenId;
        _safeMint(to, tokenId);

        // State update AFTER _safeMint — vulnerable to reentrancy via onERC721Received
        nextTokenId++;
        auctionActive[tokenId] = true;
        highestBid[tokenId] = startPrice;
    }

    // BUG 3: Missing _exists() check in tokenURI
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        return _tokenURIs[tokenId];
    }

    // BUG 4: setApprovalForAll override without additional validation
    function setApprovalForAll(address operator, bool approved) public override {
        super.setApprovalForAll(operator, approved);
    }

    function placeBid(uint256 tokenId) external payable {
        require(auctionActive[tokenId], "Auction not active");
        require(msg.value > highestBid[tokenId], "Bid too low");

        address previousBidder = highestBidder[tokenId];
        uint256 previousBid = highestBid[tokenId];

        highestBidder[tokenId] = msg.sender;
        highestBid[tokenId] = msg.value;

        if (previousBidder != address(0)) {
            payable(previousBidder).transfer(previousBid);
        }
    }

    function endAuction(uint256 tokenId) external {
        require(auctionActive[tokenId], "Auction not active");
        require(ownerOf(tokenId) == msg.sender, "Not token owner");

        auctionActive[tokenId] = false;
        address winner = highestBidder[tokenId];

        if (winner != address(0)) {
            safeTransferFrom(msg.sender, winner, tokenId);
        }
    }
}
