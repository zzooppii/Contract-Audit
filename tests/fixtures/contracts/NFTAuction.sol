// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract NFTAuction is ERC721 {
    uint256 public nextTokenId;
    mapping(uint256 => bool) public auctionActive;
    mapping(uint256 => string) private _tokenURIs;

    constructor() ERC721("ANFT", "ANFT") {}

    // Unsafe _mint (should use _safeMint)
    function mintNFT(address to) external returns (uint256) {
        uint256 tokenId = nextTokenId++;
        _mint(to, tokenId);
        return tokenId;
    }

    // State change after _safeMint (callback reentrancy)
    function safeMintAndAuction(address to, uint256 price) external {
        uint256 tokenId = nextTokenId;
        _safeMint(to, tokenId);
        nextTokenId++;
        auctionActive[tokenId] = true;
    }

    // Missing _exists check in tokenURI
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        return _tokenURIs[tokenId];
    }

    // setApprovalForAll override without validation
    function setApprovalForAll(address operator, bool approved) public override {
        super.setApprovalForAll(operator, approved);
    }
}
