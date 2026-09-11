// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title The Black Box Bazaar
/// @notice On-chain marketplace for cryptographic vulnerability disclosure.
///         Flagship / MVP vertical: ECDSA nonce-reuse. A seller claims that a
///         target account's signing process reused an ECDSA nonce `k` across
///         two signatures. That claim has a deterministic mathematical
///         predicate: two valid ECDSA signatures from the SAME public key,
///         over two DIFFERENT messages, that share the same `r` component
///         (r = x-coordinate of k*G mod n), are, for all practical purposes,
///         only possible if the same nonce `k` was reused (finding two
///         different nonces whose k*G share an x-coordinate is as hard as
///         breaking the discrete log problem). So the contract can check
///         "is this a genuine nonce-reuse instance" with nothing but
///         `ecrecover` -- no oracle, no human judgment call.
/// @dev Full flow:
///      1. Seller commits to a complete finding (target metadata + the full
///         writeup) by listing `keccak256(findingText)` alongside public,
///         non-sensitive metadata (target, category, severity, title). The
///         finding text itself is NOT stored yet -- buyers can't read what
///         they haven't paid for.
///      2. Buyer calls `purchase`, paying `price` into escrow, sight-unseen.
///      3. Seller calls `reveal` with the full finding text plus the actual
///         cryptographic evidence: two (messageHash, v, s) pairs sharing one
///         `r`. The contract:
///           a. checks `keccak256(findingText) == commitmentHash` -- proves
///              the revealed text is what was committed to at listing time
///              (the commitment is *not* proof of a real bug -- only proof
///              of what was promised);
///           b. runs `ecrecover` on both signatures and requires both to
///              recover to `targetAccount`, with two distinct message
///              hashes -- this *is* the deterministic cryptographic proof
///              of nonce reuse.
///         If both checks pass, escrow releases to the seller (their stake
///         is returned too) and the finding becomes on-chain / disclosed.
///         If not, the sale is rejected: the buyer is refunded in full and
///         the seller's stake is slashed to them as compensation.
///      4. If the seller never reveals before the deadline, anyone can call
///         `claimTimeout`, which resolves the sale exactly like a failed
///         reveal.
contract BlackBoxBazaar {
    enum Status {
        Listed,
        Escrowed,
        Verified,
        Failed,
        Refunded,
        Cancelled
    }

    struct Listing {
        address payable seller;
        address targetAccount;   // account whose key is allegedly compromised
        uint256 price;           // wei, paid by buyer into escrow
        uint256 stake;           // wei, seller's good-faith bond
        string category;         // e.g. "ECDSA Nonce Reuse"
        string severity;         // e.g. "Critical" -- display only, not verified on-chain
        string title;            // e.g. "Example Wallet signing service" -- public metadata
        bytes32 commitmentHash;  // keccak256(findingText), committed before payment
        Status status;
        address payable buyer;
        uint256 revealDeadline;
        string finding;          // filled in only once a reveal is Verified
    }

    struct Reputation {
        uint32 verified;
        uint32 failed;
    }

    uint256 public listingCount;
    mapping(uint256 => Listing) public listings;
    mapping(address => Reputation) public reputationOf;

    uint256 public constant REVEAL_WINDOW = 1 hours;
    uint256 public constant STAKE_BPS = 1000; // seller stakes 10% of price

    event Listed(
        uint256 indexed id,
        address indexed seller,
        address indexed targetAccount,
        uint256 price,
        uint256 stake,
        string category,
        string title
    );
    event Purchased(uint256 indexed id, address indexed buyer, uint256 revealDeadline);
    event Verified(uint256 indexed id, address indexed seller, address indexed buyer);
    event Failed(uint256 indexed id, address indexed seller, address indexed buyer, string reason);
    event Refunded(uint256 indexed id, address indexed buyer);
    event Cancelled(uint256 indexed id, address indexed seller);
    event Disclosed(uint256 indexed id, string finding);

    modifier onlySeller(uint256 id) {
        require(msg.sender == listings[id].seller, "not seller");
        _;
    }

    /// @notice List a claim. Public metadata is visible immediately; the
    ///         full finding is committed to (by hash) but stays hidden.
    function createListing(
        address targetAccount,
        uint256 price,
        string calldata category,
        string calldata severity,
        string calldata title,
        bytes32 commitmentHash
    ) external payable returns (uint256 id) {
        require(targetAccount != address(0), "bad target");
        require(price > 0, "price must be > 0");
        uint256 requiredStake = (price * STAKE_BPS) / 10000;
        require(msg.value == requiredStake, "must stake 10% of price");

        id = listingCount++;
        Listing storage l = listings[id];
        l.seller = payable(msg.sender);
        l.targetAccount = targetAccount;
        l.price = price;
        l.stake = msg.value;
        l.category = category;
        l.severity = severity;
        l.title = title;
        l.commitmentHash = commitmentHash;
        l.status = Status.Listed;

        emit Listed(id, msg.sender, targetAccount, price, msg.value, category, title);
    }

    /// @notice Seller withdraws an unpurchased listing and reclaims their stake.
    function cancelListing(uint256 id) external onlySeller(id) {
        Listing storage l = listings[id];
        require(l.status == Status.Listed, "not cancellable");
        l.status = Status.Cancelled;
        uint256 refund = l.stake;
        l.stake = 0;
        emit Cancelled(id, msg.sender);
        (bool ok, ) = l.seller.call{value: refund}("");
        require(ok, "refund failed");
    }

    /// @notice Buyer pays the listed price into escrow, sight-unseen.
    function purchase(uint256 id) external payable {
        Listing storage l = listings[id];
        require(l.status == Status.Listed, "not available");
        require(msg.value == l.price, "wrong price");

        l.buyer = payable(msg.sender);
        l.status = Status.Escrowed;
        l.revealDeadline = block.timestamp + REVEAL_WINDOW;

        emit Purchased(id, msg.sender, l.revealDeadline);
    }

    /// @notice Seller reveals the full finding plus the nonce-reuse evidence.
    /// @param findingText The complete disclosure, must hash to the listing's commitmentHash.
    /// @param msgHash1,v1,s1 First signature: ecrecover(msgHash1, v1, r, s1) must equal targetAccount.
    /// @param msgHash2,v2,s2 Second signature over a DIFFERENT message, same shared `r`.
    /// @param r The shared signature component -- if both signatures verify against the same
    ///        target address with the same `r` but different message hashes, the nonce was reused.
    function reveal(
        uint256 id,
        string calldata findingText,
        bytes32 msgHash1,
        uint8 v1,
        bytes32 r,
        bytes32 s1,
        bytes32 msgHash2,
        uint8 v2,
        bytes32 s2
    ) external onlySeller(id) {
        Listing storage l = listings[id];
        require(l.status == Status.Escrowed, "not awaiting reveal");
        require(block.timestamp <= l.revealDeadline, "reveal window passed");

        if (keccak256(bytes(findingText)) != l.commitmentHash) {
            _settleFailed(l, id, "finding does not match commitment");
            return;
        }
        if (msgHash1 == msgHash2) {
            _settleFailed(l, id, "signatures must cover different messages");
            return;
        }

        address rec1 = ecrecover(msgHash1, v1, r, s1);
        address rec2 = ecrecover(msgHash2, v2, r, s2);

        bool valid = rec1 != address(0) && rec1 == l.targetAccount && rec2 == l.targetAccount;

        if (valid) {
            l.status = Status.Verified;
            l.finding = findingText;
            reputationOf[l.seller].verified += 1;

            uint256 payout = l.price + l.stake;
            emit Verified(id, l.seller, l.buyer);
            emit Disclosed(id, findingText);

            (bool ok, ) = l.seller.call{value: payout}("");
            require(ok, "payout failed");
        } else {
            _settleFailed(l, id, "signatures do not prove nonce reuse against target account");
        }
    }

    /// @notice Anyone may resolve a sale the seller never revealed in time.
    function claimTimeout(uint256 id) external {
        Listing storage l = listings[id];
        require(l.status == Status.Escrowed, "not awaiting reveal");
        require(block.timestamp > l.revealDeadline, "reveal window not over");
        _settleFailed(l, id, "seller did not reveal in time");
    }

    function _settleFailed(Listing storage l, uint256 id, string memory reason) internal {
        l.status = Status.Failed;
        reputationOf[l.seller].failed += 1;

        uint256 refund = l.price + l.stake;
        emit Failed(id, l.seller, l.buyer, reason);

        (bool ok, ) = l.buyer.call{value: refund}("");
        require(ok, "refund failed");
    }

    // ---------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------

    function getListing(uint256 id) external view returns (Listing memory) {
        return listings[id];
    }

    function reputationScoreBps(address seller) external view returns (uint256) {
        Reputation memory rep = reputationOf[seller];
        uint256 total = uint256(rep.verified) + uint256(rep.failed);
        if (total == 0) return 10000; // no history yet -- display as neutral 100%
        return (uint256(rep.verified) * 10000) / total;
    }
}
