pragma solidity 0.5.13;

import "./UTXOClaimValidation.sol";


contract UTXORedeemableToken is UTXOClaimValidation {
    /**
     * @dev PUBLIC FACING: Claim a BTC address and its Satoshi balance in Spades
     * crediting the appropriate amount to a specified Eth address. Bitcoin ECDSA
     * signature must be from that BTC address and must match the claim message
     * for the Eth address.
     * @param rawSatoshis Raw BTC address balance in Satoshis
     * @param proof Merkle tree proof
     * @param claimToAddr Destination Eth address to credit Spades to
     * @param pubKeyX First  half of uncompressed ECDSA public key for the BTC address
     * @param pubKeyY Second half of uncompressed ECDSA public key for the BTC address
     * @param claimFlags Claim flags specifying address and message formats
     * @param v v parameter of ECDSA signature
     * @param r r parameter of ECDSA signature
     * @param s s parameter of ECDSA signature
     * @param autoStakeDays Number of days to auto-stake, subject to minimum auto-stake days
     * @param referrerAddr Eth address of referring user (optional; 0x0 for no referrer)
     * @return Total number of Spades credited, if successful
     */
    function btcAddressClaim(
        uint256 rawSatoshis,
        bytes32[] calldata proof,
        address claimToAddr,
        bytes32 pubKeyX,
        bytes32 pubKeyY,
        uint8 claimFlags,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint256 autoStakeDays,
        address referrerAddr
    )
        external
        returns (uint256)
    {
        /* Sanity check */
        require(rawSatoshis <= MAX_BTC_ADDR_BALANCE_SATOSHIS, "OCT: CHK: rawSatoshis");

        /* Enforce the minimum stake time for the auto-stake from this claim */
        require(autoStakeDays >= MIN_AUTO_STAKE_DAYS, "OCT: autoStakeDays lower than minimum");

        /* Ensure signature matches the claim message containing the Eth address and claimParamHash */
        {
            bytes32 claimParamHash = 0;

            if (claimToAddr != msg.sender) {
                /* Claimer did not send this, so claim params must be signed */
                claimParamHash = keccak256(
                    abi.encodePacked(MERKLE_TREE_ROOT, autoStakeDays, referrerAddr)
                );
            }

            require(
                claimMessageMatchesSignature(
                    claimToAddr,
                    claimParamHash,
                    pubKeyX,
                    pubKeyY,
                    claimFlags,
                    v,
                    r,
                    s
                ),
                "OCT: Signature mismatch"
            );
        }

        /* Derive BTC address from public key */
        bytes20 btcAddr = pubKeyToBtcAddress(pubKeyX, pubKeyY, claimFlags);

        /* Ensure BTC address has not yet been claimed */
        require(!btcAddressClaims[btcAddr], "OCT: BTC address balance already claimed");

        /* Ensure BTC address is part of the Merkle tree */
        require(
            _btcAddressIsValid(btcAddr, rawSatoshis, proof),
            "OCT: BTC address or balance unknown"
        );

        /* Mark BTC address as claimed */
        btcAddressClaims[btcAddr] = true;

        return _satoshisClaimSync(
            rawSatoshis,
            claimToAddr,
            btcAddr,
            claimFlags,
            autoStakeDays,
            referrerAddr
        );
    }

    function _satoshisClaimSync(
        uint256 rawSatoshis,
        address claimToAddr,
        bytes20 btcAddr,
        uint8 claimFlags,
        uint256 autoStakeDays,
        address referrerAddr
    )
        private
        returns (uint256 totalClaimedSpades)
    {
        GlobalsCache memory g;
        GlobalsCache memory gSnapshot;
        _globalsLoad(g, gSnapshot);

        totalClaimedSpades = _satoshisClaim(
            g,
            rawSatoshis,
            claimToAddr,
            btcAddr,
            claimFlags,
            autoStakeDays,
            referrerAddr
        );

        _globalsSync(g, gSnapshot);

        return totalClaimedSpades;
    }

    /**
     * @dev Credit an Eth address with the Spades value of a raw Satoshis balance
     * @param g Cache of stored globals
     * @param rawSatoshis Raw BTC address balance in Satoshis
     * @param claimToAddr Destination Eth address for the claimed Spades to be sent
     * @param btcAddr Bitcoin address (binary; no base58-check encoding)
     * @param autoStakeDays Number of days to auto-stake, subject to minimum auto-stake days
     * @param referrerAddr Eth address of referring user (optional; 0x0 for no referrer)
     * @return Total number of Spades credited, if successful
     */
    function _satoshisClaim(
        GlobalsCache memory g,
        uint256 rawSatoshis,
        address claimToAddr,
        bytes20 btcAddr,
        uint8 claimFlags,
        uint256 autoStakeDays,
        address referrerAddr
    )
        private
        returns (uint256 totalClaimedSpades)
    {
        /* Allowed only during the claim phase */
        require(g._currentDay >= CLAIM_PHASE_START_DAY, "OCT: Claim phase has not yet started");
        require(g._currentDay < CLAIM_PHASE_END_DAY, "OCT: Claim phase has ended");

        /* Check if log data needs to be updated */
        _dailyDataUpdateAuto(g);

        /* Sanity check */
        require(
            g._claimedBtcAddrCount < CLAIMABLE_BTC_ADDR_COUNT,
            "OCT: CHK: _claimedBtcAddrCount"
        );

        (uint256 adjSatoshis, uint256 claimedSpades, uint256 claimBonusSpades) = _calcClaimValues(
            g,
            rawSatoshis
        );

        /* Increment claim count to track viral rewards */
        g._claimedBtcAddrCount++;

        totalClaimedSpades = _remitBonuses(
            claimToAddr,
            btcAddr,
            claimFlags,
            rawSatoshis,
            adjSatoshis,
            claimedSpades,
            claimBonusSpades,
            referrerAddr
        );

        /* Auto-stake a percentage of the successful claim */
        uint256 autoStakeSpades = totalClaimedSpades * AUTO_STAKE_CLAIM_PERCENT / 100;
        _stakeStart(g, autoStakeSpades, autoStakeDays, true);

        /* Mint remaining claimed Spades to claim address */
        _mint(claimToAddr, totalClaimedSpades - autoStakeSpades);

        return totalClaimedSpades;
    }

    function _remitBonuses(
        address claimToAddr,
        bytes20 btcAddr,
        uint8 claimFlags,
        uint256 rawSatoshis,
        uint256 adjSatoshis,
        uint256 claimedSpades,
        uint256 claimBonusSpades,
        address referrerAddr
    )
        private
        returns (uint256 totalClaimedSpades)
    {
        totalClaimedSpades = claimedSpades + claimBonusSpades;

        uint256 originBonusSpades = claimBonusSpades;

        if (referrerAddr == address(0)) {
            /* No referrer */
            _emitClaim(
                claimToAddr,
                btcAddr,
                claimFlags,
                rawSatoshis,
                adjSatoshis,
                totalClaimedSpades,
                referrerAddr
            );
        } else {
            /* Referral bonus of 10% of total claimed Spades to claimer */
            uint256 referralBonusSpades = totalClaimedSpades / 10;

            totalClaimedSpades += referralBonusSpades;

            /* Then a cumulative referrer bonus of 20% to referrer */
            uint256 referrerBonusSpades = totalClaimedSpades / 5;

            originBonusSpades += referralBonusSpades + referrerBonusSpades;

            if (referrerAddr == claimToAddr) {
                /* Self-referred */
                totalClaimedSpades += referrerBonusSpades;
                _emitClaim(
                    claimToAddr,
                    btcAddr,
                    claimFlags,
                    rawSatoshis,
                    adjSatoshis,
                    totalClaimedSpades,
                    referrerAddr
                );
            } else {
                /* Referred by different address */
                _emitClaim(
                    claimToAddr,
                    btcAddr,
                    claimFlags,
                    rawSatoshis,
                    adjSatoshis,
                    totalClaimedSpades,
                    referrerAddr
                );
                _mint(referrerAddr, referrerBonusSpades);
            }
        }

        _mint(ORIGIN_ADDR, originBonusSpades);

        return totalClaimedSpades;
    }

    function _emitClaim(
        address claimToAddr,
        bytes20 btcAddr,
        uint8 claimFlags,
        uint256 rawSatoshis,
        uint256 adjSatoshis,
        uint256 claimedSpades,
        address referrerAddr
    )
        private
    {
        emit Claim( // (auto-generated event)
            uint256(uint40(block.timestamp))
                | (uint256(uint56(rawSatoshis)) << 40)
                | (uint256(uint56(adjSatoshis)) << 96)
                | (uint256(claimFlags) << 152)
                | (uint256(uint72(claimedSpades)) << 160),
            uint256(uint160(msg.sender)),
            btcAddr,
            claimToAddr,
            referrerAddr
        );

        if (claimToAddr == msg.sender) {
            return;
        }

        emit ClaimAssist( // (auto-generated event)
            uint256(uint40(block.timestamp))
                | (uint256(uint160(btcAddr)) << 40)
                | (uint256(uint56(rawSatoshis)) << 200),
            uint256(uint56(adjSatoshis))
                | (uint256(uint160(claimToAddr)) << 56)
                | (uint256(claimFlags) << 216),
            uint256(uint72(claimedSpades))
                | (uint256(uint160(referrerAddr)) << 72),
            msg.sender
        );
    }

    function _calcClaimValues(GlobalsCache memory g, uint256 rawSatoshis)
        private
        pure
        returns (uint256 adjSatoshis, uint256 claimedSpades, uint256 claimBonusSpades)
    {
        /* Apply Silly Whale reduction */
        adjSatoshis = _adjustSillyWhale(rawSatoshis);
        require(
            g._claimedSatoshisTotal + adjSatoshis <= CLAIMABLE_SATOSHIS_TOTAL,
            "OCT: CHK: _claimedSatoshisTotal"
        );
        g._claimedSatoshisTotal += adjSatoshis;

        uint256 daysRemaining = CLAIM_PHASE_END_DAY - g._currentDay;

        /* Apply late-claim reduction */
        adjSatoshis = _adjustLateClaim(adjSatoshis, daysRemaining);
        g._unclaimedSatoshisTotal -= adjSatoshis;

        /* Convert to Spades and calculate speed bonus */
        claimedSpades = adjSatoshis * SPADES_PER_SATOSHI;
        claimBonusSpades = _calcSpeedBonus(claimedSpades, daysRemaining);

        return (adjSatoshis, claimedSpades, claimBonusSpades);
    }

    /**
     * @dev Apply Silly Whale adjustment
     * @param rawSatoshis Raw BTC address balance in Satoshis
     * @return Adjusted BTC address balance in Satoshis
     */
    function _adjustSillyWhale(uint256 rawSatoshis)
        private
        pure
        returns (uint256)
    {
        if (rawSatoshis < 1000e8) {
            /* For < 1,000 BTC: no penalty */
            return rawSatoshis;
        }
        if (rawSatoshis >= 10000e8) {
            /* For >= 10,000 BTC: penalty is 75%, leaving 25% */
            return rawSatoshis / 4;
        }
        /*
            For 1,000 <= BTC < 10,000: penalty scales linearly from 50% to 75%

            penaltyPercent  = (btc - 1000) / (10000 - 1000) * (75 - 50) + 50
                            = (btc - 1000) / 9000 * 25 + 50
                            = (btc - 1000) / 360 + 50

            appliedPercent  = 100 - penaltyPercent
                            = 100 - ((btc - 1000) / 360 + 50)
                            = 100 - (btc - 1000) / 360 - 50
                            = 50 - (btc - 1000) / 360
                            = (18000 - (btc - 1000)) / 360
                            = (18000 - btc + 1000) / 360
                            = (19000 - btc) / 360

            adjustedBtc     = btc * appliedPercent / 100
                            = btc * ((19000 - btc) / 360) / 100
                            = btc * (19000 - btc) / 36000

            adjustedSat     = 1e8 * adjustedBtc
                            = 1e8 * (btc * (19000 - btc) / 36000)
                            = 1e8 * ((sat / 1e8) * (19000 - (sat / 1e8)) / 36000)
                            = 1e8 * (sat / 1e8) * (19000 - (sat / 1e8)) / 36000
                            = (sat / 1e8) * 1e8 * (19000 - (sat / 1e8)) / 36000
                            = (sat / 1e8) * (19000e8 - sat) / 36000
                            = sat * (19000e8 - sat) / 36000e8
        */
        return rawSatoshis * (19000e8 - rawSatoshis) / 36000e8;
    }

    /**
     * @dev Apply late-claim adjustment to scale claim to zero by end of claim phase
     * @param adjSatoshis Adjusted BTC address balance in Satoshis (after Silly Whale)
     * @param daysRemaining Number of reward days remaining in claim phase
     * @return Adjusted BTC address balance in Satoshis (after Silly Whale and Late-Claim)
     */
    function _adjustLateClaim(uint256 adjSatoshis, uint256 daysRemaining)
        private
        pure
        returns (uint256)
    {
        /*
            Only valid from CLAIM_PHASE_DAYS to 1, and only used during that time.

            adjustedSat = sat * (daysRemaining / CLAIM_PHASE_DAYS) * 100%
                        = sat *  daysRemaining / CLAIM_PHASE_DAYS
        */
        return adjSatoshis * daysRemaining / CLAIM_PHASE_DAYS;
    }

    /**
     * @dev Calculates speed bonus for claiming earlier in the claim phase
     * @param claimedSpades Spades claimed from adjusted BTC address balance Satoshis
     * @param daysRemaining Number of claim days remaining in claim phase
     * @return Speed bonus in Spades
     */
    function _calcSpeedBonus(uint256 claimedSpades, uint256 daysRemaining)
        private
        pure
        returns (uint256)
    {
        /*
            Only valid from CLAIM_PHASE_DAYS to 1, and only used during that time.
            Speed bonus is 20% ... 0% inclusive.

            bonusSpades = claimedSpades  * ((daysRemaining - 1)  /  (CLAIM_PHASE_DAYS - 1)) * 20%
                        = claimedSpades  * ((daysRemaining - 1)  /  (CLAIM_PHASE_DAYS - 1)) * 20/100
                        = claimedSpades  * ((daysRemaining - 1)  /  (CLAIM_PHASE_DAYS - 1)) / 5
                        = claimedSpades  *  (daysRemaining - 1)  / ((CLAIM_PHASE_DAYS - 1)  * 5)
        */
        return claimedSpades * (daysRemaining - 1) / ((CLAIM_PHASE_DAYS - 1) * 5);
    }
}
