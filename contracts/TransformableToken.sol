pragma solidity 0.5.13;

import "./UTXORedeemableToken.sol";


contract TransformableToken is UTXORedeemableToken {
    /**
     * @dev PUBLIC FACING: Enter the tranform lobby for the current round
     * @param referrerAddr Eth address of referring user (optional; 0x0 for no referrer)
     */
    function xfLobbyEnter(address referrerAddr)
        external
        payable
    {
        uint256 enterDay = _currentDay();
        require(enterDay < CLAIM_PHASE_END_DAY, "OCT: Lobbies have ended");

        uint256 rawAmount = msg.value;
        require(rawAmount != 0, "OCT: Amount required");

        XfLobbyQueueStore storage qRef = xfLobbyMembers[enterDay][msg.sender];

        uint256 entryIndex = qRef.tailIndex++;

        qRef.entries[entryIndex] = XfLobbyEntryStore(uint96(rawAmount), referrerAddr);

        xfLobby[enterDay] += rawAmount;

        _emitXfLobbyEnter(enterDay, entryIndex, rawAmount, referrerAddr);
    }

    /**
     * @dev PUBLIC FACING: Leave the transform lobby after the round is complete
     * @param enterDay Day number when the member entered
     * @param count Number of queued-enters to exit (optional; 0 for all)
     */
    function xfLobbyExit(uint256 enterDay, uint256 count)
        external
    {
        require(enterDay < _currentDay(), "OCT: Round is not complete");

        XfLobbyQueueStore storage qRef = xfLobbyMembers[enterDay][msg.sender];

        uint256 headIndex = qRef.headIndex;
        uint256 endIndex;

        if (count != 0) {
            require(count <= qRef.tailIndex - headIndex, "OCT: count invalid");
            endIndex = headIndex + count;
        } else {
            endIndex = qRef.tailIndex;
            require(headIndex < endIndex, "OCT: count invalid");
        }

        uint256 waasLobby = _waasLobby(enterDay);
        uint256 _xfLobby = xfLobby[enterDay];
        uint256 totalXfAmount = 0;
        uint256 originBonusSpades = 0;

        do {
            uint256 rawAmount = qRef.entries[headIndex].rawAmount;
            address referrerAddr = qRef.entries[headIndex].referrerAddr;

            delete qRef.entries[headIndex];

            uint256 xfAmount = waasLobby * rawAmount / _xfLobby;

            if (referrerAddr == address(0)) {
                /* No referrer */
                _emitXfLobbyExit(enterDay, headIndex, xfAmount, referrerAddr);
            } else {
                /* Referral bonus of 10% of xfAmount to member */
                uint256 referralBonusSpades = xfAmount / 10;

                xfAmount += referralBonusSpades;

                /* Then a cumulative referrer bonus of 20% to referrer */
                uint256 referrerBonusSpades = xfAmount / 5;

                if (referrerAddr == msg.sender) {
                    /* Self-referred */
                    xfAmount += referrerBonusSpades;
                    _emitXfLobbyExit(enterDay, headIndex, xfAmount, referrerAddr);
                } else {
                    /* Referred by different address */
                    _emitXfLobbyExit(enterDay, headIndex, xfAmount, referrerAddr);
                    _mint(referrerAddr, referrerBonusSpades);
                }
                originBonusSpades += referralBonusSpades + referrerBonusSpades;
            }

            totalXfAmount += xfAmount;
        } while (++headIndex < endIndex);

        qRef.headIndex = uint40(headIndex);

        if (originBonusSpades != 0) {
            _mint(ORIGIN_ADDR, originBonusSpades);
        }
        if (totalXfAmount != 0) {
            _mint(msg.sender, totalXfAmount);
        }
    }

    /**
     * @dev PUBLIC FACING: Release any value that has been sent to the contract
     */
    function xfLobbyFlush()
        external
    {
        require(address(this).balance != 0, "OCT: No value");

        FLUSH_ADDR.transfer(address(this).balance);
    }

    /**
     * @dev PUBLIC FACING: External helper to return multiple values of xfLobby[] with
     * a single call
     * @param beginDay First day of data range
     * @param endDay Last day (non-inclusive) of data range
     * @return Fixed array of values
     */
    function xfLobbyRange(uint256 beginDay, uint256 endDay)
        external
        view
        returns (uint256[] memory list)
    {
        require(
            beginDay < endDay && endDay <= CLAIM_PHASE_END_DAY && endDay <= _currentDay(),
            "OCT: invalid range"
        );

        list = new uint256[](endDay - beginDay);

        uint256 src = beginDay;
        uint256 dst = 0;
        do {
            list[dst++] = uint256(xfLobby[src++]);
        } while (src < endDay);

        return list;
    }

    /**
     * @dev PUBLIC FACING: Return a current lobby member queue entry.
     * Only needed due to limitations of the standard ABI encoder.
     * @param memberAddr Eth address of the lobby member
     * @param entryId 49 bit compound value. Top 9 bits: enterDay, Bottom 40 bits: entryIndex
     * @return 1: Raw amount that was entered with; 2: Referring Eth addr (optional; 0x0 for no referrer)
     */
    function xfLobbyEntry(address memberAddr, uint256 entryId)
        external
        view
        returns (uint256 rawAmount, address referrerAddr)
    {
        uint256 enterDay = entryId >> XF_LOBBY_ENTRY_INDEX_SIZE;
        uint256 entryIndex = entryId & XF_LOBBY_ENTRY_INDEX_MASK;

        XfLobbyEntryStore storage entry = xfLobbyMembers[enterDay][memberAddr].entries[entryIndex];

        require(entry.rawAmount != 0, "OCT: Param invalid");

        return (entry.rawAmount, entry.referrerAddr);
    }

    /**
     * @dev PUBLIC FACING: Return the lobby days that a user is in with a single call
     * @param memberAddr Eth address of the user
     * @return Bit vector of lobby day numbers
     */
    function xfLobbyPendingDays(address memberAddr)
        external
        view
        returns (uint256[XF_LOBBY_DAY_WORDS] memory words)
    {
        uint256 day = _currentDay() + 1;

        if (day > CLAIM_PHASE_END_DAY) {
            day = CLAIM_PHASE_END_DAY;
        }

        while (day-- != 0) {
            if (xfLobbyMembers[day][memberAddr].tailIndex > xfLobbyMembers[day][memberAddr].headIndex) {
                words[day >> 8] |= 1 << (day & 255);
            }
        }

        return words;
    }

    function _waasLobby(uint256 enterDay)
        private
        returns (uint256 waasLobby)
    {
        if (enterDay >= CLAIM_PHASE_START_DAY) {
            GlobalsCache memory g;
            GlobalsCache memory gSnapshot;
            _globalsLoad(g, gSnapshot);

            _dailyDataUpdateAuto(g);

            uint256 unclaimed = dailyData[enterDay].dayUnclaimedSatoshisTotal;
            waasLobby = unclaimed * SPADES_PER_SATOSHI / CLAIM_PHASE_DAYS;

            _globalsSync(g, gSnapshot);
        } else {
            waasLobby = WAAS_LOBBY_SEED_SPADES;
        }
        return waasLobby;
    }

    function _emitXfLobbyEnter(
        uint256 enterDay,
        uint256 entryIndex,
        uint256 rawAmount,
        address referrerAddr
    )
        private
    {
        emit XfLobbyEnter( // (auto-generated event)
            uint256(uint40(block.timestamp))
                | (uint256(uint96(rawAmount)) << 40),
            msg.sender,
            (enterDay << XF_LOBBY_ENTRY_INDEX_SIZE) | entryIndex,
            referrerAddr
        );
    }

    function _emitXfLobbyExit(
        uint256 enterDay,
        uint256 entryIndex,
        uint256 xfAmount,
        address referrerAddr
    )
        private
    {
        emit XfLobbyExit( // (auto-generated event)
            uint256(uint40(block.timestamp))
                | (uint256(uint72(xfAmount)) << 40),
            msg.sender,
            (enterDay << XF_LOBBY_ENTRY_INDEX_SIZE) | entryIndex,
            referrerAddr
        );
    }
}
