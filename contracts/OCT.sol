pragma solidity 0.5.13;

import "./TransformableToken.sol";


contract OCT is TransformableToken {
    constructor()
        public
    {
        /* Initialize global shareRate to 1 */
        globals.shareRate = uint40(1 * SHARE_RATE_SCALE);

        /* Initialize dailyDataCount to skip pre-claim period */
        globals.dailyDataCount = uint16(PRE_CLAIM_DAYS);

        /* Add all Satoshis from UTXO snapshot to contract */
        globals.claimStats = _claimStatsEncode(
            0, // _claimedBtcAddrCount
            0, // _claimedSatoshisTotal
            FULL_SATOSHIS_TOTAL // _unclaimedSatoshisTotal
        );
    }

    function() external payable {}
}