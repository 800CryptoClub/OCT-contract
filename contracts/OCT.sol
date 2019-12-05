pragma solidity ^0.5.7;

import "./StakeableToken.sol";


contract OCT is StakeableToken {
    constructor()
        public
    {
        /* Add all Satoshis from UTXO snapshot to contract */
        globals.unclaimedSatoshisTotal = uint64(FULL_SATOSHIS_TOTAL);
        _mint(address(this), FULL_SATOSHIS_TOTAL * SPADES_PER_SATOSHI);
    }

    /**
     * @dev PUBLIC FACING: Contract fallback function
     */
    function()
        external
        payable
    {
        /* Empty */
    }

    /**
     * @dev PUBLIC FACING: Release any ETH that has been sent to the contract
     */
    function flushTrappedEth()
        external
    {
        require(address(this).balance != 0, "OCT: No trapped ETH");

        TRAPPED_ETH_FLUSH_ADDR.transfer(address(this).balance);
    }
}
