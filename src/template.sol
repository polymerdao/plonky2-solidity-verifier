// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// Import this file to use console.log
import "hardhat/console.sol";

contract Plonky2Verifier {
    bytes32 constant sigmas_cap = $SIGMA_CAP;

    function verify() public view {
        console.logBytes32(sigmas_cap);
    }
}
