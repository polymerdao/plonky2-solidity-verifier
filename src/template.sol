// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// Import this file to use console.log
import "hardhat/console.sol";

contract Plonky2Verifier {
    uint256 constant SIGMAS_CAP_COUNT = $SIGMA_CAP_COUNT;

    function get_sigma_cap() internal pure returns(bytes32[SIGMAS_CAP_COUNT] memory sc) {
        $SET_SIGMA_CAP;
    }

    function verify() public view {
        bytes32[SIGMAS_CAP_COUNT] memory sc = get_sigma_cap();
        console.logBytes32(sc[0]);
        console.logBytes32(sc[SIGMAS_CAP_COUNT-1]);
    }
}
