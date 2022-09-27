// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./Challenger.sol";

contract TestChallenger {
    using ChallengerLib for ChallengerLib.Challenger;
    function observe_uint64(ChallengerLib.Challenger memory challenger, uint64 num) internal pure {
        challenger.observe_element(ChallengerLib.elementToLeBytes(num));
    }

    function test_challenger() external {
        ChallengerLib.Challenger memory challenger;

        observe_uint64(challenger, 8917524657281059100);
        observe_uint64(challenger, 13029010200779371910);
        observe_uint64(challenger, 16138660518493481604);
        observe_uint64(challenger, 17277322750214136960);
        observe_uint64(challenger, 1441151880423231822);

        uint64[] memory nums = challenger.get_challenges(4);
        require(nums[0] == 10556094283316);
        require(nums[1] == 2969885698010629776);
        require(nums[2] == 891839585018115537);
        require(nums[3] == 6951606774775366384);
    }
}
