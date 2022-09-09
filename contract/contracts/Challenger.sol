// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

library ChallengerLib {
    uint32 constant SPONGE_RATE = 8;
    uint32 constant SPONGE_CAPACITY = 4;
    uint32 constant SPONGE_WIDTH = 12;

    struct Challenger {
        bytes8[] input_buf;
        bytes8[] output_buf;
        bytes8[SPONGE_WIDTH] sponge_state;
    }

    function reverse(uint64 input) internal pure returns (uint64 v) {
        v = input;

        // swap bytes
        v = ((v & 0xFF00FF00FF00FF00) >> 8) |
        ((v & 0x00FF00FF00FF00FF) << 8);

        // swap 2-byte long pairs
        v = ((v & 0xFFFF0000FFFF0000) >> 16) |
        ((v & 0x0000FFFF0000FFFF) << 16);

        // swap 4-byte long pairs
        v = (v >> 32) | (v << 32);
    }

    function elementToLeBytes(uint64 input) internal pure returns (bytes8 res) {
        res = bytes8(input >> 56) & 0x00000000000000FF;
        res = res | (bytes8(input >> 40) & 0x000000000000FF00);
        res = res | (bytes8(input >> 24) & 0x0000000000FF0000);
        res = res | (bytes8(input >> 8) & 0x00000000FF000000);
        res = res | (bytes8(input << 8) & 0x000000FF00000000);
        res = res | (bytes8(input << 24) & 0x0000FF0000000000);
        res = res | (bytes8(input << 40) & 0x00FF000000000000);
        res = res | (bytes8(input << 56) & 0xFF00000000000000);
        return res;
    }

    function toBytes8(bytes memory _bytes, uint256 _start) internal pure returns (bytes8) {
        require(_bytes.length >= _start + 8, "toBytes8_outOfBounds");
        bytes8 tempBytes8;

        assembly {
            tempBytes8 := mload(add(add(_bytes, 0x20), _start))
        }

        return tempBytes8;
    }

    function keccak_permutation(bytes8[SPONGE_WIDTH] memory input) internal pure returns (bytes8[SPONGE_WIDTH] memory res) {
        bytes32 h = keccak256(abi.encodePacked(input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
            input[8], input[9], input[10], input[11]));
        bytes32 hh = keccak256(abi.encodePacked(h));
        bytes32 hhh = keccak256(abi.encodePacked(hh));
        bytes memory tmp = abi.encodePacked(h, hh, hhh);
        uint8 pos = 0;

        for (uint i = 0; i < SPONGE_WIDTH * 8; i = i + 8) {
            bytes8 b = toBytes8(tmp, i);
            // check bytes in the field order (little endian)
            if ((b & 0x00000000FFFFFFFF) != 0x00000000FFFFFFFF) {
                res[pos++] = b;
            }
        }

        return res;
    }

    function duplexing(Challenger memory challenger) internal pure {
        require(challenger.input_buf.length <= SPONGE_RATE);
        for (uint i = 0; i < challenger.input_buf.length; i++) {
            challenger.sponge_state[i] = challenger.input_buf[i];
        }
        delete challenger.input_buf;
        challenger.sponge_state = keccak_permutation(challenger.sponge_state);
        delete challenger.output_buf;
        challenger.output_buf = new bytes8[](SPONGE_RATE);
        for (uint i = 0; i < SPONGE_RATE; i++) {
            challenger.output_buf[i] = challenger.sponge_state[i];
        }
    }

    function observe_element(Challenger memory challenger, bytes8 element) internal pure {
        delete challenger.output_buf;
        bytes8[] memory input = new bytes8[](challenger.input_buf.length + 1);
        for (uint32 i = 0; i < input.length - 1; i++) {
            input[i] = challenger.input_buf[i];
        }
        input[input.length - 1] = element;
        delete challenger.input_buf;
        challenger.input_buf = input;
        if (challenger.input_buf.length == SPONGE_RATE) {
            duplexing(challenger);
        }
    }

    function observe_extension(Challenger memory challenger, bytes16 ext) internal pure {
        bytes8 element = bytes8(ext);
        observe_element(challenger, element);
        element = bytes8(ext << 64);
        observe_element(challenger, element);
    }

    function observe_hash(Challenger memory challenger, bytes25 hash) internal pure {
        bytes8 b0 = bytes8(hash);
        bytes8 b1 = bytes8(hash << 56);
        bytes8 b2 = bytes8(hash << 112);
        bytes8 b3 = bytes8(hash << 168);
        b0 = b0 & 0xFFFFFFFFFFFFFF00;
        b1 = b1 & 0xFFFFFFFFFFFFFF00;
        b2 = b2 & 0xFFFFFFFFFFFFFF00;
        b3 = b3 & 0xFFFFFFFF00000000;

        observe_element(challenger, b0);
        observe_element(challenger, b1);
        observe_element(challenger, b2);
        observe_element(challenger, b3);
    }

    function get_challenge(Challenger memory challenger) internal pure returns (uint64 res) {
        if (challenger.input_buf.length > 0 || challenger.output_buf.length == 0) {
            duplexing(challenger);
        }
        res = reverse(uint64(challenger.output_buf[challenger.output_buf.length - 1]));
        bytes8[] memory output = new bytes8[](challenger.output_buf.length - 1);
        for (uint32 i = 0; i < output.length; i++) {
            output[i] = challenger.output_buf[i];
        }
        delete challenger.output_buf;
        challenger.output_buf = output;
        return res;
    }

    function get_challenges(Challenger memory challenger, uint32 num) internal pure returns (uint64[] memory) {
        uint64[] memory res = new uint64[](num);
        for (uint i = 0; i < num; i++) {
            res[i] = get_challenge(challenger);
        }
        return res;
    }

    function get_extension_challenge(Challenger memory challenger) internal pure returns (uint64[2] memory res) {
        res[0] = get_challenge(challenger);
        res[1] = get_challenge(challenger);
    }
}
