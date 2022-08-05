import {expect} from "chai";
import {ethers} from "hardhat";

describe("Verifier", function () {
    describe("Verify", function () {
        it("Should verify the proof", async function () {
            const Verifier = await ethers.getContractFactory("Plonky2Verifier");
            const verifier = await Verifier.deploy();

            await expect(verifier.verify(), "");
        });
    });
});
