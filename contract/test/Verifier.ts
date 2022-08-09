import {expect} from "chai";
import {ethers} from "hardhat";

const proof = require("./data/proof.json");

describe("Verifier", function () {
    describe("Verify", function () {
        it("Should verify the proof", async function () {
            const Verifier = await ethers.getContractFactory("Plonky2Verifier");
            const verifier = await Verifier.deploy();

            const view = Buffer.from(proof[0], 'base64');
            console.log("proof size: " + view.length);
            expect(await verifier.verify(Array.from(view))).to.equal(true);
        });
    });
});
