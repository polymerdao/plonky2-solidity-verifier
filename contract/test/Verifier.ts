import {expect} from "chai";
import {ethers} from "hardhat";
import {Plonky2Verifier} from "../typechain-types";

const proof = require("./data/proof.json");
const conf = require("./data/conf.json")

describe("Verifier", function () {
    describe("Verify", function () {
        it("Should verify the proof", async function () {
            const Verifier = await ethers.getContractFactory("Plonky2Verifier");
            const verifier = await Verifier.deploy();

            const buf = Buffer.from(proof[0], 'base64');
            console.log("proof size: " + buf.length);



            let verifier_input: Plonky2Verifier.ProofStruct = {
                wires_cap: [Buffer.from(proof.wires_cap, 'base64')],
                plonk_zs_partial_products_cap: [Buffer.from(proof.plonk_zs_partial_products_cap, 'base64')],
                quotient_polys_cap: [Buffer.from(proof.quotient_polys_cap, 'base64')],
                rest_bytes: Array.from(Buffer.from(proof.rest_bytes, 'base64')),//[Buffer.from(proof.rest_bytes, 'base64')],
            };
            expect(await verifier.verify(verifier_input)).to.equal(true);
        });
    });
});
