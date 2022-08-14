import {expect} from "chai";
import {ethers} from "hardhat";
import {Plonky2Verifier} from "../typechain-types";

const proof = require("./data/proof.json");
const conf = require("./data/conf.json")

function deserialize_vec(buf: Buffer, size: number) {
    let res = [];
    let pos = 0;
    while (pos < buf.length) {
        res.push(buf.subarray(pos, pos + size));
        pos += size;
    }
    console.assert(pos == buf.length);
    return res;
}

describe("Verifier", function () {
    describe("Verify", function () {
        it("Should verify the proof", async function () {
            const Verifier = await ethers.getContractFactory("Plonky2Verifier");
            const verifier = await Verifier.deploy();

            const buf = Buffer.from(proof[0], 'base64');
            console.log("proof size: " + buf.length);

            let pos = 0;
            let wires_cap_size = conf.num_wires_cap * conf.hash_size;
            let wires_cap = deserialize_vec(buf.subarray(pos, pos + wires_cap_size), conf.hash_size);
            pos += wires_cap_size;

            let plonk_zs_partial_products_cap_size = conf.num_plonk_zs_partial_products_cap * conf.hash_size;
            let plonk_zs_partial_products_cap = deserialize_vec(buf.subarray(pos, pos + plonk_zs_partial_products_cap_size), conf.hash_size);
            pos += plonk_zs_partial_products_cap_size;

            let quotient_polys_cap_size = conf.num_quotient_polys_cap * conf.hash_size;
            let quotient_polys_cap = deserialize_vec(buf.subarray(pos, pos + quotient_polys_cap_size), conf.hash_size);
            pos += quotient_polys_cap_size;

            let openings_constants_size = conf.num_openings_constants * conf.ext_field_size;
            let openings_constants = deserialize_vec(buf.subarray(pos, pos + openings_constants_size), conf.ext_field_size);
            pos += openings_constants_size;

            let openings_plonk_sigmas_size = conf.num_openings_plonk_sigmas * conf.ext_field_size;
            let openings_plonk_sigmas = deserialize_vec(buf.subarray(pos, pos + openings_plonk_sigmas_size), conf.ext_field_size);
            pos += openings_plonk_sigmas_size;

            let openings_wires_size = conf.num_openings_wires * conf.ext_field_size;
            let openings_wires = deserialize_vec(buf.subarray(pos, pos + openings_wires_size), conf.ext_field_size);
            pos += openings_wires_size;

            let openings_plonk_zs_size = conf.num_openings_plonk_zs * conf.ext_field_size;
            let openings_plonk_zs = deserialize_vec(buf.subarray(pos, pos + openings_plonk_zs_size), conf.ext_field_size);
            pos += openings_plonk_zs_size;

            let openings_plonk_zs_next_size = conf.num_openings_plonk_zs_next * conf.ext_field_size;
            let openings_plonk_zs_next = deserialize_vec(buf.subarray(pos, pos + openings_plonk_zs_next_size), conf.ext_field_size);
            pos += openings_plonk_zs_next_size;

            let openings_partial_products_size = conf.num_openings_partial_products * conf.ext_field_size;
            let openings_partial_products = deserialize_vec(buf.subarray(pos, pos + openings_partial_products_size), conf.ext_field_size);
            pos += openings_partial_products_size;

            let openings_quotient_polys_size = conf.num_openings_quotient_polys * conf.ext_field_size;
            let openings_quotient_polys = deserialize_vec(buf.subarray(pos, pos + openings_quotient_polys_size), conf.ext_field_size);
            pos += openings_quotient_polys_size;

            let input: Plonky2Verifier.ProofStruct = {
                wires_cap: [wires_cap[0]],
                plonk_zs_partial_products_cap: [plonk_zs_partial_products_cap[0]],
                quotient_polys_cap: [quotient_polys_cap[0]],
                openings_constants: [openings_constants[0], openings_constants[1],
                    openings_constants[2], openings_constants[3], openings_constants[4]],
                openings_plonk_sigmas: openings_plonk_sigmas,
                openings_wires: openings_wires,
                openings_plonk_zs: [openings_plonk_zs[0], openings_plonk_zs[1]],
                openings_plonk_zs_next: [openings_plonk_zs_next[0], openings_plonk_zs_next[1]],
                openings_partial_products: openings_partial_products,
                openings_quotient_polys: openings_quotient_polys,
                rest_bytes: Array.from(buf.subarray(pos, buf.length - pos)),
            };
            expect(await verifier.verify(input)).to.equal(true);
        });
    });
});
