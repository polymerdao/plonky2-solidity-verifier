import "@nomicfoundation/hardhat-toolbox";
import "hardhat-gas-reporter"

module.exports = {
    networks: {
        hardhat: {
            gas: 3000000000000000,
            allowUnlimitedContractSize: true,
        },
    },
    solidity: {
        version: "0.8.9",
        settings: {
            optimizer: {
                enabled: true,
            },
        },
    },
    gasReporter: {
        enabled: true
    },
    mocha: {
        timeout: 200000
    },
}
