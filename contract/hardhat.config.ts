import "@nomicfoundation/hardhat-toolbox";
import "hardhat-gas-reporter"

module.exports = {
    networks: {
        hardhat: {
            allowUnlimitedContractSize: true,
            blockGasLimit: 3000000000,
            gas: 300000000,
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
