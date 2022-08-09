import "@nomicfoundation/hardhat-toolbox";
import "hardhat-gas-reporter"

module.exports = {
    solidity: {
        version: "0.8.9",
        settings: {
            optimizer: {
                enabled: false,
            },
        },
    },
    gasReporter: {
        enabled: true
    }
}
