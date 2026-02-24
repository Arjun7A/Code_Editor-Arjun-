require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

const rpcUrl = process.env.SEPOLIA_RPC_URL || "";
const privateKey = (process.env.BLOCKCHAIN_PRIVATE_KEY || "").trim();
const accounts = privateKey
  ? [privateKey.startsWith("0x") ? privateKey : `0x${privateKey}`]
  : [];

/** @type import("hardhat/config").HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {},
    sepolia: {
      url: rpcUrl,
      accounts,
      chainId: 11155111,
    },
  },
};
