const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying BlackBoxBazaar with account:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");

  const Bazaar = await ethers.getContractFactory("BlackBoxBazaar");
  const bazaar = await Bazaar.deploy();
  await bazaar.waitForDeployment();

  const address = await bazaar.getAddress();
  const net = await ethers.provider.getNetwork();
  console.log("BlackBoxBazaar deployed to:", address);
  console.log("Chain ID:", net.chainId.toString());
  console.log("Paste this address into the frontend's 'Deployed BlackBoxBazaar address' field.");
  console.log("Verify with:");
  console.log(`  npx hardhat verify --network baseSepolia ${address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
