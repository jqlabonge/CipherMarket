const hre = require("hardhat");
const { ethers } = hre;

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

  // --- Post-deployment self-check -----------------------------------
  // This exists specifically because of a real bug class: the frontend
  // silently pointed at an OLD deployment that was missing the
  // isEligibleBuyer() function entirely. Every call to it reverted with
  // "no data present" and looked exactly like a logic bug, even though
  // the Solidity logic itself was correct the whole time. A stale address
  // is a deployment/config mistake, not something a unit test (which
  // always runs against a fresh in-memory deployment) can ever catch --
  // so we check the ACTUAL on-chain bytecode right here, immediately
  // after deploying, and refuse to report success if it's wrong.
  console.log("\nRunning post-deployment self-check...");
  let selfCheckPassed = true;

  try {
    const code = await ethers.provider.getCode(address);
    if (code === "0x" || code.length <= 2) {
      console.log("  FAIL: no bytecode found at the deployed address.");
      selfCheckPassed = false;
    } else {
      console.log(`  OK: contract bytecode present (${(code.length - 2) / 2} bytes).`);
    }

    // Call isEligibleBuyer(0, deployer.address) directly. On a fresh
    // deployment with zero listings this should simply return false -- it
    // must NOT revert. A revert here means this deployment doesn't actually
    // have the eligibility feature, which is exactly the bug that happened.
    // (Deliberately NOT using address(0) here: a nonexistent listing's
    // target defaults to address(0), so checking eligibility for the zero
    // address against it trivially returns true -- zero equals zero, not a
    // real bypass, just a degenerate case. Any real account works instead.)
    const eligible = await bazaar.isEligibleBuyer(0, deployer.address);
    console.log(`  OK: isEligibleBuyer(0, deployer) callable, returned ${eligible} (expected false).`);
    if (eligible !== false) {
      console.log("  FAIL: expected false for a nonexistent listing, got true.");
      selfCheckPassed = false;
    }

    // Sanity-check a couple of other core entry points exist too, so a
    // partial/mismatched deployment can't slip through either.
    const count = await bazaar.listingCount();
    console.log(`  OK: listingCount() callable, returned ${count.toString()} (expected 0 on a fresh deploy).`);
  } catch (e) {
    console.log("  FAIL: self-check call reverted or errored:", e.shortMessage || e.message);
    selfCheckPassed = false;
  }

  if (!selfCheckPassed) {
    console.log("\n!! SELF-CHECK FAILED. Do not use this address in the frontend as-is --");
    console.log("!! something is wrong with this deployment. Re-run this script or investigate above.");
    process.exitCode = 1;
    return;
  }

  console.log("\nSelf-check PASSED. This deployment has the full expected interface.");
  console.log("Paste this address into the frontend's 'Deployed BlackBoxBazaar address' field:");
  console.log(`  ${address}`);
  console.log("\nVerify with:");
  console.log(`  npx hardhat verify --network ${hre.network.name} ${address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
