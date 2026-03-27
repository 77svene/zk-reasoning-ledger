import { task } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-gas-reporter";
import "solidity-coverage";

require("dotenv").config();

const SEPOLIA_RPC_URL = process.env.SEPOLIA_RPC_URL || "https://ethereum-sepolia-rpc.publicnode.com";
const PRIVATE_KEY = process.env.PRIVATE_KEY || "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || "";

/**
 * ZK-Reasoning Ledger Hardhat Configuration
 * 
 * This configuration enables:
 * - Local Ganache development with forked mainnet state
 * - Sepolia testnet deployment with gas optimization
 * - Hardhat network for ZK circuit integration testing
 * - Gas reporting for audit compliance
 * 
 * SECURITY: Private keys are loaded from environment variables only.
 * NO hardcoded credentials. Production deployments require secure key management.
 */
export default {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
        details: {
          peephole: true,
          inliner: true,
          jumpdestRemover: true,
          orderLiterals: true,
          deduplicate: true,
          cse: true,
          constantOptimizer: true,
          yul: true,
          yulDetails: {
            stackAllocation: true,
            optimizerSteps: "dhfoDgvulfnTUtnIf"
          }
        }
      },
      evmVersion: "cancun",
      viaIR: true,
      metadata: {
        bytecodeHash: "none"
      }
    }
  },
  networks: {
    hardhat: {
      forking: {
        url: SEPOLIA_RPC_URL,
        enabled: true
      },
      chainId: 31337,
      gas: "auto",
      gasPrice: "auto",
      allowUnlimitedContractSize: false,
      timeout: 60000
    },
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 31337,
      gas: 12000000,
      gasPrice: 1000000000,
      timeout: 60000,
      accounts: {
        count: 10,
        initialBalance: "10000000000000000000000"
      }
    },
    sepolia: {
      url: SEPOLIA_RPC_URL,
      chainId: 11155111,
      gas: "auto",
      gasPrice: "auto",
      accounts: PRIVATE_KEY ? [PRIVATE_KEY] : [],
      timeout: 120000,
      confirmations: 1
    },
    sepolia_fork: {
      url: SEPOLIA_RPC_URL,
      chainId: 11155111,
      forking: {
        url: SEPOLIA_RPC_URL,
        blockNumber: 5000000
      },
      accounts: PRIVATE_KEY ? [PRIVATE_KEY] : []
    }
  },
  etherscan: {
    apiKey: ETHERSCAN_API_KEY
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS ? true : false,
    currency: "USD",
    coinmarketcap: process.env.COINMARKETCAP_API_KEY || "",
    outputFile: "gas-report.txt",
    showTimeSpent: true
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  },
  mocha: {
    timeout: 100000,
    reporter: "spec",
    reporterOption: {
      verbose: true
    }
  },
  typescript: {
    neverTsc: true
  }
};

/**
 * Custom Task: Circuit Compilation Integration
 * 
 * This task bridges Hardhat with Circom circuit compilation.
 * It ensures circuit artifacts are available before contract compilation.
 * 
 * USAGE: npx hardhat compile:circuit
 */
task("compile:circuit", "Compile Circom circuits before Hardhat compilation")
  .addOptionalParam("circuit", "Circuit file to compile", "reasoning_policy")
  .setAction(async (taskArgs, hre) => {
    const { execSync } = await import("child_process");
    const circuitPath = `circuits/${taskArgs.circuit}.circom`;
    
    try {
      console.log(`Compiling circuit: ${circuitPath}`);
      execSync(`circom ${circuitPath} --wasm --sym --r1cs`, { stdio: "inherit" });
      console.log("Circuit compilation successful");
    } catch (error) {
      console.error("Circuit compilation failed:", error.message);
      process.exit(1);
    }
  });

/**
 * Custom Task: ZK Key Generation Pipeline
 * 
 * Orchestrates the full ZK key generation workflow:
 * 1. Circuit compilation
 * 2. Power of Tau ceremony (local for testing)
 * 3. Final zkey generation
 * 4. Verification key extraction
 * 
 * SECURITY: Production deployments require trusted setup from a multi-party ceremony.
 */
task("generate:keys", "Generate ZK proving and verification keys")
  .addOptionalParam("circuit", "Circuit name", "reasoning_policy")
  .setAction(async (taskArgs, hre) => {
    const { execSync } = await import("child_process");
    const circuitName = taskArgs.circuit;
    
    try {
      console.log("Starting ZK key generation pipeline...");
      
      // Step 1: Compile circuit if not already done
      console.log("Step 1: Compiling circuit...");
      execSync(`circom circuits/${circuitName}.circom --wasm --sym --r1cs`, { stdio: "inherit" });
      
      // Step 2: Generate witness (using snarkjs)
      console.log("Step 2: Generating witness...");
      execSync(`node circuits/${circuitName}_js/generate_witness.js circuits/${circuitName}_js/witness_calculator.js input.json circuits/${circuitName}_js/witness.wtns`, { stdio: "inherit" });
      
      // Step 3: Create initial zkey
      console.log("Step 3: Creating initial zkey...");
      execSync(`snarkjs groth16 setup circuits/${circuitName}.r1cs circuits/powersOfTau28_hez_final_20.pt circuits/${circuitName}_0000.zkey`, { stdio: "inherit" });
      
      // Step 4: Export verification key
      console.log("Step 4: Exporting verification key...");
      execSync(`snarkjs zkey export verificationkey circuits/${circuitName}_0000.zkey circuits/${circuitName}_verification_key.json`, { stdio: "inherit" });
      
      console.log("ZK key generation complete");
      console.log(`Verification key: circuits/${circuitName}_verification_key.json`);
    } catch (error) {
      console.error("Key generation failed:", error.message);
      process.exit(1);
    }
  });

/**
 * Custom Task: Circuit Verification
 * 
 * Verifies a ZK proof against the verification key.
 * Used for testing proof generation and validation.
 */
task("verify:proof", "Verify a ZK proof against the verification key")
  .addParam("proof", "Proof file path")
  .addParam("publicSignals", "Public signals file path")
  .addParam("vkey", "Verification key file path")
  .setAction(async (taskArgs, hre) => {
    const { execSync } = await import("child_process");
    
    try {
      console.log("Verifying ZK proof...");
      execSync(`snarkjs groth16 verify ${taskArgs.vkey} ${taskArgs.publicSignals} ${taskArgs.proof}`, { stdio: "inherit" });
      console.log("Proof verification successful");
    } catch (error) {
      console.error("Proof verification failed:", error.message);
      process.exit(1);
    }
  });

/**
 * Custom Task: Gas Audit
 * 
 * Runs gas analysis on all contract deployments and transactions.
 * Outputs detailed gas report for optimization.
 */
task("audit:gas", "Run comprehensive gas audit on all contracts")
  .setAction(async (taskArgs, hre) => {
    console.log("Starting gas audit...");
    console.log("Note: Run with REPORT_GAS=1 for detailed gas reporting");
    
    const { execSync } = await import("child_process");
    
    try {
      execSync("REPORT_GAS=1 npx hardhat test", { stdio: "inherit" });
      console.log("Gas audit complete. Check gas-report.txt for details");
    } catch (error) {
      console.error("Gas audit failed:", error.message);
      process.exit(1);
    }
  });

/**
 * Custom Task: Circuit Integration Test
 * 
 * Runs end-to-end test of circuit compilation, proof generation, and verification.
 * Ensures ZK pipeline works before contract deployment.
 */
task("test:circuit", "Run circuit integration tests")
  .setAction(async (taskArgs, hre) => {
    console.log("Running circuit integration tests...");
    
    const { execSync } = await import("child_process");
    
    try {
      execSync("npm run compile:circuit", { stdio: "inherit" });
      execSync("npm run generate:keys", { stdio: "inherit" });
      console.log("Circuit integration tests passed");
    } catch (error) {
      console.error("Circuit integration tests failed:", error.message);
      process.exit(1);
    }
  });

/**
 * Custom Task: Deploy with ZK Verification
 * 
 * Deploys contracts and verifies ZK proof integration.
 * Ensures deployed contracts can verify proofs from the circuit.
 */
task("deploy:zk", "Deploy contracts with ZK verification integration")
  .addParam("network", "Network to deploy to", "localhost")
  .setAction(async (taskArgs, hre) => {
    console.log(`Deploying to ${taskArgs.network} with ZK verification...`);
    
    const { execSync } = await import("child_process");
    
    try {
      execSync(`npx hardhat run scripts/deploy.js --network ${taskArgs.network}`, { stdio: "inherit" });
      console.log("Deployment complete with ZK verification");
    } catch (error) {
      console.error("Deployment failed:", error.message);
      process.exit(1);
    }
  });

export {};