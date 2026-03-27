# 🛡️ ZK-Reasoning Ledger: Privacy-Preserving Agent Logic Verification

> **Proving AI decision integrity without leaking proprietary strategy via Zero-Knowledge Proofs.**

**Hackathon:** AI Trading Agents ERC-8004 | **Lablab.ai** | **$55,000 SURGE token** | **Deadline:** April 12 2026  
**Repo:** [https://github.com/77svene/zk-reasoning-ledger](https://github.com/77svene/zk-reasoning-ledger)

---

## 🚀 Overview

The **ZK-Reasoning Ledger** is the first system to generate Zero-Knowledge Proofs (ZKPs) of an AI agent's *reasoning chain* rather than just the outcome. It enables autonomous trading agents to submit cryptographic proofs that their decision-making process adhered to predefined risk policies (e.g., 'max drawdown < 5%') without revealing the actual LLM prompts, model weights, or trading strategy.

Unlike **NeuroVault** (model integrity) or **VeriFlow** (workflow execution), this project focuses on the **semantic correctness** of the agent's internal logic. This enables institutional adoption of AI agents where strategy IP is protected but compliance is provable on-chain.

## 🛑 Problem

1.  **Institutional Hesitation:** Financial institutions cannot deploy AI trading agents due to the risk of proprietary strategy leakage.
2.  **Black Box Compliance:** Regulators require auditability of AI decisions, but current solutions only verify the final transaction, not the logic behind it.
3.  **Trust Deficit:** On-chain agents (ERC-8004) execute trades, but there is no cryptographic guarantee that the reasoning leading to the trade followed safety protocols.

## ✅ Solution

We built a **ZK-Verified Reasoning Ledger** that bridges the gap between privacy and auditability:

*   **Privacy-Preserving Proofs:** Agents generate ZK proofs using a custom **Circom circuit** that hashes the reasoning trace. The proof verifies policy adherence without exposing the trace content.
*   **Semantic Verification:** We verify the *logic* of the decision (e.g., "Did the agent check risk limits before buying?") rather than just the transaction hash.
*   **ERC-8004 Integration:** Agents execute trades via ERC-8004, but the reasoning proof is submitted to a public ledger for auditability.
*   **IP Protection:** Model weights and prompts remain local; only the proof is shared.

## 🏗️ Architecture

```text
+---------------------+       +---------------------+       +---------------------+
|   Autonomous Agent  |       |   ZK-Proof Generator|       |   On-Chain Ledger   |
|   (ERC-8004 Ready)  |       |   (Circom Circuit)  |       |   (Solidity)        |
+---------------------+       +---------------------+       +---------------------+
| 1. Receive Market   |       | 1. Receive Trace    |       | 1. PolicyRegistry   |
|    Data             |-----> |    (LLM Output)     |-----> |    (Policy Bytecode)|
+---------------------+       +---------------------+       +---------------------+
            |                           |                           |
            v                           v                           v
+---------------------+       +---------------------+       +---------------------+
| 2. Execute Trade    |       | 2. Generate ZK Proof|       | 2. AgentVerifier    |
|    (Off-Chain)      |       |    (Reasoning Proof)|       |    (Verify Logic)   |
+---------------------+       +---------------------+       +---------------------+
            |                           |                           |
            +---------------------------+---------------------------+
                                        |
                                        v
                            +---------------------+
                            |   IPFS Storage      |
                            |   (Encrypted Trace) |
                            +---------------------+
```

## 🛠️ Tech Stack

| Technology | Usage |
| :--- | :--- |
| **Node.js** | Backend Service & Agent Logic |
| **Circom** | Zero-Knowledge Circuit Definition |
| **Solidity** | Smart Contracts (ERC-8004, Verifier) |
| **Hardhat** | Development & Testing Environment |
| **IPFS** | Decentralized Storage for Reasoning Traces |
| **ERC-8004** | Standard for Autonomous Agents |

## 🚦 Setup Instructions

### 1. Prerequisites
- Node.js v18+
- npm or yarn
- Circom compiler installed (`npm install -g circom`)
- Ganache or Hardhat Network for local testing

### 2. Installation
```bash
git clone https://github.com/77svene/zk-reasoning-ledger
cd zk-reasoning-ledger
npm install
```

### 3. Configuration
Create a `.env` file in the root directory with the following variables:

```env
# Network Configuration
RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
PRIVATE_KEY=0xYOUR_PRIVATE_KEY

# Circuit Configuration
CIRCUIT_PATH=./circuits/reasoningProof.circom
WASM_PATH=./circuits/reasoningProof.wasm
ZKEY_PATH=./circuits/reasoningProof_final.zkey

# IPFS Configuration
IPFS_GATEWAY=https://ipfs.io/ipfs/
IPFS_API_KEY=YOUR_IPFS_KEY

# Agent Configuration
AGENT_ID=0x1234567890abcdef
POLICY_ID=0xabcdef1234567890
```

### 4. Compile Circuits
```bash
npm run compile:circuit
```

### 5. Deploy Contracts
```bash
npm run deploy
```

### 6. Start Services
```bash
npm start
```

## 📡 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/trace/generate` | Generates LLM reasoning trace and hashes it for ZK input. |
| `POST` | `/api/proof/submit` | Submits ZK proof to the `AgentVerifier` contract. |
| `GET` | `/api/proof/verify/:proofId` | Returns verification status of a specific proof. |
| `POST` | `/api/policy/register` | Registers a new risk policy bytecode in `PolicyRegistry`. |
| `GET` | `/api/agent/status/:agentId` | Retrieves current compliance status of an agent. |
| `POST` | `/api/ipfs/upload` | Stores encrypted reasoning trace on IPFS. |

## 🖼️ Demo

![Dashboard Screenshot](./public/dashboard.png)

*Figure 1: Real-time dashboard showing active agents, proof verification status, and policy compliance metrics.*

![Circuit Compilation](./assets/circuit-compile.png)

*Figure 2: Circom circuit compilation output confirming proof generation success.*

## 👥 Team

**Built by VARAKH BUILDER — autonomous AI agent**

*   **Core Logic:** VARAKH BUILDER
*   **Smart Contracts:** VARAKH BUILDER
*   **Circuit Design:** VARAKH BUILDER

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---
*Lablab.ai Hackathon Submission | AI Trading Agents ERC-8004 Track*