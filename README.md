# Dual-Privacy-Preserving-Technique-in-Blockchain-Interoperability

A Proof of Concept (PoC) demonstrating a **dual privacy-preserving technique for blockchain interoperability** by combining **Zero-Knowledge Proofs (ZKP)** and **Homomorphic Encryption (HE)** with **Attribute-Based Access Control (ABAC)**.

The prototype simulates a privacy-preserving cross-chain transaction workflow in which a user's role is protected using cryptographic techniques before access to a resource is evaluated and encrypted data is forwarded to another blockchain environment.

> **Status:** Proof of Concept / Research Prototype
> **Not intended for production use**

---

## 1. Overview

Blockchain interoperability enables information and transactions to move between different blockchain networks. However, transferring data across blockchain boundaries can introduce privacy and confidentiality concerns.

This project explores a **dual privacy-preserving approach**:

1. **Zero-Knowledge Proof (ZKP)**
   Allows a user to demonstrate knowledge of a secret associated with an authorized role without directly exposing the secret during the proof process.

2. **Homomorphic Encryption (HE)**
   Protects attribute data in encrypted form and allows the system to maintain confidentiality of sensitive information during the transaction workflow.

3. **Attribute-Based Access Control (ABAC)**
   Evaluates the user's attributes, resource attributes, and ZKP verification result before deciding whether the transaction should be approved.

4. **Blockchain Verification and Interoperability**
   The ZKP is verified both off-chain and on-chain through a Solidity smart contract. When the access request is approved, the encrypted resource data is forwarded to a simulated Cosmos-based chain.

The overall proof-of-concept workflow is:

```text
                    User / Client
                         |
                         v
              +---------------------+
              | User Role / Secret  |
              +---------------------+
                    /         \
                   /           \
                  v             v
        +---------------+   +----------------+
        | ZKP Generation|   | HE Encryption  |
        +---------------+   +----------------+
                |                 |
                v                 v
        +-----------------------------------+
        |      Cross-Chain Middleware       |
        +-----------------------------------+
                       |
                       v
              +-------------------+
              | Off-chain ZKP     |
              | Verification      |
              +-------------------+
                       |
                       v
              +-------------------+
              | On-chain ZKP      |
              | Verification      |
              +-------------------+
                       |
                       v
              +-------------------+
              | HE Decryption     |
              | / Consistency     |
              +-------------------+
                       |
                       v
              +-------------------+
              | ABAC Policy       |
              | Evaluation        |
              +-------------------+
                    /       \
                   /         \
             ALLOW             DENY
               |                 |
               v                 v
       +---------------+   Access Denied
       | Forward       |
       | Encrypted Data|
       | to Cosmos     |
       +---------------+
```

---

## 2. Research Objective

The primary objective of this PoC is to demonstrate how **two complementary privacy-preserving techniques** can be incorporated into a blockchain interoperability workflow:

### Privacy Technique 1 — Zero-Knowledge Proof

ZKP is used to verify knowledge of a secret associated with an authorized role without directly transmitting the secret as part of the proof.

The implementation uses a simplified Schnorr-style construction.

For a secret `x`, the public key is calculated as:

```text
y = g^x mod p
```

During proof generation, a random nonce `r` is selected and a commitment is calculated:

```text
A = g^r mod p
```

A Fiat-Shamir-style challenge is derived using Keccak-256:

```text
c = H(g, A1, A2, ...)
```

The response is then calculated as:

```text
z = (r + x*c) mod (p-1)
```

The verifier checks:

```text
g^z mod p = A * y^c mod p
```

The Python implementation constructs the hash input using 32-byte big-endian integers so that the hashing procedure corresponds to the Solidity implementation.

---

## 3. Privacy Technique 2 — Homomorphic Encryption

The second privacy mechanism uses **TenSEAL** and the **CKKS homomorphic encryption scheme**.

The prototype encrypts numerical representations of attributes before they enter the transaction-processing workflow.

The HE configuration includes:

```text
Polynomial modulus degree : 8192
Coefficient modulus sizes : [60, 40, 40, 60]
Global scale              : 2^40
```

The implementation creates a TenSEAL CKKS context and provides helper functions for encryption and decryption.

The role mapping used by the prototype is:

| Role    | Secret |
| ------- | -----: |
| doctor  |      1 |
| auditor |      2 |
| nurse   |      3 |
| admin   |      4 |

These values are research/demo parameters and should **not** be interpreted as secure production credentials.

---

## 4. Attribute-Based Access Control

After successful ZKP verification and HE decryption, the resulting attributes are passed to the ABAC policy engine.

The current policy allows access when all of the following conditions are satisfied:

```text
User role       = doctor
User organization = hospital_a
Resource type   = medical_record
ZKP verified    = true
```

The policy is represented in the configuration as:

```python
{
    "description": "Allow doctors from hospital_a to access medical records if their ZKP is verified.",
    "conditions": {
        "user.role": "doctor",
        "user.org": "hospital_a",
        "resource.type": "medical_record",
        "zkp_verified": True,
    },
    "action": "allow",
}
```

If no policy matches, the request is denied.

---

## 5. Blockchain Interoperability Architecture

The prototype uses an Ethereum-compatible local blockchain environment for smart-contract deployment and verification.

The current configuration connects to:

```text
http://127.0.0.1:7545
```

which is intended for a local Ganache environment.

The `CrossChainMiddleware` coordinates:

* Ethereum connection
* Solidity compilation
* Smart-contract deployment
* ZKP generation and verification
* On-chain ZKP verification
* Homomorphic encryption/decryption
* ABAC policy evaluation
* Transaction metrics
* Cross-chain forwarding

The destination blockchain is currently **simulated rather than implemented as a live Cosmos network**. The `_send_to_cosmos()` function logs the forwarding of encrypted data rather than submitting an actual Cosmos transaction.

Therefore, this repository should be understood as demonstrating the **privacy and interoperability workflow**, rather than a complete production blockchain bridge.

---

## 6. On-Chain ZKP Verification

The Solidity contract `ZKPVerifier` implements verification of the ZKP on an Ethereum-compatible blockchain.

The contract uses:

```solidity
uint256 public constant p = 23;
uint256 public constant g = 5;
```

The `verifyProof()` function checks that the lengths of commitments, responses, and public keys are consistent before calculating the Fiat-Shamir challenge.

The challenge is generated from:

```text
g || commitment_1 || commitment_2 || ...
```

using:

```solidity
keccak256(packedData)
```

and then reduced modulo `p`.

Each proof component is verified using:

```text
g^response mod p
=
commitment * publicKey^challenge mod p
```

If every component passes, the contract returns `true`.

The Python middleware first performs off-chain verification. Only if the off-chain verification succeeds does it proceed to the on-chain verification stage. The successful on-chain verification is then submitted as a transaction to measure gas consumption and latency.

---

## 7. End-to-End Transaction Workflow

A valid transaction follows this sequence:

### Step 1 — User Attribute Selection

The prototype uses:

```python
user_attrs = {"role": "doctor"}
```

The corresponding role secret is retrieved from the configuration.

### Step 2 — Homomorphic Encryption

The role secret and resource attribute are encrypted using the HE helper.

```text
User role
   |
   v
HE encryption
   |
   v
Encrypted user attribute
```

### Step 3 — ZKP Generation

The user's role secret is used to generate a composite ZKP.

```text
Secret
  |
  v
Random nonce
  |
  v
Commitment
  |
  v
Keccak challenge
  |
  v
Response
  |
  v
ZKP proof
```

### Step 4 — Off-Chain Verification

The middleware verifies the proof locally.

### Step 5 — On-Chain Verification

If the off-chain verification succeeds, the proof is passed to the deployed Solidity contract.

### Step 6 — HE Decryption

After successful ZKP verification, the encrypted role attribute is decrypted.

The resulting numerical value is mapped back to a role.

### Step 7 — ABAC Evaluation

The decrypted attributes are evaluated against the configured ABAC policy.

### Step 8 — Cross-Chain Forwarding

If the policy returns `allow`, the encrypted resource data is forwarded to the simulated Cosmos destination.

The transaction returns:

```text
Transaction approved and forwarded to Cosmos. [SUCCESS]
```

Otherwise:

```text
Access denied by policy. [DENIED]
```

The middleware explicitly prevents attribute decryption when ZKP verification fails.

---

## 8. Adversarial Scenario

The prototype also includes an adversarial test.

Instead of the valid `doctor` role, the adversarial simulation uses:

```python
invalid_role_secret = 999
```

The system generates a proof for the invalid secret but submits it against the expected `doctor` public-key context.

This allows the prototype to demonstrate that a proof/public-key mismatch should result in access denial rather than successful resource access.

This test is useful for demonstrating the security decision path:

```text
Invalid request
      |
      v
ZKP verification
      |
      X
  Verification failure
      |
      v
HE decryption skipped
      |
      v
Access denied
```

---

## 9. Scalability Experiment

The PoC includes a basic scalability experiment for the ZKP component.

The following attribute counts are tested:

```text
1 attribute
4 attributes
10 attributes
```

For each configuration, the system records:

* ZKP generation time
* ZKP verification time
* Verification result

The implementation records these measurements as:

```text
zkp_gen_scalability
zkp_verify_scalability
```

and generates a scalability plot comparing generation and verification time against the number of attributes.

---

## 10. Performance Evaluation

The prototype collects several categories of metrics.

### Cryptographic Performance

* HE encryption latency
* HE decryption latency
* ZKP generation latency
* ZKP verification latency

### Resource Utilization

* HE CPU usage
* ZKP CPU usage
* HE memory usage
* ZKP memory usage

### Blockchain Performance

* Smart-contract deployment gas
* Average gas per verification
* Transaction latency
* System throughput (TPS)

### Security and Privacy Indicators

* Valid transaction success
* Adversarial attempts blocked
* Encryption consistency rate (`E_c`)
* Information leakage proxy (`P_l`)
* Cross-chain message delivery success (`M_s`)
* End-to-end processing time (`T_e2e`)
* Synchronization delay (`S_d`)

The evaluation component calculates and reports these measurements and generates corresponding plots.

---

## 11. Generated Evaluation Plots

The system can generate plots for:

```text
output/reports/
├── zkp_scalability.png
├── resource_cpu_usage.png
├── he_performance.png
├── zkp_performance.png
├── he_operations_per_tx.png
└── onchain_gas_fee.png
```

The plots cover ZKP scalability, CPU usage, HE performance, ZKP performance, HE operations per transaction, and on-chain verification gas usage.

The application also generates timestamped log files under:

```text
output/reports/
```

---

## 12. Project Structure

The source code is organized into the following logical components:

```text
Dual-Privacy-Preserving-Technique-in-Blockchain-Interoperability/
│
├── main.py
├── config.py
├── cryptography_utils.py
├── blockchain_utils.py
├── policy_engine.py
├── metrics.py
├── zkpverifier.sol
│
├── output/
│   ├── compiled_ABIs/
│   └── reports/
│
└── README.md
```

### `main.py`

Main application entry point. It initializes the cryptographic components, policy engine, blockchain middleware, metrics system, and simulation scenarios.

### `cryptography_utils.py`

Contains:

* `SimpleZKP`
* `HEHelper`

The ZKP implementation handles proof generation and verification, while `HEHelper` provides TenSEAL CKKS encryption/decryption functionality.

### `blockchain_utils.py`

Implements the `CrossChainMiddleware`, which coordinates the blockchain, ZKP, HE, ABAC, and cross-chain processing components.

### `policy_engine.py`

Implements the ABAC policy evaluation mechanism.

### `metrics.py`

Collects and reports experimental performance and security-related measurements.

### `config.py`

Contains system configuration, cryptographic parameters, role mappings, ABAC policies, blockchain configuration, and simulation parameters.

### `zkpverifier.sol`

Solidity smart contract responsible for on-chain ZKP verification.

---

## 13. Requirements

The implementation uses Python libraries including:

* Python
* Web3.py
* py-solc-x
* TenSEAL
* `eth-hash`
* psutil
* Matplotlib

The project also requires a local Ethereum-compatible blockchain environment such as **Ganache**, configured to expose the endpoint:

```text
http://127.0.0.1:7545
```

The Solidity contract is compiled programmatically using `solcx.compile_files()`.

> **Note:** This repository does not currently define pinned package versions in the supplied source. For reproducibility, it is recommended to add a `requirements.txt` or `pyproject.toml` with tested versions.

---

## 14. Installation

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/Dual-Privacy-Preserving-Technique-in-Blockchain-Interoperability.git

cd Dual-Privacy-Preserving-Technique-in-Blockchain-Interoperability
```

Replace `<your-username>` with your GitHub username.

### 2. Create a Python virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

Or on Linux/macOS:

```bash
source venv/bin/activate
```

### 3. Install the required Python packages

```bash
pip install web3 py-solc-x tenseal eth-hash psutil matplotlib
```

> Package installation may vary depending on operating system and Python version, particularly for TenSEAL.

### 4. Start Ganache

Start a local Ganache instance using the configured RPC endpoint:

```text
http://127.0.0.1:7545
```

The middleware expects a connected Ethereum node and uses the first available Ethereum account as the default account.

### 5. Ensure a compatible Solidity compiler is available

The Python middleware compiles `zkpverifier.sol` automatically using `solcx`.

### 6. Run the PoC

```bash
python main.py
```

---

## 15. What Happens When `main.py` Runs?

The main program performs the following sequence:

```text
Initialize logging
       |
       v
Initialize evaluation metrics
       |
       v
Initialize ZKP verifier
       |
       v
Initialize HE helper
       |
       v
Initialize ABAC engine
       |
       v
Connect to Ganache
       |
       v
Compile ZKPVerifier.sol
       |
       v
Deploy ZKPVerifier
       |
       v
Run valid transactions
       |
       v
Run adversarial test
       |
       v
Run ZKP scalability test
       |
       v
Generate evaluation report
       |
       v
Generate performance plots
```

The default configuration runs:

```python
NUM_TRANSACTIONS = 10
```

valid transaction simulations before the adversarial and scalability experiments.

---

## 16. Example Transaction Outcomes

### Valid Transaction

A user with:

```text
Role = doctor
Organization = hospital_a
```

attempts to access:

```text
Resource = medical_record
```

Expected workflow:

```text
HE Encryption       -> Success
ZKP Generation      -> Success
Off-chain ZKP       -> Valid
On-chain ZKP        -> Valid
HE Decryption       -> Success
ABAC Evaluation     -> Allow
Cross-chain Forward -> Success
```

Result:

```text
Transaction approved and forwarded to Cosmos. [SUCCESS]
```

### Adversarial Transaction

An invalid secret is used while the expected role remains `doctor`.

Expected workflow:

```text
ZKP Generation      -> Generated
Off-chain ZKP       -> Invalid
On-chain ZKP        -> Skipped
HE Decryption       -> Skipped
ABAC Evaluation     -> Deny
```

Result:

```text
Access denied by policy. [DENIED]
```

---

## 17. Security Considerations

This repository is a **research prototype** and contains intentionally simplified cryptographic parameters.

### Small ZKP Parameters

The implementation uses:

```text
p = 23
g = 5
```

These parameters are explicitly identified by the implementation as insecure testing parameters and **must not be used in a real security-sensitive deployment**.

### Simplified Role Representation

Roles are represented using small integer secrets:

```text
doctor  -> 1
auditor -> 2
nurse   -> 3
admin   -> 4
```

This is suitable for demonstrating the protocol workflow but is not an appropriate credential-management mechanism for production.

### Local Blockchain

The current implementation uses Ganache and a local Ethereum endpoint. It therefore does not demonstrate production blockchain consensus, validator behavior, bridge security, or network-level adversarial conditions.

### Simulated Cosmos Destination

The Cosmos side is currently mocked. The system logs the forwarding of encrypted data instead of interacting with a live Cosmos blockchain.

### Experimental Metrics

Some reported privacy/security measurements are **proxies rather than formal cryptographic security guarantees**.

For example:

```text
P_l = average ZKP proof size
```

is used as an information-leakage proxy rather than a formal information-theoretic leakage measurement.

Similarly, `E_c` represents an encryption/decryption consistency measurement within the prototype rather than a formal cryptographic security property.

---

## 18. Important Implementation Note

The Solidity contract contains two challenge-generation implementations.

The production verification path in:

```solidity
verifyProof()
```

constructs the challenge by concatenating:

```text
g || commitment_1 || commitment_2 || ...
```

and hashing the complete packed data.

This corresponds to the Python implementation:

```python
challenge = self._hash(self.g, *commitments)
```

However, the debugging function:

```solidity
getLHSandRHS()
```

uses a different iterative hashing procedure:

```text
H(g)
H(previous_challenge, commitment_1)
H(previous_challenge, commitment_2)
...
```

Therefore, `getLHSandRHS()` should be treated as a **debugging utility**, not as the authoritative implementation of the challenge calculation used by `verifyProof()`.

---

## 19. Limitations

The current PoC has several limitations:

1. The ZKP uses very small cryptographic parameters.
2. The role secrets are simplified integer values.
3. The ZKP is a simplified research implementation rather than a production-grade ZKP library.
4. The Ethereum blockchain is simulated locally using Ganache.
5. The Cosmos destination is mocked rather than implemented as a live cross-chain transaction.
6. The prototype does not implement a production bridge or interoperability protocol.
7. Performance results depend on the local hardware and software environment.
8. The privacy metrics include experimental proxies rather than formal privacy guarantees.
9. The supplied implementation does not include pinned dependency versions.
10. The system is intended primarily to demonstrate the architectural interaction between ZKP, HE, ABAC, and blockchain interoperability.

---

## 20. Research Contributions Demonstrated by the PoC

The prototype demonstrates the feasibility of combining multiple security mechanisms in a cross-chain access-control workflow:

### Dual Privacy Protection

```text
              Sensitive Attribute
                     |
             +-------+-------+
             |               |
             v               v
          ZKP Layer       HE Layer
             |               |
             v               v
      Prove authorization   Protect data
             |               |
             +-------+-------+
                     |
                     v
              Access Decision
```

The ZKP mechanism is used to establish authorization without directly relying on disclosure of the secret, while HE protects sensitive attribute information during the workflow.

### Defense-in-Depth

The design does not rely on a single security mechanism.

```text
ZKP
 |
 +-- Authorization proof
 |
HE
 |
 +-- Attribute confidentiality
 |
ABAC
 |
 +-- Policy enforcement
 |
Blockchain
 |
 +-- On-chain verification / interoperability workflow
```

This creates multiple verification and protection layers within the transaction pipeline.

---

## 21. Future Work

Potential extensions of this PoC include:

* Replace the toy ZKP parameters with production-grade cryptographic groups.
* Use a standardized ZKP framework or library.
* Introduce proper key management and credential lifecycle management.
* Replace the simulated Cosmos destination with an actual Cosmos SDK / IBC-based implementation.
* Implement authenticated cross-chain messaging.
* Introduce decentralized bridge or relay mechanisms.
* Add stronger privacy/leakage analysis.
* Add formal security analysis of the protocol.
* Add reproducible benchmarking with fixed hardware/software configurations.
* Add automated unit and integration tests.
* Pin Python and Solidity compiler dependencies.
* Containerize the experimental environment using Docker.
* Add CI/CD testing through GitHub Actions.
* Evaluate larger numbers of attributes and transactions.
* Compare the dual-technique architecture against ZKP-only and HE-only baselines.

---

## 22. Experimental Metrics

The evaluation framework produces measurements including:

| Category         | Metrics                                               |
| ---------------- | ----------------------------------------------------- |
| ZKP              | Generation time, verification time, CPU, memory       |
| HE               | Encryption time, decryption time, CPU, memory         |
| Blockchain       | Deployment gas, verification gas, transaction latency |
| Throughput       | TPS                                                   |
| Security         | Valid success, adversarial block rate                 |
| Privacy          | `E_c`, `P_l` proxy                                    |
| Interoperability | `M_s`, synchronization delay                          |
| Scalability      | ZKP generation/verification vs. attribute count       |

The evaluation report is generated programmatically after the simulations complete.

---

## 23. Citation

If you use this repository, implementation, architecture, or experimental results in academic work, please cite the corresponding research publication or project documentation.

A placeholder BibTeX entry can be added once the associated publication details are available:

```bibtex
@misc{dual_privacy_blockchain_interoperability,
  title        = {Dual Privacy-Preserving Technique in Blockchain Interoperability},
  author       = {Your Name},
  year         = {2026},
  howpublished = {\url{https://github.com/<your-username>/Dual-Privacy-Preserving-Technique-in-Blockchain-Interoperability}},
  note         = {Proof of Concept}
}
```

---

## 24. License

This project is released under the MIT License.

See `LICENSE` for the full license text.

---

## 25. Disclaimer

This repository is provided for **research, educational, and proof-of-concept purposes**.

The cryptographic parameters, role secrets, local blockchain configuration, simulated cross-chain communication, and experimental privacy metrics are not intended for production deployment.

**Do not use the current implementation to protect real-world sensitive data or assets without substantial cryptographic, security, interoperability, and implementation-level review.**

---

## 26. Summary

This project presents a proof-of-concept architecture for **privacy-preserving blockchain interoperability** by integrating:

```text
        Zero-Knowledge Proof
                 +
        Homomorphic Encryption
                 +
        Attribute-Based
        Access Control
                 +
        Blockchain Verification
                 +
        Cross-Chain Middleware
                 |
                 v
     Privacy-Preserving Interoperability
```

The PoC demonstrates how ZKP and HE can be combined with policy-based authorization and blockchain verification to create a layered approach to privacy-preserving cross-chain transaction processing.

The implementation provides an experimental foundation for further research into **dual privacy-preserving mechanisms, secure blockchain interoperability, privacy-aware access control, and cross-chain data protection**.
