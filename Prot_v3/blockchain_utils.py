# blockchain_utils.py
#
# Manages interactions with the blockchain.
# ==============================================================================
import json
import logging
import os
import time
from typing import Dict, Tuple, List, Any, Optional

from solcx import compile_files
from web3 import Web3
from web3.contract import Contract

from config import Config
from cryptography_utils import SimpleZKP, HEHelper
from policy_engine import ABACPolicyEngine
from metrics import EvaluationMetrics


class CrossChainMiddleware:
    """
    Handles the logic for cross-chain interactions, orchestrating ZKP, HE,
    and ABAC components.
    """

    def __init__(
        self,
        zkp_verifier: SimpleZKP,
        he_helper: HEHelper,
        abac_engine: ABACPolicyEngine,
        metrics: EvaluationMetrics,
    ):
        """
        Initializes the middleware, connects to blockchains, and deploys contracts.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.zkp = zkp_verifier
        self.he = he_helper
        self.abac_engine = abac_engine
        self.metrics = metrics

        self.ethereum = self._connect_to_ethereum(Config.GANACHE_URL)

        compiled_sol = self._compile_contracts(Config.CONTRACT_FILES)

        # MODIFIED: Capture the deployment gas cost from the return value, 19Oct2025
        self.zkp_contract, deployment_gas = self._deploy_contract(
            self.ethereum, compiled_sol, Config.ZKP_VERIFIER_CONTRACT_ID
        )
        if deployment_gas > 0:
            self.metrics.record("contract_deployment_cost", deployment_gas)

        self.role_secrets = Config.ROLE_SECRETS
        self.role_public_keys = self._precompute_public_keys()
        self.logger.info("Middleware initialization complete.")

    def _connect_to_ethereum(self, provider_url: str) -> Web3:
        """Connects to an Ethereum node."""
        w3 = Web3(Web3.HTTPProvider(provider_url))
        if not w3.is_connected():
            self.logger.critical("Failed to connect to Ethereum node!")
            raise ConnectionError(f"Could not connect to Ganache at {provider_url}")

        w3.eth.default_account = w3.eth.accounts[0]
        self.logger.info(
            f"Connected to Ethereum node. Default account: {w3.eth.default_account}"
        )
        return w3

    def _compile_contracts(self, contract_files: List[str]) -> Dict:
        """Compiles Solidity contract files."""
        self.logger.info(f"Compiling Solidity files: {contract_files}...")
        try:
            compiled_sol = compile_files(contract_files, output_values=["abi", "bin"])
            self.logger.info("Contracts compiled successfully.")
            return compiled_sol
        except Exception as e:
            self.logger.critical(f"Solidity compilation failed: {e}")
            raise

    def _deploy_contract(
        self, w3: Web3, compiled_sol: Dict, contract_id: str
    ) -> Tuple[
        Optional[Contract], int
    ]:  # MODIFIED: Return type to include gas cost, 19Oct2025
        """Deploys a single contract to the blockchain."""
        contract_name = contract_id.split(":")[-1]
        self.logger.info(f"Deploying {contract_name} contract...")

        if contract_id not in compiled_sol:
            self.logger.critical(
                f"Contract ID '{contract_id}' not found in compiled output."
            )
            return None, 0

        contract_data = compiled_sol[contract_id]
        abi = contract_data["abi"]
        bytecode = contract_data["bin"]

        os.makedirs(Config.COMPILED_ABI_DIR, exist_ok=True)
        abi_path = os.path.join(Config.COMPILED_ABI_DIR, f"{contract_name}.json")
        with open(abi_path, "w") as f:
            json.dump(abi, f, indent=4)
        self.logger.info(f"ABI for {contract_name} saved to {abi_path}")

        try:
            ContractFactory = w3.eth.contract(abi=abi, bytecode=bytecode)
            tx_hash = ContractFactory.constructor().transact()
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

            # NEW: Capture deployment gas cost
            deployment_gas_cost = tx_receipt.get("gasUsed", 0)
            self.logger.info(f"Contract deployment cost: {deployment_gas_cost} gas")

            contract_address = tx_receipt.contractAddress
            self.logger.info(
                f"{contract_name} deployed successfully at address: {contract_address}"
            )

            contract_instance = w3.eth.contract(address=contract_address, abi=abi)
            return contract_instance, deployment_gas_cost  # MODIFIED: Return cost
        except Exception as e:
            self.logger.critical(f"Failed to deploy {contract_name}: {e}")
            raise

    def _precompute_public_keys(self) -> Dict[str, int]:
        """Pre-computes public keys (g^secret) for all known roles."""
        self.logger.info("Pre-computing public keys for all roles...")
        return {
            role: pow(self.zkp.g, secret, self.zkp.p)
            for role, secret in self.role_secrets.items()
        }

    def _num_to_role(self, num: float) -> str:
        """Maps a decrypted number back to its string role."""
        rounded_num = int(round(num))
        for role, secret in self.role_secrets.items():
            if secret == rounded_num:
                return role
        self.logger.warning(
            f"Decrypted number {num} (rounded to {rounded_num}) does not map to a known role."
        )
        return "unknown"

    def handle_transaction(
        self,
        encrypted_user_attrs: bytes,
        encrypted_resource_attrs: bytes,
        zkp_proof: Tuple[List[int], List[int]],
        expected_role: str = "doctor",
    ) -> str:

        """
        Processes an incoming transaction request.
        """
        self.logger.info(
            f"--- Handling new transaction, expecting role: '{expected_role}' ---"
        )
        # FIX: Increment total cross-chain attempts for Ms calculation
        # --- NEW: Initialize phase timers for Hybrid Execution Behavior ---
        tx_phases = {'zkp': 0.0, 'he': 0.0, 'blockchain': 0.0}
        self.metrics.increment_count("cross_chain_attempt")

        try:
            commitments, responses = zkp_proof
        except (TypeError, ValueError):
            self.logger.error("Invalid ZKP proof format received.")
            return "Access denied: Invalid ZKP proof format."

        public_key = self.role_public_keys.get(expected_role)
        if not public_key:
            self.logger.error(f"No public key found for expected role: {expected_role}")
            return "Access denied: Configuration error."
        public_keys = [public_key]

        # --- NEW: Start ZKP Phase Timer ---
        zkp_phase_start = time.perf_counter()

        offchain_verified = self.zkp.verify_composite_proof(
            commitments, responses, public_keys
        )

        # NEW: Record Success Rate
        self.metrics.record_verification('zkp', offchain_verified)

        onchain_verified = False
        if offchain_verified:
            self.logger.info(
                "Off-chain ZKP verification passed. Proceeding to on-chain checks."
            )
            try:
                # 1. Check if the proof is valid (no gas cost)
                onchain_verified = self.zkp_contract.functions.verifyProof(
                    commitments, responses, public_keys
                ).call()
                # --- NEW: End ZKP Phase Timer ---
                tx_phases['zkp'] = time.perf_counter() - zkp_phase_start
                self.logger.info(
                    f"On-chain verification result (from call): {onchain_verified}"
                )
                

                if onchain_verified:
                    self.logger.info(
                        "Submitting transaction to measure on-chain gas cost..."
                    )
                    # --- NEW: Start Blockchain Phase Timer ---
                    blockchain_start_time = time.perf_counter()

                    # NEW: Start latency timer, added on 19Oct2025
                    latency_start_time = time.perf_counter()

                    # 2. Execute the transaction to measure gas cost and latency
                    tx_hash = self.zkp_contract.functions.verifyProof(
                        commitments, responses, public_keys
                    ).transact({"from": self.ethereum.eth.default_account})

                    tx_receipt = self.ethereum.eth.wait_for_transaction_receipt(tx_hash)

                    # --- NEW: End Blockchain Phase Timer ---
                    tx_phases['blockchain'] = time.perf_counter() - blockchain_start_time


                    # NEW: Calculate and record latency, added on 19Oct2025
                    latency = time.perf_counter() - latency_start_time
                    self.metrics.record("transaction_latency", latency)

                    gas_used = tx_receipt.get("gasUsed", 0)
                    self.metrics.record("onchain_gas_fee", gas_used)
                    self.logger.info(
                        f"On-chain transaction successful. Gas used: {gas_used}"
                    )
                else:
                    tx_phases['zkp'] = time.perf_counter() - zkp_phase_start
                    self.logger.warning(
                        "On-chain verification returned false. No gas-measuring transaction sent."
                    )

            except Exception as e:
                self.logger.error(
                    f"On-chain ZKP verification or transaction failed: {e}",
                    exc_info=True,
                )
                onchain_verified = False
        else:
            tx_phases['zkp'] = time.perf_counter() - zkp_phase_start
            self.logger.warning(
                "Off-chain ZKP verification failed. Skipping on-chain check."
            )

        zkp_fully_verified = offchain_verified and onchain_verified

        user_attrs, resource_attrs, env_attrs = {}, {}, {}
        dec_count = 0
        decryption_success = False
        decrypted_role_num = None  # Store the result here to avoid re-decryption

        if zkp_fully_verified:
            self.logger.info(
                "ZKP fully verified. Decrypting attributes for policy evaluation."
            )
            # ------------------------------------------------------------------
            # NEW: HE Decryption with Consistency Check (E_c)
            # ------------------------------------------------------------------
            try:
                # --- NEW: Start HE Phase Timer ---
                he_start_time = time.perf_counter()
                self.metrics.start_measurement("he_decrypt")

                # FIX: Decrypting User Role (Only once)
                decrypted_role_num = self.he.decrypt(encrypted_user_attrs)

                # Decrypting Resource Attributes (Assuming one more decryption for resource attrs)
                # Note: If your system uses encrypted_resource_attrs, you need to decrypt it here.
                # If your system only decrypts the role, remove this line:
                # decrypted_resource_info = self.he.decrypt(encrypted_resource_attrs)

                self.metrics.stop_measurement("he_decrypt")
                self.metrics.increment_count("he_decryption_success")
                self.metrics.record_verification('he', True)
                decryption_success = True
                # --- NEW: End HE Phase Timer ---
                tx_phases['he'] = time.perf_counter() - he_start_time

            except Exception as e:
                # This block captures HE-related errors (E_c failure)
                self.metrics.stop_measurement("he_decrypt")
                self.logger.error(
                    f"HE Decryption FAILED due to inconsistency: {e}", exc_info=False
                )
                decryption_success = False
            # ------------------------------------------------------------------

            if decryption_success and decrypted_role_num is not None:
                # If decryption succeeded, set the attributes for ABAC
                user_attrs = {
                    "role": self._num_to_role(decrypted_role_num),
                    "org": "hospital_a",
                }
                resource_attrs = {"type": "medical_record"}
                dec_count = 1
            else:
                # If ZKP was good but HE failed, fail the transaction
                self.logger.warning(
                    "Decryption FAILED due to HE inconsistency (E_c error). Attributes will not be set."
                )
        else:
            # This handles transactions where ZKP failed (off-chain or on-chain)
            self.logger.warning(
                "ZKP verification failed. Attributes will not be decrypted."
            )
        # Assuming two HE encryptions occurred upstream (for user and resource attrs)
        self.metrics.record_transaction(enc_count=2, dec_count=dec_count)

        decision = self.abac_engine.evaluate(
            user_attrs,
            resource_attrs,
            env_attrs,
            zkp_fully_verified
            and decryption_success,  # Final check now includes E_c result
        )
        # --- FINAL DECISION AND METRIC STOPPING ---
        if decision == "allow":
            self._send_to_cosmos(encrypted_resource_attrs)
            self.metrics.increment_success()
            if expected_role == "doctor":
                self.metrics.increment_valid_success()
            # *** FIX: Removed emoji for compatibility ***
            self.metrics.stop_measurement("e2e_time")
            return "Transaction approved and forwarded to Cosmos. [SUCCESS]"
        else:
            self.metrics.increment_error()
            if expected_role != "doctor":
                self.metrics.increment_adversarial_error()
            # <METRICS: T_E2E LOGIC> 3. Stop End-to-End Processing Time (DENIAL)
            self.metrics.stop_measurement("e2e_time")
            return "Access denied by policy. [DENIED]"
        

    def _send_to_cosmos(self, data: bytes):
        """Mocks sending data to a Cosmos-based chain."""
        self.logger.info(
            f"[Cosmos] Forwarding encrypted data (first 50 bytes): {data[:50].hex()}..."
        )
