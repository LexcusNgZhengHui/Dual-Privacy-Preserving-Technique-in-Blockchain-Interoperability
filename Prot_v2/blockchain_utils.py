# blockchain_utils.py
#
# Manages interactions with the blockchain.
# ==============================================================================
import json
import logging
import os
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
        self.zkp_contract = self._deploy_contract(
            self.ethereum, compiled_sol, Config.ZKP_VERIFIER_CONTRACT_ID
        )

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
    ) -> Optional[Contract]:
        """Deploys a single contract to the blockchain."""
        contract_name = contract_id.split(":")[-1]
        self.logger.info(f"Deploying {contract_name} contract...")

        if contract_id not in compiled_sol:
            self.logger.critical(
                f"Contract ID '{contract_id}' not found in compiled output."
            )
            return None

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

            contract_address = tx_receipt.contractAddress
            self.logger.info(
                f"{contract_name} deployed successfully at address: {contract_address}"
            )

            return w3.eth.contract(address=contract_address, abi=abi)
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

        offchain_verified = self.zkp.verify_composite_proof(
            commitments, responses, public_keys
        )

        onchain_verified = False
        if offchain_verified:
            self.logger.info(
                "Off-chain ZKP verification passed. Proceeding to on-chain checks."
            )
            try:
                onchain_verified = self.zkp_contract.functions.verifyProof(
                    commitments, responses, public_keys
                ).call()
                self.logger.info(
                    f"On-chain verification result (from call): {onchain_verified}"
                )

                if onchain_verified:
                    self.logger.info(
                        "Submitting transaction to measure on-chain gas cost..."
                    )
                    tx_hash = self.zkp_contract.functions.verifyProof(
                        commitments, responses, public_keys
                    ).transact({"from": self.ethereum.eth.default_account})

                    tx_receipt = self.ethereum.eth.wait_for_transaction_receipt(tx_hash)
                    gas_used = tx_receipt.get("gasUsed", 0)
                    self.metrics.record("onchain_gas_fee", gas_used)
                    self.logger.info(
                        f"On-chain transaction successful. Gas used: {gas_used}"
                    )
                else:
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
            self.logger.warning(
                "Off-chain ZKP verification failed. Skipping on-chain check."
            )

        zkp_fully_verified = offchain_verified and onchain_verified

        user_attrs, resource_attrs, env_attrs = {}, {}, {}
        dec_count = 0
        if zkp_fully_verified:
            self.logger.info(
                "ZKP fully verified. Decrypting attributes for policy evaluation."
            )
            user_role_num = self.he.decrypt(encrypted_user_attrs)
            user_attrs = {"role": self._num_to_role(user_role_num), "org": "hospital_a"}
            resource_attrs = {"type": "medical_record"}
            dec_count = 1
        else:
            self.logger.warning(
                "ZKP verification failed. Attributes will not be decrypted."
            )

        self.metrics.record_transaction(enc_count=2, dec_count=dec_count)

        decision = self.abac_engine.evaluate(
            user_attrs, resource_attrs, env_attrs, zkp_fully_verified
        )

        if decision == "allow":
            self._send_to_cosmos(encrypted_resource_attrs)
            self.metrics.increment_success()
            if expected_role == "doctor":
                self.metrics.increment_valid_success()
            # *** FIX: Removed emoji for compatibility ***
            return "Transaction approved and forwarded to Cosmos. [SUCCESS]"
        else:
            self.metrics.increment_error()
            if expected_role != "doctor":
                self.metrics.increment_adversarial_error()
            return "Access denied by policy. [DENIED]"

    def _send_to_cosmos(self, data: bytes):
        """Mocks sending data to a Cosmos-based chain."""
        self.logger.info(
            f"[Cosmos] Forwarding encrypted data (first 50 bytes): {data[:50].hex()}..."
        )
