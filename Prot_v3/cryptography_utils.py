# cryptography_utils.py
#
# Contains utility classes for cryptographic operations, including:
# - SimpleZKP: A simple implementation of the Schnorr protocol for ZKP.
# - HEHelper: A wrapper for the TenSEAL library for Homomorphic Encryption.
# ==============================================================================
import logging
import random
import time
from typing import Tuple, List, Optional
import sys
import os

import psutil
import tenseal as ts
from eth_hash.auto import keccak

from config import Config
from metrics import EvaluationMetrics


class SimpleZKP:
    """
    Implements a simple Zero-Knowledge Proof using the Schnorr protocol.
    """

    def __init__(self, metrics: EvaluationMetrics):
        """
        Initializes the ZKP system with public parameters.
        """
        self.p = Config.ZKP_PRIME_P
        self.g = Config.ZKP_GENERATOR_G
        self.metrics = metrics
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info(
            f"Initialized with insecure test parameters (p={self.p}, g={self.g}). "
            "DO NOT USE IN PRODUCTION."
        )

    def _int_to_bytes32(self, num: int) -> bytes:
        """Converts an integer to a 32-byte big-endian representation."""
        return num.to_bytes(32, "big")

    def _hash(self, *args: int) -> int:
        """
        Creates a keccak256 hash of the given arguments, matching Solidity's
        `abi.encodePacked`.
        """
        packed_data = b"".join(self._int_to_bytes32(arg) for arg in args)
        hash_bytes = keccak(packed_data)
        self.logger.debug(f"Hashing input: {args} -> Packed: {packed_data.hex()}")
        return int.from_bytes(hash_bytes, "big") % self.p

    def generate_composite_proof(
        self, secrets: List[int]
    ) -> Optional[Tuple[List[int], List[int]]]:
        """
        Generates a composite ZKP for multiple secrets.
        Also measures computational resources and records the proof transmission size. 20Oct2025
        """
        self.metrics.start_measurement("zkp_gen")

        if not secrets:
            self.logger.error("No secrets provided for ZKP proof generation.")
            return None

        start_time = time.perf_counter()
        # Resource Monitoring Start
        process = psutil.Process(os.getpid())
        # Use instantaneous measurement before and after the operation
        cpu_before = psutil.cpu_percent(interval=None)
        mem_before = psutil.virtual_memory().used

        # 1. Prover picks random nonce values (r_i)
        r_values = [random.randint(1, self.p - 1) for _ in secrets]
        # 2. Prover computes commitments (A_i)
        commitments = [pow(self.g, r, self.p) for r in r_values]
        # 3. Prover computes challenge (c) - H(g, A_1, A_2, ...)
        challenge = self._hash(self.g, *commitments)
        # 4. Prover computes responses (z_i)
        responses = [
            (r + (secret * challenge)) % (self.p - 1)
            for r, secret in zip(r_values, secrets)
        ]

        elapsed = time.perf_counter() - start_time
        cpu_after = psutil.cpu_percent(interval=None)
        mem_after = psutil.virtual_memory().used

        self.metrics.record("zkp_gen", elapsed)
        self.metrics.record("zkp_cpu", cpu_after - cpu_before)
        self.metrics.record("zkp_memory", mem_after - mem_before)

        self.logger.debug(f"Generated ZKP in {elapsed:.6f}s")
        self.logger.debug(f"  - Commitments: {commitments}")
        self.logger.debug(f"  - Responses:   {responses}")

        # P_l Proxy: Measure Proof Size (Information Leakage Probability)
        proof_tuple = (commitments, responses)
        proof_str = str(proof_tuple)
        proof_size_bytes = sys.getsizeof(proof_str)
        proof_size_bytes = sys.getsizeof(proof_str)
        self.metrics.record("proof_transmission_size", proof_size_bytes)
        self.logger.info(f"Generated ZKP proof size (proxy): {proof_size_bytes} bytes.")

        return commitments, responses

    def verify_composite_proof(
        self, commitments: List[int], responses: List[int], public_keys: List[int]
    ) -> bool:
        """
        Verifies a composite ZKP for multiple secrets.
        """
        start_time = time.perf_counter()
        challenge = self._hash(self.g, *commitments)
        self.logger.debug(f"Verification challenge: {challenge}")

        for i in range(len(commitments)):
            lhs = pow(self.g, responses[i], self.p)
            rhs = (commitments[i] * pow(public_keys[i], challenge, self.p)) % self.p

            self.logger.debug(f"Verifying proof #{i+1}:")
            self.logger.debug(f"  - LHS (g^response): {lhs}")
            self.logger.debug(f"  - RHS (commitment * pk^challenge): {rhs}")

            if lhs != rhs:
                self.logger.error(f"ZKP verification FAILED at proof #{i+1}.")
                return False

        elapsed = time.perf_counter() - start_time
        self.metrics.record("zkp_verify", elapsed)
        # *** FIX: Removed emoji for compatibility ***
        self.logger.info(f"ZKP verification successful in {elapsed:.6f}s. [SUCCESS]")
        return True


class HEHelper:
    """
    A helper class for Homomorphic Encryption operations using TenSEAL.
    """

    def __init__(self, metrics: EvaluationMetrics):
        """
        Initializes the TenSEAL context for CKKS encryption.
        """
        self.metrics = metrics
        self.logger = logging.getLogger(self.__class__.__name__)

        try:
            self.context = ts.context(
                ts.SCHEME_TYPE.CKKS,
                poly_modulus_degree=Config.HE_POLY_MODULUS_DEGREE,
                coeff_mod_bit_sizes=Config.HE_COEFF_MOD_BIT_SIZES,
            )
            self.context.global_scale = Config.HE_GLOBAL_SCALE
            self.context.generate_galois_keys()
            self.logger.info("TenSEAL context created successfully.")
        except Exception as e:
            self.logger.critical(f"Failed to initialize TenSEAL context: {e}")
            raise

    def encrypt(self, data: float) -> bytes:
        """
        Encrypts a numerical data point using the CKKS scheme.
        """
        start_time = time.perf_counter()
        cpu_before = psutil.cpu_percent(interval=None)
        mem_before = psutil.virtual_memory().used

        encrypted_vector = ts.ckks_vector(self.context, [data])
        serialized_data = encrypted_vector.serialize()

        elapsed = time.perf_counter() - start_time
        cpu_after = psutil.cpu_percent(interval=None)
        mem_after = psutil.virtual_memory().used

        self.metrics.record("he_encrypt", elapsed)
        self.metrics.record("he_cpu", cpu_after - cpu_before)
        self.metrics.record("he_memory", mem_after - mem_before)
        self.logger.debug(f"HE encryption took {elapsed:.6f}s.")
        return serialized_data

    def decrypt(self, encrypted_data: bytes) -> float:
        """
        Decrypts a CKKS-encrypted data point.
        """
        start_time = time.perf_counter()

        vector = ts.ckks_vector_from(self.context, encrypted_data)
        decrypted_value = vector.decrypt()[0]

        elapsed = time.perf_counter() - start_time
        self.metrics.record("he_decrypt", elapsed)
        self.logger.debug(f"HE decryption took {elapsed:.6f}s.")
        return decrypted_value
