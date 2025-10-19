# config.py
#
# Centralized configuration for the application.
# Moving settings here makes the application easier to configure and maintain.
# ==============================================================================
import os
from typing import Dict, List, Any


class Config:
    """
    A centralized class for application-wide configurations.
    """

    # --- Blockchain Configuration ---
    GANACHE_URL: str = "http://127.0.0.1:7545"

    # --- Directory and File Paths ---
    # Create an output directory for compiled contracts and reports
    OUTPUT_DIR: str = "output"
    COMPILED_ABI_DIR: str = os.path.join(OUTPUT_DIR, "compiled_ABIs")
    REPORTS_DIR: str = os.path.join(OUTPUT_DIR, "reports")

    # --- Solidity Contract Configuration ---
    CONTRACT_FILES: List[str] = ["./zkpverifier.sol"]
    ZKP_VERIFIER_CONTRACT_ID: str = "./zkpverifier.sol:ZKPVerifier"

    # --- Cryptographic Parameters ---
    # WARNING: These are small, insecure parameters for testing only.
    # In a production environment, use large, cryptographically-secure primes.
    ZKP_PRIME_P: int = 23
    ZKP_GENERATOR_G: int = 5

    # TenSEAL (Homomorphic Encryption) configuration
    HE_POLY_MODULUS_DEGREE: int = 8192
    HE_COEFF_MOD_BIT_SIZES: List[int] = [60, 40, 40, 60]
    HE_GLOBAL_SCALE: int = 2**40

    # --- Role and Attribute Mapping ---
    # Maps human-readable roles to integer secrets for cryptographic operations.
    ROLE_SECRETS: Dict[str, int] = {"doctor": 1, "auditor": 2, "nurse": 3, "admin": 4}

    # --- ABAC Policy Configuration ---
    # Defines the rules for access control.
    POLICIES: List[Dict[str, Any]] = [
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
    ]

    # --- Simulation Parameters ---
    NUM_TRANSACTIONS: int = 5

    # Increased to get more data points for plots
