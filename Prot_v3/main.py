# main.py
#
# This file serves as the main entry point for the cross-chain transaction simulation.
# It demonstrates a workflow involving Zero-Knowledge Proofs (ZKP), Homomorphic
# Encryption (HE), and Attribute-Based Access Control (ABAC) for secure data sharing.
# The script is designed to be modular, with clear separation of concerns,
# making it easy to test, maintain, and extend.

import logging
import time
import os
import datetime
from typing import Dict, Any, List

# Local application imports
from config import Config
from cryptography_utils import SimpleZKP, HEHelper
from policy_engine import ABACPolicyEngine
from blockchain_utils import CrossChainMiddleware
from metrics import EvaluationMetrics


def setup_logging():
    """
    Configures logging to output to both the console and a timestamped file
    in the reports directory.
    """
    # Ensure the reports directory exists
    os.makedirs(Config.REPORTS_DIR, exist_ok=True)

    # Generate a unique filename based on the current date and time
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = f"Log_Record_{timestamp}.txt"
    log_filepath = os.path.join(Config.REPORTS_DIR, log_filename)

    # Get the root logger.
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Clear existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # Create a formatter
    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] [%(name)s] - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # *** FIX: Specify UTF-8 encoding for the file handler to prevent UnicodeEncodeError ***
    file_handler = logging.FileHandler(log_filepath, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Create a console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Set a higher log level for noisy third-party libraries
    logging.getLogger("web3.providers.HTTPProvider").setLevel(logging.WARNING)
    logging.getLogger("web3.RequestManager").setLevel(logging.WARNING)

    logger.info(
        f"Logging initialized. Full log record will be saved to: {log_filepath}"
    )


def run_valid_transaction_simulation(middleware: CrossChainMiddleware):
    """
    Simulates a valid transaction where a user with the correct attributes
    attempts to access a resource.
    """
    logging.info("==============================================")
    # *** FIX: Removed emoji for compatibility ***
    logging.info("[STARTING] Valid Transaction Simulation")
    logging.info("==============================================")

    user_attrs = {"role": "doctor"}
    role_secret = middleware.role_secrets[user_attrs["role"]]
    logging.info(
        f"Simulating transaction for user role: 'doctor' (secret: {role_secret})"
    )

    logging.info("Encrypting user attributes using HE...")
    encrypted_user_attrs = middleware.he.encrypt(role_secret)
    encrypted_resource_attrs = middleware.he.encrypt(0)

    logging.info("Generating ZKP for user's role...")
    zkp_proof = middleware.zkp.generate_composite_proof([role_secret])
    if not zkp_proof:
        logging.error("Failed to generate ZKP proof. Aborting transaction.")
        return

    logging.info("Submitting transaction to the cross-chain middleware...")
    result = middleware.handle_transaction(
        encrypted_user_attrs, encrypted_resource_attrs, zkp_proof
    )
    # *** FIX: Removed emoji for compatibility ***
    logging.info(f"[RESULT] Transaction Result: {result}")
    logging.info("==============================================\n")


def run_adversarial_test(middleware: CrossChainMiddleware):
    """
    Simulates an adversarial attack where a user with an invalid role
    attempts to gain access.
    """
    logging.info("==============================================")
    # *** FIX: Removed emoji for compatibility ***
    logging.info("[STARTING] Adversarial Test Simulation")
    logging.info("==============================================")

    invalid_role_secret = 999
    logging.info(
        f"Simulating adversarial transaction with invalid secret: {invalid_role_secret}"
    )

    logging.info("Encrypting invalid user attributes using HE...")
    encrypted_invalid_user_attrs = middleware.he.encrypt(invalid_role_secret)
    encrypted_resource_attrs = middleware.he.encrypt(0)

    logging.info("Generating ZKP for the invalid role...")
    invalid_zkp_proof = middleware.zkp.generate_composite_proof([invalid_role_secret])
    if not invalid_zkp_proof:
        logging.error("Failed to generate ZKP proof for adversarial test. Aborting.")
        return

    logging.info(
        "Attempting to handle transaction with mismatched proof and public key context."
    )
    result = middleware.handle_transaction(
        encrypted_invalid_user_attrs,
        encrypted_resource_attrs,
        invalid_zkp_proof,
        expected_role="doctor",
    )
    # *** FIX: Removed emoji for compatibility ***
    logging.info(f"[RESULT] Adversarial Test Result: {result}")
    logging.info("==============================================\n")


def run_scalability_test(middleware: CrossChainMiddleware):
    """
    Tests the performance of ZKP generation and verification with an
    increasing number of attributes.
    """
    logging.info("==============================================")
    # *** FIX: Removed emoji for compatibility ***
    logging.info("[STARTING] ZKP Scalability Test")
    logging.info("==============================================")

    attribute_sets = [
        [1],
        [1, 2, 3, 4],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    ]

    for secrets in attribute_sets:
        num_attrs = len(secrets)
        logging.info(f"--- Testing with {num_attrs} attribute(s) ---")

        gen_start_time = time.perf_counter()
        proof = middleware.zkp.generate_composite_proof(secrets)
        gen_time = time.perf_counter() - gen_start_time
        middleware.metrics.record("zkp_gen_scalability", (num_attrs, gen_time))
        logging.info(f"Generation time for {num_attrs} attrs: {gen_time:.6f}s")

        public_keys = [
            pow(middleware.zkp.g, secret, middleware.zkp.p) for secret in secrets
        ]
        verify_start_time = time.perf_counter()
        is_valid = middleware.zkp.verify_composite_proof(
            proof[0], proof[1], public_keys
        )
        verify_time = time.perf_counter() - verify_start_time
        middleware.metrics.record("zkp_verify_scalability", (num_attrs, verify_time))
        logging.info(f"Verification time for {num_attrs} attrs: {verify_time:.6f}s")
        # *** FIX: Removed emoji for compatibility ***
        logging.info(f"Verification result: {'Success' if is_valid else 'Failure'}")

    logging.info("==============================================\n")


def main():
    """
    Main function to initialize the system and run simulations.
    """
    setup_logging()

    try:
        metrics = EvaluationMetrics()
        zkp_verifier = SimpleZKP(metrics=metrics)
        he_helper = HEHelper(metrics=metrics)
        abac_engine = ABACPolicyEngine(policies=Config.POLICIES)

        middleware = CrossChainMiddleware(
            zkp_verifier=zkp_verifier,
            he_helper=he_helper,
            abac_engine=abac_engine,
            metrics=metrics,
        )
        # NEW: Start timer for TPS calculation
        simulation_start_time = time.perf_counter()

        for _ in range(Config.NUM_TRANSACTIONS):
            run_valid_transaction_simulation(middleware)

        run_adversarial_test(middleware)
        """Add on in 19 Oct 2025
        Note: The scalability test is not a standard transaction,
        so it's often excluded from simple TPS calculations.
        We will keep it inside the timer for simplicity here."""
        run_scalability_test(middleware)

        # NEW: Calculate total simulation duration
        simulation_duration = time.perf_counter() - simulation_start_time

        logging.info("==============================================")
        # *** FIX: Removed emoji for compatibility ***
        logging.info("[REPORT] Generating Final Evaluation Report")
        logging.info("==============================================")

        # NEW: Pass the duration to the report generator, 19Oct2025
        middleware.metrics.generate_report(total_duration=simulation_duration)

        #middleware.metrics.generate_report()
        logging.info(
            "Report generation complete. Check the output directory for plots and the log file."
        )

    except Exception as e:
        logging.critical(f"A critical error occurred: {e}", exc_info=True)


if __name__ == "__main__":
    main()
