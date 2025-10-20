# metrics.py
#
# A dedicated class for collecting, calculating, and reporting performance
# and evaluation metrics for the entire system.
# ==============================================================================
import logging
import os
import time
from collections import defaultdict
from typing import Dict, List, Tuple, Union

import matplotlib.pyplot as plt

from config import Config


class EvaluationMetrics:
    """
    Manages the collection and reporting of all performance metrics.
    """

    def __init__(self):
        """Initializes storage for all metrics."""
        self.logger = logging.getLogger(self.__class__.__name__)

        self.metrics: Dict[str, List[Union[float, int]]] = defaultdict(list)
        self.start_times: Dict[str, float] = {}
        self.error_count = 0
        self.success_count = 0
        self.valid_success = 0
        self.adversarial_errors = 0
        self.transactions = []

        # NEW: Counter for Encryption Consistency Rate (E_c)
        self.he_decryption_success_count = 0

        # NEW: Counter for Cross-Chain Success (M_s)
        self.total_cross_chain_attempts = 0  # Tracks every time we attempt a tx.

        os.makedirs(Config.REPORTS_DIR, exist_ok=True)
        self.logger.info(f"Metrics reports will be saved to '{Config.REPORTS_DIR}'")

    def record(self, metric_name: str, value):
        """Records a single data point for a given metric."""
        self.metrics[metric_name].append(value)

    def start_measurement(self, metric_name: str):
        """Starts timing a specific metric."""
        self.start_times[metric_name] = time.perf_counter()

    def stop_measurement(self, metric_name: str):
        """Stops timing and records the duration of a specific metric."""
        if metric_name in self.start_times:
            duration = time.perf_counter() - self.start_times[metric_name]
            self.record(metric_name, duration)
            del self.start_times[metric_name]

    def record_transaction(self, enc_count: int, dec_count: int):
        """Records the number of HE operations in a single transaction."""
        self.transactions.append((enc_count, dec_count))

    def increment_error(self):
        """Increments the total error count."""
        self.error_count += 1

    def increment_success(self):
        """Increments the total success count."""
        self.success_count += 1

    def increment_valid_success(self):
        """Increments the count of successful valid (non-adversarial) transactions."""
        self.valid_success += 1

    def increment_adversarial_error(self):
        """Increments the count of correctly blocked adversarial attempts."""
        self.adversarial_errors += 1

    def increment_count(self, counter_name: str, value: int = 1):
        """Increments specific general counters."""
        if counter_name == "he_decryption_success":
            self.he_decryption_success_count += value
        elif counter_name == "cross_chain_attempt":  # NEW counter increment
            self.total_cross_chain_attempts += value
        else:
            self.logger.error(f"Unknown counter name: {counter_name}")

    def _calculate_average(self, metric_name: str) -> float:
        """Safely calculates the average of a list of metrics."""
        data = self.metrics.get(metric_name, [])
        return sum(data) / len(data) if data else 0

    """Add on total_duration , 19oct2025"""

    def generate_report(self, total_duration: float = 0):
        """Generates a summary report and saves all plots."""
        self.logger.info("Generating evaluation report and plots...")

        total_transactions = self.success_count + self.error_count
        success_rate = (
            (self.success_count / total_transactions * 100)
            if total_transactions > 0
            else 0
        )

        total_adversarial = self.adversarial_errors
        adversarial_block_rate = 100.0 if total_adversarial > 0 else 0

        # --- Calculations for E_c and P_l Proxy 20 Oct2025 ---

        # E_c: Encryption Consistency Rate (Successes / Total Valid Attempts)
        # We assume Config.NUM_TRANSACTIONS is the total number of valid attempts
        consistency_rate = (
            (self.he_decryption_success_count / Config.NUM_TRANSACTIONS * 100)
            if Config.NUM_TRANSACTIONS > 0
            else 0
        )

        # P_l Proxy: Average ZKP proof size (from cryptography_utils)
        avg_proof_size = self._calculate_average("proof_transmission_size")

        # --- NEW: Cross-Chain Metrics Calculations ---

        # M_s: Cross-Chain Message Delivery Success
        onchain_successes = len(self.metrics.get("onchain_gas_fee", []))
        ms_rate = (
            (onchain_successes / self.total_cross_chain_attempts * 100)
            if self.total_cross_chain_attempts > 0
            else 0
        )

        # T_e2e: End-to-End Processing Time (Average)
        avg_e2e_time = self._calculate_average("e2e_time")

        # S_d: Synchronization Delay (Average)
        avg_sync_delay = self._calculate_average("synchronization_delay")

        # --- NEW: Calculations for TPS --- ,19Oct2025
        # We consider only the main transactions (valid + adversarial) for TPS
        tps_total_transactions = (
            Config.NUM_TRANSACTIONS + 1
        )  # (N valid + 1 adversarial)
        throughput_tps = (
            (tps_total_transactions / total_duration) if total_duration > 0 else 0
        )

        # --- MODIFIED: Report String --- , 19Oct2025
        # Add on Blockchain Execution and Cost Metric and Resource Utilization (Approximate) 19Oct2025"
        report = f"""
        ======================= Evaluation Report =======================
        
        Overall Performance:
        - Total Transactions Processed: {total_transactions}
        - Successful Transactions:      {self.success_count}
        - Failed/Denied Transactions:   {self.error_count}
        - Overall Success Rate:         {success_rate:.2f}%
        
        Security Effectiveness:
        - Valid Transactions Succeeded:   {self.valid_success}
        - Adversarial Attempts Blocked:   {self.adversarial_errors}
        - Adversarial Block Rate:         {adversarial_block_rate:.2f}%

        Privacy and Consistency Metrics:
        - Encryption Consistency Rate (E_c):   {consistency_rate:.2f}%
        - Information Leakage Proxy (P_l):     {avg_proof_size:.2f} bytes (Avg. ZKP Proof Size)

        Average Latency per Operation/Computational Latency (seconds):
        - HE Encryption:        {self._calculate_average('he_encrypt'):.6f}
        - HE Decryption:        {self._calculate_average('he_decrypt'):.6f}
        - ZKP Generation:       {self._calculate_average('zkp_gen'):.6f}
        - ZKP Verification:     {self._calculate_average('zkp_verify'):.6f}

        Average On-Chain Cost:
        - Gas Fee per Tx:       {self._calculate_average('onchain_gas_fee'):.0f}

        Average Resource Usage:
        - HE CPU Usage (%):     {self._calculate_average('he_cpu'):.2f}
        - ZKP CPU Usage (%):    {self._calculate_average('zkp_cpu'):.2f}
        - HE Memory (bytes):    {self._calculate_average('he_memory'):.0f}
        - ZKP Memory (bytes):   {self._calculate_average('zkp_memory'):.0f}

        Blockchain Execution and Cost Metrics:
        - Contract Deployment Cost (C_dep):   {self.metrics.get('contract_deployment_cost', [0])[0]} gas
        - Average Gas per Verification (G):   {self._calculate_average('onchain_gas_fee'):.2f} gas
        - Average Transaction Latency (L_tx): {self._calculate_average('transaction_latency'):.4f} seconds
        - System Throughput (TPS):            {throughput_tps:.2f} transactions/sec

        Resource Utilization (Averages):
        - Avg. CPU Usage (U_cpu, HE):   {self._calculate_average('he_cpu'):.2f}%
        - Avg. CPU Usage (U_cpu, ZKP):  {self._calculate_average('zkp_cpu'):.2f}%
        - Avg. Memory Usage (U_mem, HE): {self._calculate_average('he_memory') / 1024:.2f} KB
        - Avg. Memory Usage (U_mem, ZKP): {self._calculate_average('zkp_memory') / 1024:.2f} KB
        
          =================================================================
        """
        self.logger.info(report)

        self.plot_scalability()
        self.plot_resources()
        self.plot_he_performance()
        self.plot_zkp_performance()
        self.plot_he_operations_per_tx()
        self.plot_gas_usage()

    def _save_plot(self, title: str, filename: str):
        """Helper to save a matplotlib plot."""
        plt.title(title, fontsize=16)
        plt.grid(True, linestyle="--", alpha=0.6)
        path = os.path.join(Config.REPORTS_DIR, filename)
        plt.savefig(path)
        self.logger.info(f"Plot saved: {path}")
        plt.close()

    def plot_scalability(self):
        """Plots the scalability of ZKP operations."""
        if not self.metrics["zkp_gen_scalability"]:
            return

        plt.figure(figsize=(10, 6))

        gen_data = sorted(self.metrics["zkp_gen_scalability"], key=lambda x: x[0])
        verify_data = sorted(self.metrics["zkp_verify_scalability"], key=lambda x: x[0])

        plt.plot(
            [d[0] for d in gen_data],
            [d[1] for d in gen_data],
            marker="o",
            label="ZKP Generation",
        )
        plt.plot(
            [d[0] for d in verify_data],
            [d[1] for d in verify_data],
            marker="o",
            label="ZKP Verification",
        )

        plt.xlabel("Number of Attributes")
        plt.ylabel("Time (seconds)")
        plt.xticks([d[0] for d in gen_data])
        plt.legend()
        self._save_plot(
            "ZKP Scalability vs. Number of Attributes", "zkp_scalability.png"
        )

    def plot_resources(self):
        """Plots the average CPU usage for cryptographic operations."""
        labels = ["HE Encryption", "ZKP Generation"]
        cpu_usage = [
            self._calculate_average("he_cpu"),
            self._calculate_average("zkp_cpu"),
        ]

        plt.figure(figsize=(8, 6))
        plt.bar(labels, cpu_usage, color=["skyblue", "lightgreen"])
        plt.ylabel("Average CPU Usage (%)")
        self._save_plot(
            "Average CPU Usage per Crypto Operation", "resource_cpu_usage.png"
        )

    def plot_he_performance(self):
        """Plots the latency of HE operations over time."""
        plt.figure(figsize=(10, 6))
        plt.plot(
            self.metrics["he_encrypt"], label="Encryption", marker=".", linestyle="-"
        )
        plt.plot(
            self.metrics["he_decrypt"], label="Decryption", marker=".", linestyle="-"
        )
        plt.xlabel("Transaction Sequence")
        plt.ylabel("Time (seconds)")
        plt.legend()
        self._save_plot("Homomorphic Encryption Performance", "he_performance.png")

    def plot_zkp_performance(self):
        """Plots the latency of ZKP operations over time."""
        plt.figure(figsize=(10, 6))
        plt.plot(self.metrics["zkp_gen"], label="Generation", marker=".", linestyle="-")
        plt.plot(
            self.metrics["zkp_verify"], label="Verification", marker=".", linestyle="-"
        )
        plt.xlabel("Transaction Sequence")
        plt.ylabel("Time (seconds)")
        plt.legend()
        self._save_plot("ZKP Performance", "zkp_performance.png")

    def plot_he_operations_per_tx(self):
        """Plots the number of HE operations for each transaction."""
        if not self.transactions:
            return

        encryptions = [tx[0] for tx in self.transactions]
        decryptions = [tx[1] for tx in self.transactions]

        plt.figure(figsize=(10, 6))
        x_axis = range(len(self.transactions))

        plt.bar(x_axis, encryptions, label="Encryptions per Tx")
        plt.bar(x_axis, decryptions, bottom=encryptions, label="Decryptions per Tx")

        plt.xlabel("Transaction Sequence")
        plt.ylabel("Number of HE Operations")
        plt.legend()
        self._save_plot("HE Operations per Transaction", "he_operations_per_tx.png")

    def plot_gas_usage(self):
        """Plots the on-chain gas fee for each successful verification transaction."""
        if not self.metrics.get("onchain_gas_fee"):
            self.logger.info("No on-chain gas fees were recorded to plot.")
            return

        plt.figure(figsize=(10, 6))
        gas_fees = self.metrics["onchain_gas_fee"]
        plt.plot(gas_fees, label="Gas Fee per Verification", marker="o", linestyle="-")

        plt.xlabel("Successful Verification Sequence")
        plt.ylabel("Gas Units")
        plt.legend()
        self._save_plot("On-Chain Gas Fee per Verification", "onchain_gas_fee.png")
