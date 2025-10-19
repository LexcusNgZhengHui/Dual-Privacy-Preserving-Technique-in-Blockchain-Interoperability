# policy_engine.py
#
# Contains the Attribute-Based Access Control (ABAC) policy engine.
# ==============================================================================
import logging
from typing import List, Dict, Any


class ABACPolicyEngine:
    """
    Evaluates access control decisions based on a set of predefined policies.
    """

    def __init__(self, policies: List[Dict[str, Any]]):
        """
        Initializes the policy engine with a list of policies.
        """
        self.policies = policies
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info(f"Initialized with {len(policies)} policies.")

    def evaluate(
        self,
        user_attrs: Dict[str, Any],
        resource_attrs: Dict[str, Any],
        env_attrs: Dict[str, Any],
        zkp_verified: bool,
    ) -> str:
        """
        Evaluates the attributes against the policies to determine the outcome.
        """
        self.logger.info("Evaluating ABAC policies...")
        for policy in self.policies:
            if self._check_conditions(
                policy["conditions"],
                user_attrs,
                resource_attrs,
                env_attrs,
                zkp_verified,
            ):
                self.logger.info(
                    f"Policy '{policy.get('description', 'Untitled')}' matched. "
                    f"Action: {policy['action']}"
                )
                return policy["action"]

        self.logger.warning("No policy matched the request. Denying access.")
        return "deny"

    def _check_conditions(
        self,
        conditions: Dict[str, Any],
        user_attrs: Dict[str, Any],
        resource_attrs: Dict[str, Any],
        env_attrs: Dict[str, Any],
        zkp_verified: bool,
    ) -> bool:
        """
        Checks if all conditions within a single policy are met.
        """
        for key, expected_value in conditions.items():
            actual_value = None
            if key == "zkp_verified":
                if not zkp_verified:
                    self.logger.debug("Condition failed: ZKP not verified.")
                    return False
                continue

            elif key.startswith("user."):
                attr = key.split(".", 1)[1]
                actual_value = user_attrs.get(attr)
            elif key.startswith("resource."):
                attr = key.split(".", 1)[1]
                actual_value = resource_attrs.get(attr)
            elif key.startswith("env."):
                attr = key.split(".", 1)[1]
                actual_value = env_attrs.get(attr)

            if actual_value != expected_value:
                self.logger.debug(
                    f"Condition failed: {key} expected '{expected_value}', but got '{actual_value}'."
                )
                return False

        return True
