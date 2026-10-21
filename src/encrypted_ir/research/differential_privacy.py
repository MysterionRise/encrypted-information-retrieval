"""
Differential Privacy Module

Implements differential privacy mechanisms for aggregate statistics over encrypted data
to prevent statistical inference attacks.

Mechanisms:
- Laplace mechanism for count queries (pure ε-DP)
- Gaussian mechanism for sum/average queries ((ε, δ)-DP)
- Exponential mechanism for non-numeric queries (pure ε-DP)

Includes per-tenant privacy budget (epsilon) tracking with depletion warnings
and automatic query rejection when budget is exhausted.

Use Case: Privacy-preserving analytics on encrypted financial data,
aggregate reporting with formal privacy guarantees.

References:
- Dwork & Roth (2014): "The Algorithmic Foundations of Differential Privacy"
- GDPR Art. 32: Pseudonymization and aggregation
- DORA Art. 9: Advanced privacy techniques
"""

from __future__ import annotations

import math
import os
import struct
import threading
import warnings
from collections.abc import Callable
from typing import Any


class PrivacyBudgetExhaustedError(Exception):
    """Raised when a tenant's privacy budget is exhausted."""


class PrivacyBudgetWarning(UserWarning):
    """Warning issued when privacy budget is running low."""


def _secure_random_float() -> float:
    """Generate a cryptographically secure random float in [0, 1)."""
    # Use os.urandom for cryptographic randomness
    random_bytes = os.urandom(8)
    random_int = struct.unpack("<Q", random_bytes)[0]
    return float((random_int >> 11) * (2**-53))  # IEEE 754 double precision


def _secure_uniform(low: float, high: float) -> float:
    """Generate a cryptographically secure uniform random value in [low, high)."""
    return low + (high - low) * _secure_random_float()


class LaplaceMechanism:
    """
    Laplace mechanism for pure ε-differential privacy.

    Adds Lap(sensitivity/ε) noise to numeric query results.
    Suitable for count queries where sensitivity is typically 1.
    """

    @staticmethod
    def add_noise(value: float, sensitivity: float, epsilon: float) -> float:
        """
        Add Laplace noise to a value.

        Args:
            value: True query result
            sensitivity: L1 sensitivity of the query (max change from one record)
            epsilon: Privacy parameter (smaller = more private)

        Returns:
            Noised value with ε-differential privacy guarantee
        """
        if epsilon <= 0:
            raise ValueError("Epsilon must be positive")
        if sensitivity < 0:
            raise ValueError("Sensitivity must be non-negative")

        scale = sensitivity / epsilon
        # Sample from Laplace(0, scale) using inverse CDF
        u = _secure_random_float()
        # Avoid log(0)
        while u == 0.0:
            u = _secure_random_float()
        u = u - 0.5
        noise = -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))
        return value + noise

    @staticmethod
    def variance(sensitivity: float, epsilon: float) -> float:
        """Return the variance of Laplace noise: 2 * (sensitivity/epsilon)^2."""
        scale = sensitivity / epsilon
        return 2 * scale * scale


class GaussianMechanism:
    """
    Gaussian mechanism for (ε, δ)-differential privacy.

    Adds N(0, σ²) noise where σ is calibrated to (ε, δ).
    Suitable for sum and average queries.
    """

    @staticmethod
    def compute_sigma(sensitivity: float, epsilon: float, delta: float) -> float:
        """
        Compute the standard deviation for the Gaussian mechanism.

        Uses the analytic Gaussian mechanism calibration:
        σ = sensitivity * sqrt(2 * ln(1.25/δ)) / ε

        Args:
            sensitivity: L2 sensitivity of the query
            epsilon: Privacy parameter
            delta: Failure probability parameter

        Returns:
            Standard deviation σ
        """
        if epsilon <= 0:
            raise ValueError("Epsilon must be positive")
        if delta <= 0 or delta >= 1:
            raise ValueError("Delta must be in (0, 1)")
        if sensitivity < 0:
            raise ValueError("Sensitivity must be non-negative")

        return sensitivity * math.sqrt(2 * math.log(1.25 / delta)) / epsilon

    @staticmethod
    def add_noise(value: float, sensitivity: float, epsilon: float, delta: float = 1e-5) -> float:
        """
        Add Gaussian noise to a value.

        Args:
            value: True query result
            sensitivity: L2 sensitivity of the query
            epsilon: Privacy parameter
            delta: Failure probability (default 1e-5)

        Returns:
            Noised value with (ε, δ)-differential privacy guarantee
        """
        sigma = GaussianMechanism.compute_sigma(sensitivity, epsilon, delta)
        # Box-Muller transform using secure random
        u1 = _secure_random_float()
        u2 = _secure_random_float()
        while u1 == 0.0:
            u1 = _secure_random_float()
        z = math.sqrt(-2 * math.log(u1)) * math.cos(2 * math.pi * u2)
        noise = sigma * z
        return value + noise

    @staticmethod
    def variance(sensitivity: float, epsilon: float, delta: float = 1e-5) -> float:
        """Return the variance of Gaussian noise: σ²."""
        sigma = GaussianMechanism.compute_sigma(sensitivity, epsilon, delta)
        return sigma * sigma


class ExponentialMechanism:
    """
    Exponential mechanism for non-numeric queries with pure ε-differential privacy.

    Selects an output from a set of candidates with probability proportional to
    exp(ε * utility / (2 * sensitivity)).
    """

    @staticmethod
    def select(
        candidates: list[Any],
        utility_fn: Callable[[Any], float],
        sensitivity: float,
        epsilon: float,
    ) -> Any:
        """
        Select a candidate using the exponential mechanism.

        Args:
            candidates: List of possible outputs
            utility_fn: Function mapping candidate -> utility score (higher = better)
            sensitivity: Sensitivity of the utility function
            epsilon: Privacy parameter

        Returns:
            Selected candidate with ε-differential privacy guarantee
        """
        if epsilon <= 0:
            raise ValueError("Epsilon must be positive")
        if sensitivity < 0:
            raise ValueError("Sensitivity must be non-negative")
        if not candidates:
            raise ValueError("Candidates list must not be empty")

        # Compute log-weights for numerical stability
        scores = [utility_fn(c) for c in candidates]
        log_weights = [(epsilon * s) / (2 * sensitivity) for s in scores]

        # Subtract max for numerical stability (log-sum-exp trick)
        max_log_weight = max(log_weights)
        weights = [math.exp(lw - max_log_weight) for lw in log_weights]
        total = sum(weights)
        probabilities = [w / total for w in weights]

        # Sample using cryptographic randomness
        r = _secure_random_float()
        cumulative = 0.0
        for i, p in enumerate(probabilities):
            cumulative += p
            if r < cumulative:
                return candidates[i]

        # Fallback to last candidate (floating point edge case)
        return candidates[-1]


class PrivacyBudgetTracker:
    """
    Per-tenant privacy budget (epsilon) tracker.

    Tracks cumulative epsilon consumption using basic composition.
    Issues warnings when budget is running low and rejects queries
    when the budget is exhausted.
    """

    DEFAULT_BUDGET = 10.0
    WARNING_THRESHOLD = 0.2  # Warn when 20% of budget remains

    def __init__(self, total_epsilon: float = None):
        """
        Initialize the budget tracker.

        Args:
            total_epsilon: Total privacy budget. Defaults to DEFAULT_BUDGET.
        """
        if total_epsilon is not None and total_epsilon <= 0:
            raise ValueError("Total epsilon budget must be positive")
        self._total_epsilon = total_epsilon or self.DEFAULT_BUDGET
        self._tenants: dict[str, _TenantBudget] = {}
        self._lock = threading.RLock()

    @property
    def total_epsilon(self) -> float:
        """Total epsilon budget for new tenants."""
        return self._total_epsilon

    def register_tenant(self, tenant_id: str, epsilon_budget: float = None) -> None:
        """
        Register a tenant with a privacy budget.

        Args:
            tenant_id: Unique tenant identifier
            epsilon_budget: Custom budget for this tenant. Uses default if None.
        """
        budget = epsilon_budget if epsilon_budget is not None else self._total_epsilon
        if budget <= 0:
            raise ValueError("Epsilon budget must be positive")
        with self._lock:
            self._tenants[tenant_id] = _TenantBudget(total=budget, consumed=0.0)

    def _ensure_tenant(self, tenant_id: str) -> None:
        """Auto-register a tenant if not already registered."""
        if tenant_id not in self._tenants:
            self.register_tenant(tenant_id)

    def consume(self, tenant_id: str, epsilon: float) -> float:
        """
        Consume epsilon from a tenant's budget.

        Args:
            tenant_id: Tenant identifier
            epsilon: Amount of epsilon to consume

        Returns:
            Remaining epsilon budget

        Raises:
            PrivacyBudgetExhaustedError: If insufficient budget remains
        """
        if epsilon <= 0:
            raise ValueError("Epsilon consumption must be positive")

        with self._lock:
            self._ensure_tenant(tenant_id)
            tb = self._tenants[tenant_id]
            remaining = tb.total - tb.consumed

            if epsilon > remaining:
                raise PrivacyBudgetExhaustedError(
                    f"Tenant '{tenant_id}' has insufficient privacy budget: "
                    f"requested ε={epsilon}, remaining ε={remaining:.4f}"
                )

            tb.consumed += epsilon
            new_remaining = tb.total - tb.consumed

            # Issue warning if budget is running low
            if new_remaining / tb.total <= self.WARNING_THRESHOLD:
                warnings.warn(
                    f"Tenant '{tenant_id}' privacy budget running low: "
                    f"ε={new_remaining:.4f} remaining of {tb.total}",
                    PrivacyBudgetWarning,
                    stacklevel=2,
                )

            return new_remaining

    def remaining(self, tenant_id: str) -> float:
        """
        Get remaining epsilon budget for a tenant.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Remaining epsilon
        """
        with self._lock:
            self._ensure_tenant(tenant_id)
            tb = self._tenants[tenant_id]
            return tb.total - tb.consumed

    def consumed(self, tenant_id: str) -> float:
        """
        Get consumed epsilon for a tenant.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Consumed epsilon
        """
        with self._lock:
            self._ensure_tenant(tenant_id)
            return self._tenants[tenant_id].consumed

    def is_exhausted(self, tenant_id: str) -> bool:
        """
        Check if a tenant's budget is exhausted.

        Args:
            tenant_id: Tenant identifier

        Returns:
            True if no budget remains
        """
        return self.remaining(tenant_id) <= 0

    def reset(self, tenant_id: str) -> None:
        """
        Reset a tenant's consumed budget to zero.

        Args:
            tenant_id: Tenant identifier
        """
        with self._lock:
            self._ensure_tenant(tenant_id)
            self._tenants[tenant_id].consumed = 0.0

    def get_all_tenants(self) -> dict[str, dict[str, float]]:
        """
        Get budget status for all registered tenants.

        Returns:
            Dict mapping tenant_id to {total, consumed, remaining}
        """
        with self._lock:
            return {
                tid: {
                    "total": tb.total,
                    "consumed": tb.consumed,
                    "remaining": tb.total - tb.consumed,
                }
                for tid, tb in self._tenants.items()
            }


class _TenantBudget:
    """Internal budget state for a single tenant."""

    __slots__ = ("total", "consumed")

    def __init__(self, total: float, consumed: float):
        self.total = total
        self.consumed = consumed


class DPQueryInterface:
    """
    Differential privacy query interface for aggregate statistics.

    Provides dp_count(), dp_sum(), dp_average() with automatic
    privacy budget tracking per tenant.
    """

    def __init__(
        self,
        budget_tracker: PrivacyBudgetTracker = None,
        default_delta: float = 1e-5,
    ):
        """
        Initialize the DP query interface.

        Args:
            budget_tracker: Budget tracker instance. Creates new one if None.
            default_delta: Default delta for Gaussian mechanism.
        """
        self.budget_tracker = budget_tracker or PrivacyBudgetTracker()
        self.default_delta = default_delta

    def dp_count(
        self,
        true_count: int,
        epsilon: float,
        tenant_id: str,
        sensitivity: float = 1.0,
    ) -> float:
        """
        Differentially private count query using Laplace mechanism.

        Args:
            true_count: True count result
            epsilon: Privacy parameter for this query
            tenant_id: Tenant whose budget to consume
            sensitivity: Query sensitivity (default 1 for counting queries)

        Returns:
            Noised count with ε-differential privacy

        Raises:
            PrivacyBudgetExhaustedError: If tenant budget insufficient
        """
        self.budget_tracker.consume(tenant_id, epsilon)
        return LaplaceMechanism.add_noise(float(true_count), sensitivity, epsilon)

    def dp_sum(
        self,
        true_sum: float,
        epsilon: float,
        tenant_id: str,
        sensitivity: float = 1.0,
        delta: float = None,
    ) -> float:
        """
        Differentially private sum query using Gaussian mechanism.

        Args:
            true_sum: True sum result
            epsilon: Privacy parameter for this query
            tenant_id: Tenant whose budget to consume
            sensitivity: Query sensitivity (max contribution of one record)
            delta: Failure probability. Uses default_delta if None.

        Returns:
            Noised sum with (ε, δ)-differential privacy

        Raises:
            PrivacyBudgetExhaustedError: If tenant budget insufficient
        """
        delta = delta if delta is not None else self.default_delta
        self.budget_tracker.consume(tenant_id, epsilon)
        return GaussianMechanism.add_noise(true_sum, sensitivity, epsilon, delta)

    def dp_average(
        self,
        true_average: float,
        count: int,
        epsilon: float,
        tenant_id: str,
        value_range: float = 1.0,
        delta: float = None,
    ) -> float:
        """
        Differentially private average query using Gaussian mechanism.

        The sensitivity for an average query is value_range / count.

        Args:
            true_average: True average result
            count: Number of records in the average
            epsilon: Privacy parameter for this query
            tenant_id: Tenant whose budget to consume
            value_range: Range of possible values (max - min)
            delta: Failure probability. Uses default_delta if None.

        Returns:
            Noised average with (ε, δ)-differential privacy

        Raises:
            PrivacyBudgetExhaustedError: If tenant budget insufficient
            ValueError: If count is less than 1
        """
        if count < 1:
            raise ValueError("Count must be at least 1")

        delta = delta if delta is not None else self.default_delta
        sensitivity = value_range / count
        self.budget_tracker.consume(tenant_id, epsilon)
        return GaussianMechanism.add_noise(true_average, sensitivity, epsilon, delta)

    def dp_select(
        self,
        candidates: list[Any],
        utility_fn: Callable[[Any], float],
        epsilon: float,
        tenant_id: str,
        sensitivity: float = 1.0,
    ) -> Any:
        """
        Differentially private selection using exponential mechanism.

        Args:
            candidates: List of possible outputs
            utility_fn: Function mapping candidate -> utility score
            epsilon: Privacy parameter for this query
            tenant_id: Tenant whose budget to consume
            sensitivity: Sensitivity of the utility function

        Returns:
            Selected candidate with ε-differential privacy

        Raises:
            PrivacyBudgetExhaustedError: If tenant budget insufficient
        """
        self.budget_tracker.consume(tenant_id, epsilon)
        return ExponentialMechanism.select(candidates, utility_fn, sensitivity, epsilon)
