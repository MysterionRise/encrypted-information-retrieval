"""
Differential Privacy Module (research prototype, not audited)

Implements differential privacy mechanisms for aggregate statistics over encrypted data
to prevent statistical inference attacks.

Mechanisms:
- Laplace mechanism for count queries (pure ε-DP)
- Gaussian mechanism for sum/average queries ((ε, δ)-DP), using the classical
  calibration σ = Δ₂·sqrt(2·ln(1.25/δ))/ε (Dwork & Roth 2014, Theorem A.1). That bound
  holds only for 0 < ε < 1, so other ε values are rejected. It is not the analytic
  Gaussian mechanism of Balle & Wang (2018).
- Exponential mechanism for non-numeric queries (pure ε-DP)

Sensitivity: the Laplace and Gaussian mechanisms accept sensitivity 0 and then add no
noise. A query whose output cannot change between neighbouring datasets is a constant,
and releasing a constant is 0-DP. The exponential mechanism rejects sensitivity <= 0,
because its weights exp(ε·u/(2Δu)) are undefined for Δu = 0.

Budget tracking (PrivacyBudgetTracker):
- Tenants must be registered explicitly; an unknown tenant raises KeyError instead of
  receiving a fresh default budget.
- Both ε and δ are tracked under basic (sequential) composition. Gaussian queries
  consume δ as well as ε.
- Re-registering a tenant raises ValueError unless ``replace=True``, and replacing keeps
  the consumption already recorded, because privacy loss that has happened cannot be
  undone. Only reset_tenant_budget(), an explicit administrative action, forgets it.
- Accounting uses floating point with a relative tolerance of 1e-9, so a budget can be
  consumed exactly (for example ten queries of δ=1e-5 against δ=1e-4).

Known limitation: noise is sampled with IEEE-754 floating point (inverse-CDF Laplace,
Box-Muller Gaussian). Mironov (CCS 2012) showed that the gaps in floating-point outputs
can reveal the true value, which breaks the DP guarantee. A production implementation
needs a snapping mechanism or discrete Laplace/Gaussian sampling (Canonne, Kamath and
Steinke 2020). This module does neither.

Use Case: Privacy-preserving analytics on encrypted financial data,
aggregate reporting with formal privacy guarantees.

References:
- Dwork & Roth (2014): "The Algorithmic Foundations of Differential Privacy"
- Balle & Wang (2018): "Improving the Gaussian Mechanism for Differential Privacy"
- Mironov (2012): "On Significance of the Least Significant Bits for Differential Privacy"
- Canonne, Kamath & Steinke (2020): "The Discrete Gaussian for Differential Privacy"
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
    Gaussian mechanism for (ε, δ)-differential privacy, classical calibration.

    Adds N(0, σ²) noise with σ = Δ₂·sqrt(2·ln(1.25/δ))/ε (Dwork & Roth 2014,
    Theorem A.1). The theorem holds only for 0 < ε < 1, which is enforced.
    Suitable for sum and average queries.
    """

    @staticmethod
    def compute_sigma(sensitivity: float, epsilon: float, delta: float) -> float:
        """
        Compute the standard deviation for the Gaussian mechanism.

        Uses the classical calibration σ = sensitivity * sqrt(2 * ln(1.25/δ)) / ε,
        which gives (ε, δ)-DP only for 0 < ε < 1. It is not the analytic Gaussian
        mechanism (Balle & Wang 2018).

        Args:
            sensitivity: L2 sensitivity of the query
            epsilon: Privacy parameter, 0 < ε < 1
            delta: Failure probability parameter, 0 < δ < 1

        Returns:
            Standard deviation σ

        Raises:
            ValueError: If ε is not in (0, 1), δ is not in (0, 1), or the
                sensitivity is negative.
        """
        if not 0 < epsilon < 1:
            raise ValueError(
                "Epsilon must be positive and below 1: the classical Gaussian "
                f"calibration is only valid for 0 < epsilon < 1, got {epsilon}"
            )
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
            epsilon: Privacy parameter, 0 < ε < 1
            delta: Failure probability (default 1e-5)

        Returns:
            Noised value with (ε, δ)-differential privacy guarantee (subject to the
            floating-point limitation in the module docstring)
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
            sensitivity: Sensitivity of the utility function, > 0
            epsilon: Privacy parameter

        Returns:
            Selected candidate with ε-differential privacy guarantee

        Raises:
            ValueError: If ε <= 0, sensitivity <= 0 (the weights divide by it), or
                there are no candidates.
        """
        if epsilon <= 0:
            raise ValueError("Epsilon must be positive")
        if sensitivity <= 0:
            raise ValueError("Sensitivity must be positive for the exponential mechanism")
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


_BUDGET_REL_TOLERANCE = 1e-9


def _fits(consumed: float, requested: float, total: float) -> bool:
    """True if ``requested`` fits in what is left of ``total`` (with float tolerance)."""
    return consumed + requested <= total * (1 + _BUDGET_REL_TOLERANCE)


class PrivacyBudgetTracker:
    """
    Per-tenant privacy budget (ε and δ) tracker.

    Tracks cumulative ε and δ consumption using basic composition. Issues
    warnings when the ε budget is running low and rejects queries when either
    budget would be exceeded.

    Tenants must be registered with register_tenant() before they consume
    budget; an unknown tenant raises KeyError.
    """

    DEFAULT_BUDGET = 10.0
    DEFAULT_DELTA_BUDGET = 1e-4
    WARNING_THRESHOLD = 0.2  # Warn when 20% of budget remains

    def __init__(self, total_epsilon: float = None, total_delta: float = None):
        """
        Initialize the budget tracker.

        Args:
            total_epsilon: Default ε budget for newly registered tenants.
                Defaults to DEFAULT_BUDGET.
            total_delta: Default δ budget for newly registered tenants, in [0, 1).
                Defaults to DEFAULT_DELTA_BUDGET. 0 allows only pure ε-DP queries.
        """
        if total_epsilon is not None and total_epsilon <= 0:
            raise ValueError("Total epsilon budget must be positive")
        if total_delta is not None and not 0 <= total_delta < 1:
            raise ValueError("Total delta budget must be in [0, 1)")
        self._total_epsilon = total_epsilon or self.DEFAULT_BUDGET
        self._total_delta = self.DEFAULT_DELTA_BUDGET if total_delta is None else total_delta
        self._tenants: dict[str, _TenantBudget] = {}
        self._lock = threading.RLock()

    @property
    def total_epsilon(self) -> float:
        """Default ε budget for new tenants."""
        return self._total_epsilon

    @property
    def total_delta(self) -> float:
        """Default δ budget for new tenants."""
        return self._total_delta

    def register_tenant(
        self,
        tenant_id: str,
        epsilon_budget: float = None,
        delta_budget: float = None,
        replace: bool = False,
    ) -> None:
        """
        Register a tenant with a privacy budget.

        Args:
            tenant_id: Unique tenant identifier
            epsilon_budget: ε budget for this tenant. Uses the tracker default if None.
            delta_budget: δ budget for this tenant, in [0, 1). Uses the tracker
                default if None.
            replace: Allow changing the budget of an already registered tenant. The
                consumption recorded so far is kept: privacy loss that has happened
                cannot be undone by re-registering.

        Raises:
            ValueError: If a budget is out of range, or the tenant is already
                registered and ``replace`` is False.
        """
        budget = epsilon_budget if epsilon_budget is not None else self._total_epsilon
        if budget <= 0:
            raise ValueError("Epsilon budget must be positive")
        delta = delta_budget if delta_budget is not None else self._total_delta
        if not 0 <= delta < 1:
            raise ValueError("Delta budget must be in [0, 1)")
        with self._lock:
            existing = self._tenants.get(tenant_id)
            if existing is None:
                self._tenants[tenant_id] = _TenantBudget(total=budget, total_delta=delta)
            elif replace:
                existing.total = budget
                existing.total_delta = delta
            else:
                raise ValueError(
                    f"Tenant '{tenant_id}' is already registered; pass replace=True to "
                    "change its budget (consumption is kept)"
                )

    def is_registered(self, tenant_id: str) -> bool:
        """Return True if ``tenant_id`` has been registered."""
        with self._lock:
            return tenant_id in self._tenants

    def _get_tenant(self, tenant_id: str) -> _TenantBudget:
        """Return the tenant's budget; the caller holds the lock."""
        try:
            return self._tenants[tenant_id]
        except KeyError:
            raise KeyError(
                f"Tenant '{tenant_id}' is not registered; call register_tenant() first"
            ) from None

    def consume(self, tenant_id: str, epsilon: float, delta: float = 0.0) -> float:
        """
        Consume ε (and optionally δ) from a tenant's budget, atomically.

        Args:
            tenant_id: Tenant identifier
            epsilon: Amount of ε to consume (> 0)
            delta: Amount of δ to consume (>= 0; Gaussian queries pass their δ)

        Returns:
            Remaining ε budget

        Raises:
            KeyError: If the tenant is not registered
            ValueError: If ε <= 0 or δ is outside [0, 1)
            PrivacyBudgetExhaustedError: If insufficient ε or δ remains. Nothing is
                consumed in that case.
        """
        if epsilon <= 0:
            raise ValueError("Epsilon consumption must be positive")
        if not 0 <= delta < 1:
            raise ValueError("Delta consumption must be in [0, 1)")

        with self._lock:
            tb = self._get_tenant(tenant_id)

            if not _fits(tb.consumed, epsilon, tb.total):
                raise PrivacyBudgetExhaustedError(
                    f"Tenant '{tenant_id}' has insufficient privacy budget: "
                    f"requested ε={epsilon}, remaining ε={tb.total - tb.consumed:.4f}"
                )
            if delta > 0 and not _fits(tb.consumed_delta, delta, tb.total_delta):
                raise PrivacyBudgetExhaustedError(
                    f"Tenant '{tenant_id}' has insufficient δ budget: "
                    f"requested δ={delta}, remaining δ={tb.total_delta - tb.consumed_delta:.3g}"
                )

            tb.consumed += epsilon
            tb.consumed_delta += delta
            new_remaining = max(tb.total - tb.consumed, 0.0)

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
        Get remaining ε budget for a tenant.

        Raises:
            KeyError: If the tenant is not registered
        """
        with self._lock:
            tb = self._get_tenant(tenant_id)
            return max(tb.total - tb.consumed, 0.0)

    def consumed(self, tenant_id: str) -> float:
        """
        Get consumed ε for a tenant.

        Raises:
            KeyError: If the tenant is not registered
        """
        with self._lock:
            return self._get_tenant(tenant_id).consumed

    def remaining_delta(self, tenant_id: str) -> float:
        """
        Get remaining δ budget for a tenant.

        Raises:
            KeyError: If the tenant is not registered
        """
        with self._lock:
            tb = self._get_tenant(tenant_id)
            return max(tb.total_delta - tb.consumed_delta, 0.0)

    def consumed_delta(self, tenant_id: str) -> float:
        """
        Get consumed δ for a tenant.

        Raises:
            KeyError: If the tenant is not registered
        """
        with self._lock:
            return self._get_tenant(tenant_id).consumed_delta

    def is_exhausted(self, tenant_id: str) -> bool:
        """
        Check if a tenant's ε budget is exhausted.

        Raises:
            KeyError: If the tenant is not registered
        """
        with self._lock:
            tb = self._get_tenant(tenant_id)
            return tb.total - tb.consumed <= tb.total * _BUDGET_REL_TOLERANCE

    def reset_tenant_budget(self, tenant_id: str) -> None:
        """
        Administrative action: forget a tenant's recorded ε and δ consumption.

        This does not undo any privacy loss. Every answer already released stays
        released, so after a reset the real cumulative loss exceeds the budget.
        Use it only for a new accounting period over fresh data, and audit it.

        Raises:
            KeyError: If the tenant is not registered
        """
        with self._lock:
            tb = self._get_tenant(tenant_id)
            tb.consumed = 0.0
            tb.consumed_delta = 0.0

    def get_all_tenants(self) -> dict[str, dict[str, float]]:
        """
        Get budget status for all registered tenants.

        Returns:
            Dict mapping tenant_id to {total, consumed, remaining, total_delta,
            consumed_delta, remaining_delta}
        """
        with self._lock:
            return {
                tid: {
                    "total": tb.total,
                    "consumed": tb.consumed,
                    "remaining": max(tb.total - tb.consumed, 0.0),
                    "total_delta": tb.total_delta,
                    "consumed_delta": tb.consumed_delta,
                    "remaining_delta": max(tb.total_delta - tb.consumed_delta, 0.0),
                }
                for tid, tb in self._tenants.items()
            }


class _TenantBudget:
    """Internal budget state for a single tenant."""

    __slots__ = ("total", "consumed", "total_delta", "consumed_delta")

    def __init__(self, total: float, total_delta: float):
        self.total = total
        self.consumed = 0.0
        self.total_delta = total_delta
        self.consumed_delta = 0.0


class DPQueryInterface:
    """
    Differential privacy query interface for aggregate statistics.

    Provides dp_count(), dp_sum(), dp_average() and dp_select() with privacy
    budget tracking per registered tenant. Gaussian queries (sum, average)
    consume δ as well as ε.
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
            tenant_id: Registered tenant whose budget to consume
            sensitivity: Query sensitivity (default 1 for counting queries)

        Returns:
            Noised count with ε-differential privacy

        Raises:
            KeyError: If the tenant is not registered
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
            epsilon: Privacy parameter for this query, 0 < ε < 1
            tenant_id: Registered tenant whose budget to consume
            sensitivity: Query sensitivity (max contribution of one record)
            delta: Failure probability. Uses default_delta if None.

        Returns:
            Noised sum with (ε, δ)-differential privacy

        Raises:
            KeyError: If the tenant is not registered
            ValueError: If ε is not in (0, 1) or δ is not in (0, 1); no budget is consumed
            PrivacyBudgetExhaustedError: If tenant ε or δ budget insufficient
        """
        delta = delta if delta is not None else self.default_delta
        # Validate parameters before consuming budget.
        GaussianMechanism.compute_sigma(sensitivity, epsilon, delta)
        self.budget_tracker.consume(tenant_id, epsilon, delta)
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
            epsilon: Privacy parameter for this query, 0 < ε < 1
            tenant_id: Registered tenant whose budget to consume
            value_range: Range of possible values (max - min)
            delta: Failure probability. Uses default_delta if None.

        Returns:
            Noised average with (ε, δ)-differential privacy

        Raises:
            KeyError: If the tenant is not registered
            PrivacyBudgetExhaustedError: If tenant ε or δ budget insufficient
            ValueError: If count is less than 1, or ε or δ is out of range
        """
        if count < 1:
            raise ValueError("Count must be at least 1")

        delta = delta if delta is not None else self.default_delta
        sensitivity = value_range / count
        GaussianMechanism.compute_sigma(sensitivity, epsilon, delta)
        self.budget_tracker.consume(tenant_id, epsilon, delta)
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
            tenant_id: Registered tenant whose budget to consume
            sensitivity: Sensitivity of the utility function (> 0)

        Returns:
            Selected candidate with ε-differential privacy

        Raises:
            KeyError: If the tenant is not registered
            PrivacyBudgetExhaustedError: If tenant budget insufficient
        """
        self.budget_tracker.consume(tenant_id, epsilon)
        return ExponentialMechanism.select(candidates, utility_fn, sensitivity, epsilon)
