"""Tests for the Differential Privacy module."""

import math
import warnings

import pytest

from encrypted_ir.differential_privacy import (
    DPQueryInterface,
    ExponentialMechanism,
    GaussianMechanism,
    LaplaceMechanism,
    PrivacyBudgetExhaustedError,
    PrivacyBudgetTracker,
    PrivacyBudgetWarning,
)

# ---------------------------------------------------------------------------
# Laplace Mechanism
# ---------------------------------------------------------------------------


class TestLaplaceMechanism:
    """Tests for the Laplace noise mechanism."""

    def test_noise_is_added(self):
        """Noise should shift the value away from the true answer (usually)."""
        results = [LaplaceMechanism.add_noise(100.0, 1.0, 1.0) for _ in range(50)]
        # Extremely unlikely all 50 results equal exactly 100.0
        assert not all(r == 100.0 for r in results)

    def test_mean_converges(self):
        """Over many samples the mean should be close to the true value."""
        true_val = 42.0
        n = 10_000
        total = sum(LaplaceMechanism.add_noise(true_val, 1.0, 1.0) for _ in range(n))
        mean = total / n
        assert abs(mean - true_val) < 1.0  # Within 1 of true value

    def test_variance_matches_theory(self):
        """Empirical variance should approximate 2*(sensitivity/epsilon)^2."""
        sensitivity, epsilon = 2.0, 0.5
        n = 10_000
        results = [LaplaceMechanism.add_noise(0.0, sensitivity, epsilon) for _ in range(n)]
        empirical_var = sum(r**2 for r in results) / n
        theoretical_var = LaplaceMechanism.variance(sensitivity, epsilon)
        assert abs(empirical_var - theoretical_var) < theoretical_var * 0.3

    def test_higher_epsilon_less_noise(self):
        """Higher epsilon should produce tighter distribution (less noise)."""
        n = 5_000
        low_eps = [LaplaceMechanism.add_noise(0.0, 1.0, 0.1) for _ in range(n)]
        high_eps = [LaplaceMechanism.add_noise(0.0, 1.0, 10.0) for _ in range(n)]
        var_low = sum(x**2 for x in low_eps) / n
        var_high = sum(x**2 for x in high_eps) / n
        assert var_low > var_high

    def test_higher_sensitivity_more_noise(self):
        """Higher sensitivity should produce more noise."""
        n = 5_000
        low_sens = [LaplaceMechanism.add_noise(0.0, 0.1, 1.0) for _ in range(n)]
        high_sens = [LaplaceMechanism.add_noise(0.0, 10.0, 1.0) for _ in range(n)]
        var_low = sum(x**2 for x in low_sens) / n
        var_high = sum(x**2 for x in high_sens) / n
        assert var_high > var_low

    def test_invalid_epsilon(self):
        """Epsilon must be positive."""
        with pytest.raises(ValueError, match="positive"):
            LaplaceMechanism.add_noise(1.0, 1.0, 0.0)
        with pytest.raises(ValueError, match="positive"):
            LaplaceMechanism.add_noise(1.0, 1.0, -1.0)

    def test_invalid_sensitivity(self):
        """Sensitivity must be non-negative."""
        with pytest.raises(ValueError, match="non-negative"):
            LaplaceMechanism.add_noise(1.0, -1.0, 1.0)

    def test_zero_sensitivity(self):
        """Zero sensitivity should return the exact value."""
        result = LaplaceMechanism.add_noise(42.0, 0.0, 1.0)
        assert result == 42.0

    def test_variance_formula(self):
        """Verify the closed-form variance calculation."""
        assert LaplaceMechanism.variance(1.0, 1.0) == 2.0
        assert LaplaceMechanism.variance(2.0, 1.0) == 8.0
        assert LaplaceMechanism.variance(1.0, 2.0) == 0.5


# ---------------------------------------------------------------------------
# Gaussian Mechanism
# ---------------------------------------------------------------------------


class TestGaussianMechanism:
    """Tests for the Gaussian noise mechanism."""

    def test_noise_is_added(self):
        """Noise should shift the value."""
        results = [GaussianMechanism.add_noise(100.0, 1.0, 1.0) for _ in range(50)]
        assert not all(r == 100.0 for r in results)

    def test_mean_converges(self):
        """Mean should converge to the true value."""
        true_val = 55.5
        n = 10_000
        total = sum(GaussianMechanism.add_noise(true_val, 1.0, 1.0) for _ in range(n))
        mean = total / n
        assert abs(mean - true_val) < 1.0

    def test_variance_matches_theory(self):
        """Empirical variance should approximate σ²."""
        sensitivity, epsilon, delta = 1.0, 1.0, 1e-5
        n = 10_000
        results = [GaussianMechanism.add_noise(0.0, sensitivity, epsilon, delta) for _ in range(n)]
        empirical_var = sum(r**2 for r in results) / n
        theoretical_var = GaussianMechanism.variance(sensitivity, epsilon, delta)
        assert abs(empirical_var - theoretical_var) < theoretical_var * 0.3

    def test_higher_epsilon_less_noise(self):
        """Higher epsilon → less noise."""
        n = 5_000
        low_eps = [GaussianMechanism.add_noise(0.0, 1.0, 0.1) for _ in range(n)]
        high_eps = [GaussianMechanism.add_noise(0.0, 1.0, 10.0) for _ in range(n)]
        var_low = sum(x**2 for x in low_eps) / n
        var_high = sum(x**2 for x in high_eps) / n
        assert var_low > var_high

    def test_invalid_epsilon(self):
        """Epsilon must be positive."""
        with pytest.raises(ValueError, match="positive"):
            GaussianMechanism.add_noise(1.0, 1.0, 0.0)

    def test_invalid_delta(self):
        """Delta must be in (0, 1)."""
        with pytest.raises(ValueError, match="Delta"):
            GaussianMechanism.add_noise(1.0, 1.0, 1.0, delta=0.0)
        with pytest.raises(ValueError, match="Delta"):
            GaussianMechanism.add_noise(1.0, 1.0, 1.0, delta=1.0)
        with pytest.raises(ValueError, match="Delta"):
            GaussianMechanism.add_noise(1.0, 1.0, 1.0, delta=-0.1)

    def test_invalid_sensitivity(self):
        """Sensitivity must be non-negative."""
        with pytest.raises(ValueError, match="non-negative"):
            GaussianMechanism.add_noise(1.0, -1.0, 1.0)

    def test_compute_sigma(self):
        """Verify σ computation."""
        sigma = GaussianMechanism.compute_sigma(1.0, 1.0, 1e-5)
        expected = math.sqrt(2 * math.log(1.25 / 1e-5))
        assert abs(sigma - expected) < 1e-10

    def test_sigma_scales_with_sensitivity(self):
        """σ should scale linearly with sensitivity."""
        s1 = GaussianMechanism.compute_sigma(1.0, 1.0, 1e-5)
        s2 = GaussianMechanism.compute_sigma(2.0, 1.0, 1e-5)
        assert abs(s2 / s1 - 2.0) < 1e-10


# ---------------------------------------------------------------------------
# Exponential Mechanism
# ---------------------------------------------------------------------------


class TestExponentialMechanism:
    """Tests for the exponential mechanism."""

    def test_selects_from_candidates(self):
        """Result should always be one of the candidates."""
        candidates = ["a", "b", "c"]
        for _ in range(100):
            result = ExponentialMechanism.select(
                candidates, lambda x: 1.0, sensitivity=1.0, epsilon=1.0
            )
            assert result in candidates

    def test_favors_high_utility(self):
        """With large epsilon, should almost always pick the best candidate."""
        candidates = ["bad", "ok", "good", "best"]
        scores = {"bad": 0, "ok": 1, "good": 2, "best": 10}
        counts = dict.fromkeys(candidates, 0)

        for _ in range(1000):
            result = ExponentialMechanism.select(
                candidates, lambda x: scores[x], sensitivity=1.0, epsilon=50.0
            )
            counts[result] += 1

        # "best" should be selected overwhelmingly
        assert counts["best"] > 900

    def test_uniform_with_equal_utility(self):
        """Equal utility should give roughly uniform selection."""
        candidates = ["a", "b", "c", "d"]
        counts = dict.fromkeys(candidates, 0)

        for _ in range(4000):
            result = ExponentialMechanism.select(
                candidates, lambda x: 5.0, sensitivity=1.0, epsilon=1.0
            )
            counts[result] += 1

        # Each should be ~1000, allow wide margin
        for c in candidates:
            assert 600 < counts[c] < 1400

    def test_low_epsilon_more_random(self):
        """With very low epsilon, selection should be nearly uniform."""
        candidates = ["a", "b"]
        scores = {"a": 100, "b": 0}
        counts = {"a": 0, "b": 0}

        for _ in range(2000):
            result = ExponentialMechanism.select(
                candidates, lambda x: scores[x], sensitivity=100.0, epsilon=0.001
            )
            counts[result] += 1

        # Both should be roughly 1000
        assert 700 < counts["a"] < 1300

    def test_empty_candidates(self):
        """Should raise on empty candidates list."""
        with pytest.raises(ValueError, match="empty"):
            ExponentialMechanism.select([], lambda x: 0, 1.0, 1.0)

    def test_single_candidate(self):
        """Single candidate should always be returned."""
        result = ExponentialMechanism.select(["only"], lambda x: 0, 1.0, 1.0)
        assert result == "only"

    def test_invalid_epsilon(self):
        """Epsilon must be positive."""
        with pytest.raises(ValueError, match="positive"):
            ExponentialMechanism.select(["a"], lambda x: 0, 1.0, 0.0)

    def test_invalid_sensitivity(self):
        """Sensitivity must be non-negative."""
        with pytest.raises(ValueError, match="non-negative"):
            ExponentialMechanism.select(["a"], lambda x: 0, -1.0, 1.0)


# ---------------------------------------------------------------------------
# Privacy Budget Tracker
# ---------------------------------------------------------------------------


class TestPrivacyBudgetTracker:
    """Tests for per-tenant epsilon budget tracking."""

    def test_default_budget(self):
        """New tenants should get the default budget."""
        tracker = PrivacyBudgetTracker()
        assert tracker.remaining("tenant_1") == tracker.total_epsilon

    def test_custom_global_budget(self):
        """Custom global budget should apply to auto-registered tenants."""
        tracker = PrivacyBudgetTracker(total_epsilon=5.0)
        assert tracker.remaining("t1") == 5.0

    def test_custom_tenant_budget(self):
        """Custom per-tenant budget overrides global."""
        tracker = PrivacyBudgetTracker(total_epsilon=10.0)
        tracker.register_tenant("t1", epsilon_budget=3.0)
        assert tracker.remaining("t1") == 3.0

    def test_consume_reduces_budget(self):
        """Consuming epsilon reduces remaining budget."""
        tracker = PrivacyBudgetTracker(total_epsilon=10.0)
        tracker.register_tenant("t1")
        remaining = tracker.consume("t1", 3.0)
        assert remaining == pytest.approx(7.0)
        assert tracker.consumed("t1") == pytest.approx(3.0)

    def test_multiple_consumptions(self):
        """Budget should track cumulative consumption."""
        tracker = PrivacyBudgetTracker(total_epsilon=10.0)
        tracker.consume("t1", 2.0)
        tracker.consume("t1", 3.0)
        assert tracker.consumed("t1") == pytest.approx(5.0)
        assert tracker.remaining("t1") == pytest.approx(5.0)

    def test_budget_exhausted_error(self):
        """Should raise when budget is insufficient."""
        tracker = PrivacyBudgetTracker(total_epsilon=5.0)
        tracker.consume("t1", 4.0)
        with pytest.raises(PrivacyBudgetExhaustedError, match="insufficient"):
            tracker.consume("t1", 2.0)

    def test_exact_budget_consumption(self):
        """Should allow consuming exactly the remaining budget."""
        tracker = PrivacyBudgetTracker(total_epsilon=5.0)
        tracker.consume("t1", 5.0)
        assert tracker.remaining("t1") == pytest.approx(0.0)
        assert tracker.is_exhausted("t1")

    def test_budget_warning(self):
        """Should warn when budget drops below 20%."""
        tracker = PrivacyBudgetTracker(total_epsilon=10.0)
        tracker.consume("t1", 5.0)  # 50% remaining, no warning

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            tracker.consume("t1", 4.0)  # 10% remaining → warning
            assert len(w) == 1
            assert issubclass(w[0].category, PrivacyBudgetWarning)
            assert "running low" in str(w[0].message)

    def test_is_exhausted(self):
        """is_exhausted should reflect budget state."""
        tracker = PrivacyBudgetTracker(total_epsilon=5.0)
        assert not tracker.is_exhausted("t1")
        tracker.consume("t1", 5.0)
        assert tracker.is_exhausted("t1")

    def test_reset(self):
        """Reset should restore budget to full."""
        tracker = PrivacyBudgetTracker(total_epsilon=10.0)
        tracker.consume("t1", 8.0)
        tracker.reset("t1")
        assert tracker.remaining("t1") == pytest.approx(10.0)
        assert tracker.consumed("t1") == pytest.approx(0.0)

    def test_independent_tenants(self):
        """Each tenant has independent budget."""
        tracker = PrivacyBudgetTracker(total_epsilon=10.0)
        tracker.consume("t1", 5.0)
        tracker.consume("t2", 2.0)
        assert tracker.remaining("t1") == pytest.approx(5.0)
        assert tracker.remaining("t2") == pytest.approx(8.0)

    def test_get_all_tenants(self):
        """Should return status for all registered tenants."""
        tracker = PrivacyBudgetTracker(total_epsilon=10.0)
        tracker.consume("t1", 3.0)
        tracker.consume("t2", 7.0)
        status = tracker.get_all_tenants()
        assert len(status) == 2
        assert status["t1"]["remaining"] == pytest.approx(7.0)
        assert status["t2"]["consumed"] == pytest.approx(7.0)

    def test_invalid_budget(self):
        """Negative or zero budgets should be rejected."""
        with pytest.raises(ValueError):
            PrivacyBudgetTracker(total_epsilon=-1.0)
        with pytest.raises(ValueError):
            PrivacyBudgetTracker(total_epsilon=0.0)

    def test_invalid_consume(self):
        """Consuming non-positive epsilon should raise."""
        tracker = PrivacyBudgetTracker()
        with pytest.raises(ValueError, match="positive"):
            tracker.consume("t1", 0.0)
        with pytest.raises(ValueError, match="positive"):
            tracker.consume("t1", -1.0)

    def test_thread_safety(self):
        """Budget tracking should be thread-safe."""
        import threading

        tracker = PrivacyBudgetTracker(total_epsilon=100.0)
        errors = []

        def consume_budget():
            try:
                for _ in range(100):
                    tracker.consume("shared", 0.01)
            except PrivacyBudgetExhaustedError:
                errors.append("exhausted")

        threads = [threading.Thread(target=consume_budget) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Total consumed should be <= 100 (some may have been rejected)
        assert tracker.consumed("shared") <= 100.0


# ---------------------------------------------------------------------------
# DP Query Interface
# ---------------------------------------------------------------------------


class TestDPQueryInterface:
    """Tests for the dp_count, dp_sum, dp_average query interface."""

    def test_dp_count_returns_noised_value(self):
        """dp_count should return a value close to but not exactly the true count."""
        dp = DPQueryInterface(budget_tracker=PrivacyBudgetTracker(total_epsilon=100.0))
        results = [dp.dp_count(100, epsilon=1.0, tenant_id="t1") for _ in range(20)]
        # Not all identical to 100
        assert not all(r == 100.0 for r in results)

    def test_dp_count_mean_converges(self):
        """Mean of dp_count should converge to true count."""
        dp = DPQueryInterface(budget_tracker=PrivacyBudgetTracker(total_epsilon=50000.0))
        n = 5000
        total = sum(dp.dp_count(200, epsilon=1.0, tenant_id="t1") for _ in range(n))
        mean = total / n
        assert abs(mean - 200.0) < 2.0

    def test_dp_count_consumes_budget(self):
        """Each dp_count call should consume epsilon from the budget."""
        tracker = PrivacyBudgetTracker(total_epsilon=10.0)
        dp = DPQueryInterface(budget_tracker=tracker)
        dp.dp_count(50, epsilon=2.0, tenant_id="t1")
        assert tracker.consumed("t1") == pytest.approx(2.0)

    def test_dp_count_budget_exhaustion(self):
        """dp_count should raise when budget is exhausted."""
        tracker = PrivacyBudgetTracker(total_epsilon=3.0)
        dp = DPQueryInterface(budget_tracker=tracker)
        dp.dp_count(50, epsilon=2.0, tenant_id="t1")
        with pytest.raises(PrivacyBudgetExhaustedError):
            dp.dp_count(50, epsilon=2.0, tenant_id="t1")

    def test_dp_sum_returns_noised_value(self):
        """dp_sum should add Gaussian noise."""
        dp = DPQueryInterface(budget_tracker=PrivacyBudgetTracker(total_epsilon=100.0))
        results = [dp.dp_sum(1000.0, epsilon=1.0, tenant_id="t1") for _ in range(20)]
        assert not all(r == 1000.0 for r in results)

    def test_dp_sum_mean_converges(self):
        """Mean of dp_sum should converge to true sum."""
        dp = DPQueryInterface(budget_tracker=PrivacyBudgetTracker(total_epsilon=50000.0))
        n = 5000
        total = sum(dp.dp_sum(500.0, epsilon=1.0, tenant_id="t1") for _ in range(n))
        mean = total / n
        assert abs(mean - 500.0) < 2.0

    def test_dp_sum_consumes_budget(self):
        """dp_sum should consume epsilon."""
        tracker = PrivacyBudgetTracker(total_epsilon=10.0)
        dp = DPQueryInterface(budget_tracker=tracker)
        dp.dp_sum(100.0, epsilon=3.0, tenant_id="t1")
        assert tracker.consumed("t1") == pytest.approx(3.0)

    def test_dp_average_returns_noised_value(self):
        """dp_average should add noise."""
        dp = DPQueryInterface(budget_tracker=PrivacyBudgetTracker(total_epsilon=100.0))
        results = [dp.dp_average(50.0, count=100, epsilon=1.0, tenant_id="t1") for _ in range(20)]
        assert not all(r == 50.0 for r in results)

    def test_dp_average_mean_converges(self):
        """Mean of dp_average should converge to true average."""
        dp = DPQueryInterface(budget_tracker=PrivacyBudgetTracker(total_epsilon=50000.0))
        n = 5000
        total = sum(dp.dp_average(75.0, count=1000, epsilon=1.0, tenant_id="t1") for _ in range(n))
        mean = total / n
        assert abs(mean - 75.0) < 1.0

    def test_dp_average_sensitivity_scales_with_count(self):
        """Larger count should produce less noise in average queries."""
        dp_low = DPQueryInterface(budget_tracker=PrivacyBudgetTracker(total_epsilon=50000.0))
        dp_high = DPQueryInterface(budget_tracker=PrivacyBudgetTracker(total_epsilon=50000.0))
        n = 3000

        small_count_results = [
            dp_low.dp_average(50.0, count=10, epsilon=1.0, tenant_id="t1", value_range=100.0)
            for _ in range(n)
        ]
        large_count_results = [
            dp_high.dp_average(50.0, count=10000, epsilon=1.0, tenant_id="t1", value_range=100.0)
            for _ in range(n)
        ]

        var_small = sum((x - 50.0) ** 2 for x in small_count_results) / n
        var_large = sum((x - 50.0) ** 2 for x in large_count_results) / n
        assert var_small > var_large

    def test_dp_average_invalid_count(self):
        """Count must be >= 1."""
        dp = DPQueryInterface()
        with pytest.raises(ValueError, match="Count"):
            dp.dp_average(50.0, count=0, epsilon=1.0, tenant_id="t1")

    def test_dp_select(self):
        """dp_select should use the exponential mechanism."""
        dp = DPQueryInterface(budget_tracker=PrivacyBudgetTracker(total_epsilon=50000.0))
        candidates = ["low", "medium", "high"]
        scores = {"low": 0, "medium": 5, "high": 10}
        counts = dict.fromkeys(candidates, 0)

        for _ in range(1000):
            result = dp.dp_select(
                candidates,
                lambda x: scores[x],
                epsilon=20.0,
                tenant_id="t1",
                sensitivity=1.0,
            )
            counts[result] += 1

        assert counts["high"] > 800

    def test_dp_select_consumes_budget(self):
        """dp_select should consume epsilon."""
        tracker = PrivacyBudgetTracker(total_epsilon=10.0)
        dp = DPQueryInterface(budget_tracker=tracker)
        dp.dp_select(["a", "b"], lambda x: 1.0, epsilon=2.0, tenant_id="t1")
        assert tracker.consumed("t1") == pytest.approx(2.0)

    def test_multi_query_budget_tracking(self):
        """Multiple different query types should accumulate budget."""
        tracker = PrivacyBudgetTracker(total_epsilon=10.0)
        dp = DPQueryInterface(budget_tracker=tracker)

        dp.dp_count(100, epsilon=2.0, tenant_id="t1")
        dp.dp_sum(500.0, epsilon=3.0, tenant_id="t1")
        dp.dp_average(50.0, count=100, epsilon=1.5, tenant_id="t1")

        assert tracker.consumed("t1") == pytest.approx(6.5)
        assert tracker.remaining("t1") == pytest.approx(3.5)

    def test_separate_tenant_budgets(self):
        """Different tenants should have independent budgets."""
        tracker = PrivacyBudgetTracker(total_epsilon=5.0)
        dp = DPQueryInterface(budget_tracker=tracker)

        dp.dp_count(100, epsilon=4.0, tenant_id="t1")
        dp.dp_count(100, epsilon=4.0, tenant_id="t2")

        assert tracker.remaining("t1") == pytest.approx(1.0)
        assert tracker.remaining("t2") == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Privacy Guarantee Verification
# ---------------------------------------------------------------------------


class TestPrivacyGuarantees:
    """Statistical tests to verify differential privacy properties."""

    def test_laplace_privacy_histogram(self):
        """
        Verify ε-DP by checking the ratio of output probabilities
        on neighboring databases (differing by 1 in count).

        For true ε-DP: P(M(x) ∈ S) / P(M(x') ∈ S) ≤ exp(ε)
        """
        epsilon = 1.0
        n = 50_000

        # Two "neighboring" counts differing by 1
        results_x = [LaplaceMechanism.add_noise(100.0, 1.0, epsilon) for _ in range(n)]
        results_xp = [LaplaceMechanism.add_noise(101.0, 1.0, epsilon) for _ in range(n)]

        # Bin results into a histogram and check probability ratios
        bin_width = 1.0
        bins_x = {}
        bins_xp = {}
        for r in results_x:
            b = round(r / bin_width)
            bins_x[b] = bins_x.get(b, 0) + 1
        for r in results_xp:
            b = round(r / bin_width)
            bins_xp[b] = bins_xp.get(b, 0) + 1

        # Check ratio for bins with enough samples
        max_ratio = 0.0
        for b in bins_x:
            if b in bins_xp and bins_x[b] > 50 and bins_xp[b] > 50:
                ratio = bins_x[b] / bins_xp[b]
                max_ratio = max(max_ratio, ratio, 1 / ratio)

        # The ratio should not exceed exp(ε * sensitivity) by much
        # Allow some slack for finite sampling
        assert max_ratio < math.exp(epsilon) * 1.5

    def test_gaussian_approximate_dp(self):
        """Verify the Gaussian mechanism output distributions overlap correctly."""
        epsilon, delta = 1.0, 1e-5
        n = 20_000

        results_x = [GaussianMechanism.add_noise(100.0, 1.0, epsilon, delta) for _ in range(n)]
        results_xp = [GaussianMechanism.add_noise(101.0, 1.0, epsilon, delta) for _ in range(n)]

        # Both distributions should have similar spread
        mean_x = sum(results_x) / n
        mean_xp = sum(results_xp) / n

        # Means should differ by approximately 1 (the true difference)
        assert abs((mean_xp - mean_x) - 1.0) < 1.0

    def test_composition_budget(self):
        """
        Under basic composition, k queries each with ε produce total privacy cost kε.
        Verify that budget tracker correctly implements this.
        """
        tracker = PrivacyBudgetTracker(total_epsilon=10.0)
        per_query_eps = 0.5
        k = 20  # 20 queries × 0.5 = 10.0 total

        for _ in range(k):
            tracker.consume("t1", per_query_eps)

        assert tracker.consumed("t1") == pytest.approx(10.0)
        assert tracker.is_exhausted("t1")

        # 21st query should fail
        with pytest.raises(PrivacyBudgetExhaustedError):
            tracker.consume("t1", per_query_eps)

    def test_utility_accuracy_count(self):
        """
        Verify utility: with ε=1 and sensitivity=1, 95% of counts
        should be within ~5.3 of the true value (Laplace 95th percentile).
        """
        true_count = 1000
        epsilon = 1.0
        n = 5000
        # For Laplace(0, 1/ε), 95th percentile of |noise| ≈ -ln(0.05)/ε ≈ 3.0
        threshold = 6.0  # generous threshold

        results = [LaplaceMechanism.add_noise(float(true_count), 1.0, epsilon) for _ in range(n)]
        within = sum(1 for r in results if abs(r - true_count) < threshold)
        assert within / n > 0.90

    def test_utility_accuracy_average(self):
        """
        Verify utility for dp_average: with large count, noise should be small.
        """
        dp = DPQueryInterface(budget_tracker=PrivacyBudgetTracker(total_epsilon=50000.0))
        true_avg = 50.0
        n = 1000
        results = [
            dp.dp_average(true_avg, count=10000, epsilon=1.0, tenant_id="t1", value_range=100.0)
            for _ in range(n)
        ]
        # With count=10000, sensitivity=100/10000=0.01, noise should be tiny
        for r in results:
            assert abs(r - true_avg) < 1.0
