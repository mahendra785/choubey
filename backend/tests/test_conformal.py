"""Conformal prediction: guarantee checked empirically over 200 random seeds on synthetic data."""
import math

import numpy as np
import pytest

from app.defenses.conformal import BENIGN, INJECTION, MondrianConformal, quantile_rank


def _draw(rng, n_per_class):
    """Synthetic 'classifier outputs': benign ~ Beta(1.5, 5), injection ~ Beta(5, 1.5) (overlapping on purpose)."""
    probs = np.concatenate([rng.beta(1.5, 5, n_per_class), rng.beta(5, 1.5, n_per_class)])
    labels = np.concatenate([np.zeros(n_per_class), np.ones(n_per_class)]).astype(int)
    return probs, labels


def test_quantile_rank_finite_sample_correction():
    assert quantile_rank(9, 0.1) == 9  # ceil(10 * 0.9)
    assert quantile_rank(99, 0.1) == 90
    assert quantile_rank(100, 0.05) == math.ceil(101 * 0.95)


@pytest.mark.parametrize("alpha", [0.01, 0.05, 0.1, 0.2])
def test_class_conditional_coverage_over_200_seeds(alpha):
    n_cal, n_test = 400, 1500
    cov_b, cov_i, sizes = [], [], []
    for seed in range(200):
        rng = np.random.default_rng(seed)
        cp = MondrianConformal().calibrate(*_draw(rng, n_cal), alpha)
        tp, tl = _draw(rng, n_test)
        stats = MondrianConformal.evaluate(cp.predict_sets(tp), tl)
        cov_b.append(stats["coverage_benign"])
        cov_i.append(stats["coverage_injection"])
        sizes.append(stats["avg_set_size"])
    target = 1 - alpha
    # Guarantee: E[coverage] >= 1 - alpha for EACH class. Allow tiny Monte-Carlo slack (0.004).
    assert np.mean(cov_b) >= target - 0.004, (alpha, np.mean(cov_b))
    assert np.mean(cov_i) >= target - 0.004, (alpha, np.mean(cov_i))
    # ...and it should not be wildly conservative either: within 1/(n+1) + slack above the target.
    assert np.mean(cov_i) <= target + 1 / (n_cal + 1) + 0.01
    assert 0.5 < np.mean(sizes) < 2.0


def test_smaller_alpha_means_larger_sets():
    rng = np.random.default_rng(1)
    probs, labels = _draw(rng, 500)
    tp, _ = _draw(np.random.default_rng(2), 500)
    sizes = [np.mean([len(s) for s in MondrianConformal().calibrate(probs, labels, a).predict_sets(tp)]) for a in (0.2, 0.1, 0.05, 0.01)]
    assert sizes == sorted(sizes)


def test_too_few_calibration_points_gives_infinite_quantile_and_full_set():
    cp = MondrianConformal().calibrate(np.array([0.1, 0.9]), np.array([0, 1]), alpha=0.01)  # ceil(2*.99)=2 > n=1
    assert cp.qhat[BENIGN] == math.inf and cp.qhat[INJECTION] == math.inf
    assert cp.predict_set(0.5) == frozenset({BENIGN, INJECTION})


def test_empty_set_possible_and_error_handling():
    cp = MondrianConformal()
    cp.qhat = {BENIGN: 0.1, INJECTION: 0.1}  # very strict thresholds on both classes
    assert cp.predict_set(0.5) == frozenset()  # neither label plausible -> cascade escalates
    with pytest.raises(RuntimeError):
        MondrianConformal().predict_set(0.5)
    with pytest.raises(ValueError):
        MondrianConformal().calibrate(np.array([0.5]), np.array([1]), alpha=1.5)
    with pytest.raises(ValueError):
        MondrianConformal().calibrate(np.array([0.5, 0.6]), np.array([1]), alpha=0.1)


def test_confident_examples_get_singleton_sets():
    rng = np.random.default_rng(0)
    cp = MondrianConformal().calibrate(*_draw(rng, 500), 0.1)
    assert cp.predict_set(0.001) == frozenset({BENIGN})
    assert cp.predict_set(0.999) == frozenset({INJECTION})
