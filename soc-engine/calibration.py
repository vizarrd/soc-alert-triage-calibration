"""Recall-guaranteed alert threshold from a few analyst-labelled alerts.

Implements the distribution-free order-statistic rule used in the paper (a one-sided nonparametric
tolerance bound, cf. Wilks 1941 and the Neyman-Pearson umbrella algorithm of Tong et al. 2018):

    Given the frozen model's attack scores of n analyst-labelled attacks (drawn at random from the
    target alert stream), choose the largest rank r with  I_{1-rho}(r, n-r+1) >= 1-delta  and use
    threshold t = r-th smallest labelled attack score.  Then, under (A1) the labelled alerts are a
    uniform random sample of the stream, (A2) labels are correct, (A3) the model and the attack
    score distribution do not change afterwards, the stream's true recall at t is >= rho with
    probability >= 1-delta.  If n is too small (n < ceil(ln(delta)/ln(rho)), 22 for rho=.9, delta=.1)
    no certification is possible and the threshold falls back to -inf (flag everything).

Run `python calibration.py` for a self-test (coverage on synthetic scores)."""
import math
import numpy as np
from scipy.stats import beta


def min_attacks(rho=0.90, delta=0.10):
    """Smallest number of labelled attacks for which certification is possible."""
    return math.ceil(math.log(delta) / math.log(rho))


def guaranteed_threshold(attack_scores, rho=0.90, delta=0.10):
    """Return (threshold, certified). Alerts with score >= threshold are sent to the analyst."""
    pos = np.sort(np.asarray(attack_scores, float))
    n = len(pos)
    best = 0
    for r in range(1, n + 1):
        if beta.cdf(1 - rho, r, n - r + 1) >= 1 - delta:
            best = r
    return (-math.inf, False) if best == 0 else (float(pos[best - 1]), True)


def _self_test(trials=2000, seed=0):
    rng = np.random.default_rng(seed)
    rho, delta = 0.90, 0.10
    attack = lambda size: rng.beta(5, 2, size)           # synthetic attack score distribution F
    population = np.sort(attack(200000))
    hit = cert = 0
    for _ in range(trials):
        t, ok = guaranteed_threshold(attack(60), rho, delta)
        cert += ok
        recall = 1 - np.searchsorted(population, t, 'left') / len(population)
        hit += recall >= rho
    print(f"min labelled attacks for rho={rho}, delta={delta}: {min_attacks(rho, delta)}")
    print(f"n=60 attacks: certified {cert}/{trials}; true recall >= {rho} in {hit / trials:.3f} of draws (guarantee >= {1 - delta})")
    assert hit / trials >= 1 - delta, "guarantee violated"
    t, ok = guaranteed_threshold(attack(10), rho, delta)
    assert (t, ok) == (-math.inf, False), "should fall back when n < 22"

    # Ties: heavily discretised scores (e.g. a coarse model like a rule level). Recall at threshold t is
    # P(S >= t) >= 1 - F(t), so ties can only make the guarantee more conservative -- verify empirically.
    levels = np.arange(1, 13)
    probs = np.array([1, 1, 2, 3, 5, 8, 12, 15, 20, 18, 10, 5], float); probs /= probs.sum()
    tie_attack = lambda size: rng.choice(levels, size, p=probs).astype(float)
    pop = np.sort(tie_attack(200000)); hit = 0
    for _ in range(trials):
        t, ok = guaranteed_threshold(tie_attack(60), rho, delta)
        hit += (1 - np.searchsorted(pop, t, 'left') / len(pop)) >= rho
    print(f"ties (12 distinct score levels): true recall >= {rho} in {hit / trials:.3f} of draws (guarantee >= {1 - delta})")
    assert hit / trials >= 1 - delta, "guarantee violated with tied scores"
    print("self-test passed")


if __name__ == '__main__':
    _self_test()
