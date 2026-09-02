//! Non-parametric statistics for experiment series (master prompt §31).
//!
//! These are the export-level tools used to compare ablation arms: medians
//! and quartiles, the Vargha–Delaney A12 stochastic-dominance estimator, and
//! the Mann–Whitney U two-sided test via the normal approximation with
//! continuity and tie correction. They deliberately do NOT bake conclusions
//! into the CLI: the CLI prints the numbers plus the protocol's power
//! caveat, and publication-grade comparisons require the repeated-trials
//! minimums in `docs/EXPERIMENT_PROTOCOL.md`.
//!
//! The normal approximation is exact only for larger samples; at demo-scale
//! trial counts the p-values are directional hints, not evidence. The
//! protocol document says so; this module says so; the CLI says so.

/// Median of a sample (f64). `None` for an empty sample.
pub fn median(v: &[f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    let mut s: Vec<f64> = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    Some(if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    })
}

/// Quartiles (q1, median, q3) via linear interpolation on the sorted sample.
/// `None` for fewer than 2 observations (q1/q3 undefined).
pub fn quartiles(v: &[f64]) -> Option<(f64, f64, f64)> {
    if v.len() < 2 {
        return None;
    }
    let mut s: Vec<f64> = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let q = |p: f64| -> f64 {
        let pos = p * (s.len() as f64 - 1.0);
        let lo = pos.floor() as usize;
        let hi = pos.ceil() as usize;
        if lo == hi {
            s[lo]
        } else {
            let frac = pos - lo as f64;
            s[lo] * (1.0 - frac) + s[hi] * frac
        }
    };
    Some((q(0.25), q(0.5), q(0.75)))
}

/// Vargha–Delaney A12: the probability that an observation from `x` is
/// greater than one from `y`, ties counting half. 0.5 = stochastic equality;
/// > 0.5 favors `x`. `None` if either sample is empty.
pub fn a12(x: &[f64], y: &[f64]) -> Option<f64> {
    if x.is_empty() || y.is_empty() {
        return None;
    }
    let n = x.len() as f64;
    let m = y.len() as f64;
    let mut gt = 0f64;
    for xi in x {
        for yi in y {
            gt += if xi > yi {
                1.0
            } else if xi == yi {
                0.5
            } else {
                0.0
            };
        }
    }
    Some(gt / (n * m))
}

/// Result of the Mann–Whitney U test (normal approximation).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Mwu {
    /// U for the first sample (rank-derived count of x-beats-y pairs).
    pub u: f64,
    /// Standard normal deviate (sign: negative favors the second sample).
    pub z: f64,
    /// Two-sided p-value (normal approximation, continuity + tie corrected).
    pub p_two_sided: f64,
}

/// `erfc` via Abramowitz & Stegun 7.1.26 (max |error| ~ 1.5e-7) — more than
/// enough for a two-sided normal tail at demo scale, dependency-free and
/// deterministic.
fn erfc_approx(x: f64) -> f64 {
    if x < 0.0 {
        return 2.0 - erfc_approx(-x);
    }
    let t = 1.0 / (1.0 + 0.3275911 * x);
    let p =
        ((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592;
    p * t * (-x * x).exp()
}

fn normal_two_tail(z: f64) -> f64 {
    let z = z.abs();
    let tail = 0.5 * erfc_approx(z / std::f64::consts::SQRT_2);
    (2.0 * tail).clamp(0.0, 1.0)
}

/// Mann–Whitney U on two samples (rank-based, average ranks for ties),
/// two-sided p via the normal approximation with continuity correction and
/// the tie correction. `None` if either sample is empty.
pub fn mann_whitney_u(x: &[f64], y: &[f64]) -> Option<Mwu> {
    let n = x.len();
    let m = y.len();
    if n == 0 || m == 0 {
        return None;
    }
    let total = n + m;
    // Pool with group tags; sort ascending (deterministic tie order: group,
    // then original index).
    let mut pooled: Vec<(f64, u8, usize)> = Vec::with_capacity(total);
    for (i, v) in x.iter().enumerate() {
        pooled.push((*v, 0, i));
    }
    for (i, v) in y.iter().enumerate() {
        pooled.push((*v, 1, i));
    }
    pooled.sort_by(|a, b| {
        a.0.partial_cmp(&b.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.cmp(&b.1))
            .then(a.2.cmp(&b.2))
    });
    // Average ranks within ties.
    let mut ranks_x = vec![0f64; n];
    let mut ranks_y = vec![0f64; m];
    let mut tie_sum = 0f64; // sum over ties of (t^3 - t) / 12
    let mut i = 0usize;
    while i < total {
        let mut j = i;
        while j + 1 < total && pooled[j + 1].0 == pooled[i].0 {
            j += 1;
        }
        let avg = (i as f64 + 1.0 + j as f64 + 1.0) / 2.0;
        for (_, g, idx) in &pooled[i..=j] {
            if *g == 0 {
                ranks_x[*idx] = avg;
            } else {
                ranks_y[*idx] = avg;
            }
        }
        let t = (j - i + 1) as f64;
        if t > 1.0 {
            tie_sum += (t * t * t - t) / 12.0;
        }
        i = j + 1;
    }
    let rx: f64 = ranks_x.iter().sum();
    let ry: f64 = ranks_y.iter().sum();
    let nf = n as f64;
    let mf = m as f64;
    let ux = rx - nf * (nf + 1.0) / 2.0;
    let uy = ry - mf * (mf + 1.0) / 2.0;
    let u = ux.min(uy);
    let mu = nf * mf / 2.0;
    let ntotal = total as f64;
    // Tie-corrected variance: sigma^2 = nm/12 * (N+1 - 12*tie_sum/(N(N-1))).
    let var = (nf * mf / 12.0) * (ntotal + 1.0 - 12.0 * tie_sum / (ntotal * (ntotal - 1.0)));
    let sigma = var.max(1e-12).sqrt();
    // Continuity correction: shrink |U - mu| by 0.5 (floor at 0).
    let diff = (u - mu).abs();
    let z = if u < mu {
        -((diff - 0.5).max(0.0)) / sigma
    } else {
        (diff - 0.5).max(0.0) / sigma
    };
    Some(Mwu {
        u,
        z,
        p_two_sided: normal_two_tail(z),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn medians_and_quartiles() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[3.0]), Some(3.0));
        assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]), Some(2.5));
        assert_eq!(median(&[1.0, 2.0, 3.0]), Some(2.0));
        let (q1, m, q3) = quartiles(&[1.0, 2.0, 3.0, 4.0]).unwrap();
        assert!((q1 - 1.75).abs() < 1e-9);
        assert!((m - 2.5).abs() < 1e-9);
        assert!((q3 - 3.25).abs() < 1e-9);
        assert!(quartiles(&[1.0]).is_none());
    }

    #[test]
    fn a12_known_values() {
        // Identical distributions -> 0.5.
        assert!((a12(&[1., 2., 3., 4., 5.], &[1., 2., 3., 4., 5.]).unwrap() - 0.5).abs() < 1e-12);
        // Strictly separated -> 0.0 / 1.0.
        assert_eq!(a12(&[1., 2., 3.], &[4., 5., 6.]), Some(0.0));
        assert_eq!(a12(&[4., 5., 6.], &[1., 2., 3.]), Some(1.0));
        // Hand-computed: x = 1..5 vs y = 3..7 -> 0.18.
        let x = [1., 2., 3., 4., 5.];
        let y = [3., 4., 5., 6., 7.];
        assert!((a12(&x, &y).unwrap() - 0.18).abs() < 1e-12);
        assert_eq!(a12(&[], &[1.0]), None);
    }

    #[test]
    fn mann_whitney_identical_and_separated() {
        // Identical samples: U = nm/2, z = 0, p = 1.
        let a = [1., 2., 3., 4., 5., 6.];
        let r = mann_whitney_u(&a, &a).unwrap();
        assert!((r.u - 18.0).abs() < 1e-9, "U must equal nm/2 = 18");
        assert!(r.z.abs() < 1e-9);
        assert!((r.p_two_sided - 1.0).abs() < 1e-9);
        // Fully separated: x all below y -> U = 0, p small. The normal
        // approximation with continuity correction is conservative at tiny
        // sample sizes (n = m = 5 gives p ~ 0.012), so the separation
        // assertion uses n = m = 10 where the approximation is sound
        // (z ~ 3.74, p ~ 2e-4).
        let low = [1., 2., 3., 4., 5., 6., 7., 8., 9., 10.];
        let high = [100., 200., 300., 400., 500., 600., 700., 800., 900., 1000.];
        let r2 = mann_whitney_u(&low, &high).unwrap();
        assert!(r2.u.abs() < 1e-9);
        assert!(r2.p_two_sided < 0.01);
        // Direction reversal reports the same p.
        let r3 = mann_whitney_u(&high, &low).unwrap();
        assert!((r3.p_two_sided - r2.p_two_sided).abs() < 1e-9);
        assert_eq!(mann_whitney_u(&[], &[1.0]), None);
    }

    #[test]
    fn mann_whitney_with_ties_is_stable() {
        let x = [1., 1., 1., 2.];
        let y = [1., 1., 1., 1.];
        let r = mann_whitney_u(&x, &y).unwrap();
        assert!(r.p_two_sided.is_finite());
        assert!(r.p_two_sided > 0.0 && r.p_two_sided <= 1.0);
        let r2 = mann_whitney_u(&x, &x).unwrap();
        assert!((r2.p_two_sided - 1.0).abs() < 1e-6);
    }

    #[test]
    fn erfc_sanity() {
        assert!((erfc_approx(0.0) - 1.0).abs() < 1e-9);
        assert!(erfc_approx(3.0) < 1e-4 && erfc_approx(3.0) > 0.0);
        assert!((erfc_approx(-1.0) - (2.0 - erfc_approx(1.0))).abs() < 1e-9);
    }
}
