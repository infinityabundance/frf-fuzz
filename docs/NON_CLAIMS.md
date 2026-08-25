# frf-fuzz Non-Claims

This is the fixed epistemic vocabulary of the project. These statements are
permanent; if any code, report, or documentation contradicts them, that code
is wrong.

## What frf-fuzz does NOT claim

1. **No probabilistic bug prediction.** frf-fuzz never emits "87% likely to
   be a bug", "this function is probably vulnerable", "overflow predicted",
   or any probability-of-vulnerability statement. Prediction is deterministic
   recognition of a historically observed structural prefix plus a
   falsifiable proposed continuation experiment.

2. **No causal attribution.** A structural trajectory that precedes a failure
   is not thereby the cause of the failure. frf-fuzz says "the trajectory
   matches prefix SIG-…" and "these historical continuations include …"; it
   does not say "this mutation caused the bug".

3. **No guarantee of future failure.** A matching precedent prefix does not
   guarantee the continuation occurs.

4. **No proof from pattern similarity.** Precedent matching is evidence for
   choosing the next experiment, not proof that the historical failure mode
   applies.

5. **No universal residual grammar.** frf-fuzz's generic `RegimeObserver`
   semantics are documented independently from SQL and make no universal
   claim; the real `dsfb-database` grammar remains SQL-specific and is never
   applied to generic fuzz residuals.

6. **No reimplementation of FRF semantics.** frf-fuzz findings are
   hypotheses. Receipts, claims, residual dispositions, and trajectory
   semantics are FRF's; frf-fuzz retains FRF IDs verbatim and never
   reinterprets them.

7. **No claim that Gemel writes happen per execution.** Gemel receives
   durable boundaries only.

8. **No soundness claim for the InfluenceSketch.** It is an empirical
   input-region -> observation-feature relationship with false positives and
   false negatives; it is not sound dynamic taint analysis.

9. **No GPU authority.** GPU results are proposal/ranking evidence only;
   CPU semantics are the oracle.

10. **No claim that live observation is deterministic.** The deterministic
    contract is `same valid tape -> same frf-fuzz structural interpretation`;
    arbitrary OS scheduling is not made deterministic.

11. **No nearest-label classification.** `Structured + Unknown` is a valid
    terminal result; unknown structure is never renamed to the closest motif.

12. **No silent masking of failures.** Contradicted precedents, falsified
    hypotheses, refused FRF claims, replay/live disagreements, and negative
    controls that fail to reproduce are all preserved and reported.

13. **No statistics from one run.** Performance and effectiveness claims
    require the repeated-trials protocol in `EXPERIMENT_PROTOCOL.md`.

14. **No shell string construction.** Subprocesses are spawned with
    `Command` + argv only.

## What frf-fuzz DOES claim

* "current structural trajectory matches prefix SIG-…"
* "historical continuations include …"
* "required witness X has not yet appeared"
* "probe P distinguishes precedent A from confuser B"
* "status: candidate precursor"
* "FRF verification: absent / failed / admitted"
* "this input crashes / times out / diverges" (with replay evidence)
* "coverage feature F is new / state feature S is new / morphology M is new"
* "regime episode E opened at t0, peaked at t1, closed at t2"
* "the discriminating probe supported / contradicted / left ambiguous the
  precedent"

These are falsifiable statements about observations and experiments, not
judgments about the software's future behavior.
