# Build contract

- Do not proceed past a failing or unknown required gate.
- Do not weaken tests or gates to make a run pass.
- Do not carry stubs or knowingly broken paths across a completed phase unless the specification permits them.
- Builders do not attest their own changes.
- Parallel writers use isolated worktrees and non-overlapping path ownership.
- Findings are hypotheses until mechanically reproduced.
- Bind every evidence claim to the exact repository state.
- Separate local, CI, development, production, provider-acceptance, and downstream-delivery evidence.
- Preserve the host environment's approval and safety requirements.
