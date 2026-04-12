---
description: Rank next hardening sweep targets
agent: plan
---

Do not edit code.

Identify the highest-value next hardening sweeps for this repo.

Workflow:

1. Inspect the current codebase state first.
   - Look for malformed public input boundaries.
   - Look for caller-supplied parsed object trust gaps.
   - Look for signed-bytes vs parsed-field divergence.
   - Look for duplicate/conflicting encoded input handling.
   - Look for malformed numeric/state mutation behavior.
   - Look for public APIs that still throw on malformed input.

2. Prioritize by practical bug-finding yield.
   - Highest priority: fail-open behavior.
   - Then: throw-on-input public APIs.
   - Then: pre-parsed signed object trust gaps.
   - Then: malformed counters/flags mutating semantics.
   - Then: duplicate/conflicting encoded inputs.
   - Then: diagnostics stability.

3. Return a concise ranked plan.

Output format:

- Top 5 next sweep targets.
- For each target include:
  - why it is high value
  - likely failure mode (`throw`, `fail-open`, `state mutation`, `bad diagnostics`, or `signed-field trust gap`)
  - 1-3 concrete files/functions to inspect first
- End with a recommended next target to actually sweep first.

If `$ARGUMENTS` is provided, bias the ranking toward that area but still mention the best global option if different.
