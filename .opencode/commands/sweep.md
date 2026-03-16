---
description: Run a hardening sweep
agent: build
---

Run a focused hardening sweep for $ARGUMENTS.

Workflow:

1. Start with verification, not assumptions.
   - Inspect current code first.
   - Verify each suspected issue against the live implementation.
   - Only fix issues that are real in the current code.
   - If something is already fixed or not reproducible, do not change code; explain why.

2. Treat this as a boundary-hardening pass.
   - Look for malformed public input, caller-supplied parsed objects, duplicate/conflicting encoded data, signed-bytes vs parsed-field divergence, malformed counters/flags, and throw-on-input paths.
   - Prioritize practical bug yield: fail-open behavior, unexpected throws, state mutation from invalid input, unstable diagnostics, or places where pre-parsed objects can lie.

3. Make minimal, surgical fixes.
   - Preserve existing conventions and type safety.
   - No `any`, no non-null assertions, no unsafe type assertions.
   - Prefer fail-closed typed errors or safe ignore behavior, whichever matches local semantics.
   - Re-derive signed fields from signed bytes where needed.
   - Reject duplicates instead of silently letting later values overwrite earlier ones.
   - Ignore malformed numeric controls instead of applying them when that matches verifier semantics.

4. Add regression tests for every real issue fixed.
   - Reproduce the exact malformed or tampered input shape.
   - Assert the dangerous behavior is gone.
   - Prefer semantic assertions on typed result codes over brittle string matching.
   - Keep tests targeted and narrow.

5. Verify each patch immediately.
   - Run the smallest relevant targeted test file(s) first.
   - Run `bun typecheck` after code changes.
   - If useful, run additional focused tests for the touched area only.

6. Run a review pass before moving on.
   - Use the `code-reviewer` subagent on the exact changed files.
   - If review finds a real hole, fix it, re-run tests/typecheck, then re-review.

7. Continue iteratively.
   - After each confirmed fix, identify the next highest-value sweep target nearby.
   - Prefer adjacent trust boundaries before broad unrelated exploration.
   - Keep sweeping until diminishing returns, then summarize the next best targets.

Output format:

- Say whether each confirmed issue was real.
- List what changed and why.
- List tests/checks run.
- Call out any remaining risk or the next best sweep targets.

Default priority order for findings:

1. fail-open behavior
2. throw-on-input public APIs
3. pre-parsed signed object trust gaps
4. malformed numeric/state mutation bugs
5. duplicate/conflicting encoded input handling
6. diagnostics stability and consistency

If `$ARGUMENTS` is empty, choose the highest-value remaining trust boundary in the repo and start there.
