#!/usr/bin/env bash
# PreToolUse gate, repo-scoped via this repo's .claude/settings.json:
# only the `spec-lookup` agent may read the authoritative spec corpus under
# docs/rfc, docs/itu, docs/w3c. Every other caller (the main agent or any
# other subagent) is told to delegate to the spec-lookup agent instead of
# reading the spec text directly, so spec text never pollutes a general
# agent's context and always passes through the read-it-whole, cite-verbatim
# procedure.
#
# The caller's identity is `.agent_type` in the hook payload: subagent tool
# calls carry it (verified against the gate log, where subagent type is the
# subagent_type string), and the main agent has none.

set -euo pipefail

INPUT=$(cat)
echo "${INPUT}" | jq -e . >/dev/null 2>&1 || exit 0

TOOL=$(echo "${INPUT}" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
AGENT=$(echo "${INPUT}" | jq -r '.agent_type // empty' 2>/dev/null) || exit 0

# The spec-lookup agent is the one permitted reader.
[[ "${AGENT}" == "spec-lookup" ]] && exit 0

# Authoritative source dirs. Project prose (docs/PKIX-SCOPE.md, docs/AGENTS.md,
# docs/CLAUDE.md) is deliberately not matched; anyone may read it.
SPEC_RE='docs/(rfc|itu|w3c)([/]|$|[^[:alnum:]_.-])'

MSG="STOP — the authoritative spec corpus (docs/rfc, docs/itu, docs/w3c) is read only by the spec-lookup agent.

Do not read, grep, or cat these files directly. Hand the question to the spec-lookup subagent, which censuses the whole docs/ tree, fetches missing or superseded documents, reads whole sections, and returns a cited answer:

  Agent(subagent_type: \"spec-lookup\", prompt: \"<your exact spec question>\")

That keeps the spec text out of your context and enforces the procedure in .claude/skills/spec-lookup/SKILL.md."

deny() {
	jq -cn --arg r "${MSG}" '{
	  hookSpecificOutput: {
	    hookEventName: "PreToolUse",
	    permissionDecision: "deny",
	    permissionDecisionReason: $r
	  }
	}'
	exit 0
}

if [[ "${TOOL}" == "Read" ]]; then
	FP=$(echo "${INPUT}" | jq -r '.tool_input.file_path // empty' 2>/dev/null) || exit 0
	echo "${FP}" | grep -qE "${SPEC_RE}" && deny
	exit 0
fi

if [[ "${TOOL}" == "Grep" ]]; then
	GP=$(echo "${INPUT}" | jq -r '.tool_input.path // empty' 2>/dev/null) || exit 0
	echo "${GP}" | grep -qE "${SPEC_RE}" && deny
	exit 0
fi

[[ "${TOOL}" != "Bash" ]] && exit 0

CMD=$(echo "${INPUT}" | jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[[ -z "${CMD}" ]] && exit 0

# Metadata-only commands cannot put spec text anywhere; listing the corpus is
# not reading it. Anything able to read content (a pipe, an input redirect, a
# substitution, or find's -exec / xargs) falls through to the path check.
SAFE='^[[:space:]]*(ls|find|stat|wc|file|basename|dirname|realpath|test|\[)([[:space:]]|$)'
if echo "${CMD}" | grep -qE "${SAFE}" && ! echo "${CMD}" | grep -qE '[|<]|\$\(|`|-exec|xargs'; then
	exit 0
fi

# Escape hatch: a justified inline marker with a written reason (>=10 chars).
echo "${CMD}" | grep -qE '#[[:space:]]*spec-intent:[[:space:]]*[^[:space:]].{9,}' && exit 0

# Heredoc bodies are prose (commit messages, docs), not reads; strip them
# before matching, as the redact gate does.
FILTERED=$(echo "${CMD}" | awk '
	inHd { if ($0 == hd) inHd = 0; next }
	match($0, /<<-?['"'"'"]?([A-Za-z_]+)/, m) { hd = m[1]; inHd = 1; print; next }
	{ print }
')

# The `bun spec` reader prints spec text without naming a docs/ path, so its
# content commands are gated the same way; `list` is metadata and stays open.
READER_RE='((bun|run)[[:space:]]+spec|scripts/spec/main\.ts)[[:space:]]+(read|search|headings)([[:space:]]|$)'
echo "${FILTERED}" | grep -qE "${READER_RE}" && deny

echo "${FILTERED}" | grep -qE "${SPEC_RE}" && deny
exit 0
