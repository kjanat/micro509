export const meta = {
  name: 'rfc-testing',
  description: 'Relay one agent per RFC heading: fix its coverage, then hand the baton to the next heading',
  whenToUse: 'Bringing test/rfc/rfc<n>.test.ts up to the clauses of docs/rfc/rfc<n>.txt, one heading at a time. Takes any number of RFCs, one lane each, run in parallel.',
}

/** Loop protection: no RFC in docs/rfc/ carries this many headings. */
const MAX_LEGS = 60

const REPORT = {
  type: 'object',
  additionalProperties: false,
  required: ['heading', 'status', 'findings', 'changes', 'srcChanges', 'libraryDefects', 'nextHeading'],
  properties: {
    heading: { type: 'string', description: 'The heading you actually worked, as "<number>. <title>"' },
    status: { type: 'string', enum: ['changed', 'already-complete', 'blocked'] },
    findings: { type: 'array', items: { type: 'string' }, description: 'Incompleteness or incorrectness found' },
    changes: { type: 'array', items: { type: 'string' }, description: 'Assertions added or corrected, with test names' },
    srcChanges: { type: 'array', items: { type: 'string' }, description: 'Edits under src/ that fix a real defect: file:line and what changed' },
    libraryDefects: { type: 'array', items: { type: 'string' }, description: 'Real defects found but not fixed, with the reason' },
    nextHeading: {
      type: ['string', 'null'],
      description: 'The first heading after yours in document order that no earlier leg has worked, as "<number>. <title>", or null when every heading after yours is worked or none follows. This is the baton.',
    },
  },
}

// Workflow scripts run sandboxed: no import(), no Bun, no process, and
// `import.meta` is a syntax error. Anything from the host comes in through args,
// which the harness hands over as a JSON string rather than the object passed.
const input = typeof args === 'string' && args !== '' ? JSON.parse(args) : (args ?? {})

// Agents already run in the checkout, and the sandbox exposes no cwd to name it
// with, so the prompt describes the repository rather than pointing at a path.
// An explicit repoRoot overrides that for a run driven from somewhere else.
const repoRoot = Array.isArray(input) ? undefined : input.repoRoot

// One lane per RFC: { number, testFile?, start?, done? }, where `number` is all
// that is needed and the rest resume a lane partway through. A lane may also be
// a bare number, and `args` itself may be the list.
const lanes = (Array.isArray(input) ? input : Array.isArray(input.rfcs) ? input.rfcs : [])
  .map((lane) => (typeof lane === 'object' && lane !== null ? lane : { number: String(lane) }))
  .map((lane) => ({
    number: String(lane.number),
    testFile: lane.testFile ?? `test/rfc/rfc${lane.number}.test.ts`,
    start: lane.start,
    done: lane.done ?? [],
  }))

const unusable = lanes.filter((lane) => !/^\d+$/.test(lane.number)).map((lane) => lane.number)
if (lanes.length === 0 || unusable.length > 0) {
  return {
    error: `pass args {"rfcs":[{"number":"8410"}]}${unusable.length > 0 ? `; not RFC numbers: ${unusable.join(', ')}` : ''}`,
    legsRun: 0,
  }
}

function prompt(rfcNumber, testFile, assignment, done, laneCount) {
	return `\
You are one leg of a relay over RFC ${rfcNumber}. You work ONE heading to completeness, then hand the baton on.

Repo: ${repoRoot ?? 'the checkout you are already running in'} (micro509, zero-dependency TypeScript X.509 library). Every path below is relative to its root.
Spec text: docs/rfc/rfc${rfcNumber}.txt (vendored, read-only).
Test file: ${testFile}

YOUR LEG: ${assignment}
${done.length === 0 ? 'No heading has been worked yet; yours is the first leg.' : `Already worked by earlier legs, do not redo them unless faulty or incomplete:\n${done.map((h) => `  - ${h}`).join('\n')}`}

TASK
1. Read your heading's full text in docs/rfc/rfc${rfcNumber}.txt. Read the WHOLE section, not just grep hits. If it refers to another section of this RFC, or to another RFC, read that too: docs/rfc/ holds many of them (if missing, add it using bash \`run rfc <number>\`, which invokes \`scripts/fetch-rfc.bun.ts\`), and the referenced clause is often where the real requirement is.
2. Read the matching describe(...) block in ${testFile}. Match it by its leading section number. If no describe exists for your heading, create one in correct document order.
3. Identify, concretely:
   - normative clauses (MUST / MUST NOT / SHOULD / SHOULD NOT / MAY / REQUIRED) in your section, and in what it references, that no assertion covers;
   - assertions present but WRONG: asserting something the RFC does not say, tautological assertions that test a local constant rather than the library, or a wrong expected value;
   - it.todo entries that are actually testable and should become real tests.
   - anything else this list may have left out inadvertently, strive for completeness, and accuracy.
4. IMMEDIATELY implement the fixes in test or src, as needed both.

FIX WHAT IS BROKEN
- If the RFC says the library must behave a way it does not, that is a library defect. FIX IT in src/.
- Never bend a test to make broken behaviour look correct, and never weaken an assertion to get green.
- The fix is the goal; the test is how you prove it. Also fix large or cross-cutting shit.

${
		laneCount > 1
			? `${laneCount} relays run at once, one per RFC, and every one of them may reach into src/:
- Re-read the exact region immediately before each edit; another relay may have just changed it.
- After ANY src/ change run the FULL suite: bun test. A src/ change can break suites far from yours. If you broke something, fix it. If you feel that another agent is working the same piece of code, wait a bit until you think it's finished. Evaluate if your changes are still needed, or the other agent already did the work you wanted to do, and then either do it, or continue.
- Report every src/ edit in srcChanges with file:line and what changed.`
			: `You are the only relay running:
- After ANY src/ change run the FULL suite: bun test. A src/ change can break suites far from yours. If you broke something, fix it.
- Report every src/ edit in srcChanges with file:line and what changed.`
	}

TEST FILE OWNERSHIP
In ${testFile}, you will usually edit ONLY the describe block for your own heading. The other relay legs own the others. Never touch another heading's block or another test file, unless, and this is important — your section's clause is actually violated somewhere else, in which case the fix belongs where the defect is, not where you happened to find it. A wrong assertion in a sibling block, a missing case in \`test/pem.test.ts\` or \`test/keys.test.ts\`, a helper in \`test/helpers.ts\` that encodes the wrong behaviour: fix it there and say so, rather than bolting a compensating test into your own block. Ownership is about not colliding with another leg mid-edit, not about pretending a defect stops at your section boundary. src/ is fair game.

RULES
- Verify before asserting. Run code to check an expected value rather than guessing it. A test whose expectation you guessed is worse than no test.
- Prove each new test bites: it must fail if its assertion is inverted or the behaviour regresses.
- Fixtures come from the vendored RFC text via whatever fixture helper ${testFile} already defines at its top (example(), blockAt(), lines, and the like). If the file is new and has none, write one. Do not paste base64 inline. Not very hard rule, sometimes it may be more elegant to actually inline shit. Meh...
- Invisible characters (VT, NBSP, U+3000) go in as \\u escapes, or make constants for them, and reference a char per const.
- No it.todo's. We implement shit all the way.
- Only keep/add an it.todo when the clause has no runtime claim for this library at all (bibliography, IANA registry, prose rationale). Say why in its text and in findings. Bad reasons, or incorrectness, anything that might later be adjudicated to have been lazyness, or misbehaviour will be punished to the greatest degree.
- AGENTS.md at the repo root and in test/ carries the rest of the house style. Follow it.

VERIFY BEFORE FINISHING
Run: \`bun test ${testFile}\` — must end 0 fail.
If you changed anything under src/, also run: bun test — must end 0 fail.
Delete any scratch or probe file YOU created when you are done. Do not do so for ones your colleague agents are working on, or have created.

PASS THE BATON
Open docs/rfc/rfc${rfcNumber}.txt and walk forward from your own heading in document order. Headings look like "2.  General Considerations", "5.1.  Encoding", "Appendix A.  Title". A long title wraps onto the next line; join it.
Return in nextHeading the first heading after yours that is NOT in the already-worked list above, as "<number>. <title>". Step over the worked ones.
Return nextHeading: null ONLY when you have confirmed every heading after yours is already worked, or that none follows.
Getting this wrong drops a leg of the relay, so verify it against the file rather than guessing.

Return the structured report.
`
}

// Seeding beats resumeFromRunId here. Each leg's prompt embeds the accumulated
// `done` list, so a cached replay that rebuilds that list in a different order
// changes the key and every later leg misses. Pass `start` and `alreadyDone` to
// begin at a known heading instead of re-walking the chain.
async function relay({ number: rfcNumber, testFile, start, done: alreadyDone }, laneCount) {
  const phase = `RFC ${rfcNumber}`
  const done = [...alreadyDone]
  const reports = []
  let assignment =
    start ?? `the FIRST heading in the document. Find it yourself in docs/rfc/rfc${rfcNumber}.txt.`
  // A lane ends by dropping the baton. Everything else is a stop mid-document,
  // and the caller is told which, since partial coverage otherwise reads as a
  // finished RFC.
  let unfinished = `lane never ran`

  for (let guard = 0; guard < MAX_LEGS; guard++) {
    const report = await agent(prompt(rfcNumber, testFile, assignment, done, laneCount), {
      label: `${rfcNumber}: ${String(assignment).slice(0, 40)}`,
      phase,
      schema: REPORT,
    })
    if (report === null) {
      unfinished = `leg died on "${assignment}"`
      log(`${rfcNumber}: leg died on "${assignment}", relay stops`)
      break
    }
    unfinished = `stopped after ${MAX_LEGS} legs, still holding "${report.nextHeading}"`
    reports.push(report)
    done.push(report.heading)
    log(`${rfcNumber} ${report.heading} -> ${report.status}${report.srcChanges.length > 0 ? ` (${report.srcChanges.length} src fix)` : ''}`)

    if (report.nextHeading === null) {
      unfinished = undefined
      log(`${rfcNumber}: baton dropped at the finish, ${done.length} legs run`)
      break
    }
    // The baton is meant to step over worked headings, so one that comes back
    // already worked means the leg mis-walked the document, not that the lane
    // is finished.
    if (done.includes(report.nextHeading)) {
      unfinished = `"${report.nextHeading}" came back already worked`
      log(`${rfcNumber}: "${report.nextHeading}" was already worked, relay stops rather than loop`)
      break
    }
    assignment = report.nextHeading
  }
  if (unfinished !== undefined) log(`${rfcNumber}: INCOMPLETE, ${unfinished}`)
  return { rfcNumber, reports, unfinished }
}

log(`lanes: ${lanes.map((lane) => `${lane.number}${lane.start === undefined ? '' : ` from "${lane.start}"`}`).join(', ')}`)

const perLane = (await parallel(lanes.map((lane) => () => relay(lane, lanes.length)))).filter(Boolean)

const all = perLane.flatMap((lane) => lane.reports)
return {
  incompleteLanes: perLane
    .filter((lane) => lane.unfinished !== undefined)
    .map((lane) => `rfc${lane.rfcNumber}: ${lane.unfinished}`),
  legsRun: all.length,
  changed: all.filter((r) => r.status === 'changed').length,
  alreadyComplete: all.filter((r) => r.status === 'already-complete').length,
  blocked: all.filter((r) => r.status === 'blocked').length,
  srcChanges: all.flatMap((r) => r.srcChanges.map((c) => `${r.heading}: ${c}`)),
  libraryDefects: all.flatMap((r) => r.libraryDefects.map((d) => `${r.heading}: ${d}`)),
  perHeading: all.map((r) => ({ heading: r.heading, status: r.status, findings: r.findings, changes: r.changes })),
}
