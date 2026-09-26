# Repository configuration and incident recovery

## Local serial build diagnostics

Inspect a selected lane with `python3 scripts/release/build_matrix.py --plan --artifact-node fabric-1.20.1`.
For execution, omit `--plan` and supply `--java-home /absolute/jdk21` plus
`--java17-home /absolute/jdk17` when the selected lane compiles/runs on Java17.
Use `--scope legacy` for preparing-mode legacy lanes or `--scope full` for a
complete configured inventory; the default full scope rejects unresolved targets.
`--clean` adds only the selected project's clean task.

Execution owns one checkout lock, serial Gradle processes and isolated per-lane
homes. Explicit JDK probes, observed compiler selections, source/output hashes
and archive boundaries feed `build/build-matrix-report.json`; per-lane logs and
receipts live under `build/observations/`. A new valid execution invalidates prior
success before probing; failures stop subsequent lanes. Cancellation reaps only
the owned process group. Windows execution remains unsupported until equivalent
process-tree ownership is implemented. Inherited JVM/Gradle option variables and
nonempty `ORG_GRADLE_PROJECT_*` variables are rejected. A successful diagnostic
report does not certify clean release provenance or packaged Minecraft scenarios.

## Owner configuration required

Build, E2E, evidence validation, and PR evaluation are secretless. Narrow
governance/publication writers still require owner configuration:

- Protect `master` with required pull requests, strict up-to-date heads, no
  force pushes/deletions, and no bypass actors. Require the App-sourced contexts
  `Trusted PR / Build and verify` and `Trusted PR / Packaged E2E gate`; do not
  use the similarly named candidate-workflow checks as the protected contexts.
- Create and install a repository-scoped **PR gate** GitHub App with only
  Metadata read and Commit statuses write. Create a protected `pr-gate`
  environment restricted to `master`, set `PR_GATE_APP_CLIENT_ID` there as a
  variable, and store `PR_GATE_APP_PRIVATE_KEY` there as its only secret. The
  protected `handle-pr-gate-result.yml` evaluator is read-only; a fresh writer
  job uses this App only after revalidating the current PR, exact synthetic
  merge parents/tree, ordinary control-plane parity or a bounded SHA-approved
  controller upgrade, newest run attempts, and exact job graphs. Configure both
  required contexts with this App as their expected
  source. Bootstrap in that order: install/configure the App and environment,
  let one current PR produce both contexts, then select those existing contexts
  and that exact App as the expected source in branch protection.
- An organization/enterprise may instead enforce Build and Packaged E2E as
  required-workflow rules from a protected repository/ref. GitHub does not
  expose that rule at the level of this user-owned repository, so it is not the
  documented bootstrap path here.
- Protect every matrix-enrolled release branch with strict bridge contexts
  `Release sync / Build and verify` and
  `Release sync / Packaged E2E gate` plus the same no-bypass rules. Release
  branches accept only generated synchronization PRs; the ordinary
  `Trusted PR / ...` controller and controller-upgrade mode target `master`
  only.
- Keep default `GITHUB_TOKEN` permissions read-only. The current implementation
  requires **Allow GitHub Actions to create and approve pull requests** for its
  narrowly permissioned synchronization jobs. Merely installing an App/token
  does not switch those workflows to that identity. An App migration must first
  wire a protected fresh writer and exact expected-source status policy; do not
  treat an App permission sketch as already implemented.
- Do not replace `scripts/ci/untrusted_runner.py` with environment-variable
  scrubbing alone. Build, tests, fan-in decoders and packaged Minecraft must
  remain under the non-sudo copied-tree boundary, and the account must be dead
  before `upload-artifact` runs. If Ubuntu runner/user-management semantics
  change, freeze the gates and repair this boundary before accepting evidence.
- Set Pages source to GitHub Actions. Create the `github-pages` environment and
  limit deployment to protected `master`.
- Create a protected `visual-review` environment if advisory AI review is
  desired and restrict it to protected `master`. Store the owner's
  `claude setup-token` token as that environment's `CLAUDE_CODE_OAUTH_TOKEN`
  secret, as listed in [the visual-review runbook](visual-review.md), never as
  a repository secret. Do not add an Anthropic API key. The model job has no
  checkout, package manager, image decoder, or GitHub write scope; the model
  gets only the Read tool for the images it reviews, and the job's read-only
  GitHub token exists only for the final stdlib identity preflight.
- Keep repository Actions artifact retention at **90 days or greater**; the
  canonical lossless anchor cannot meet its propagation window under a lower
  repository cap.

At the 2026-08-11 API snapshot the repository was private and both long-lived
matrix lines (`master` and `1.21.1-neoforge-fabric`) reported unprotected; the
feature-branch inventory is intentionally irrelevant. The ruleset/protection APIs returned
HTTP 403 with an upgrade requirement. GitHub Pro (or making the repository
public) is therefore required before deterministic checks can be institutionally
authoritative against direct pushes. Do not represent a green workflow as
branch governance until protection is visible through the API.

The PR-gate App is intentionally distinct from the synchronization identity.
Its installation token may write commit statuses only: it cannot read candidate
contents, dispatch workflows, modify branches, create PRs, comment, or merge.
`CODEOWNERS` is defense in depth and becomes enforceable only when branch
protection requires an eligible independent code-owner review; it does not
authenticate a check by itself. A sole repository owner cannot satisfy an
independent-review policy on their own PR.

Keep default Actions permissions read-only. The current repository setting also
disallows Actions-created PRs; enable **Allow GitHub Actions to create and
approve pull requests** before expecting the current automated release PR
creation path to work.

## Initial control-plane bootstrap limitation

The protected `pull_request_target` gates, `workflow_run` evaluators, and manual
`workflow_dispatch` entrypoints must already exist on GitHub's default branch
before GitHub will execute them as the trusted controller. Consequently this
implementation cannot produce protected PRT evidence for its own pre-merge head,
and the controller-upgrade procedure below cannot authorize the mechanism that
implements that procedure. A stacked branch does not change this boundary.

The first installation therefore requires the repository's current authorized
governance process to land one exact, completely reviewed commit. It is not
permission to reuse an older success, treat candidate-controlled checks as App
contexts, disable a gate, or add a temporary `pull_request` control path. If that
existing authority is unavailable, initial installation remains a blocker.
Immediately after installation, dispatch Build and Packaged E2E against the exact
current default-branch HEAD, then exercise both protected PRT gates and the App
bridge on a fresh same-repository PR before selecting the stable contexts in
branch protection. Any repair uses the now-installed controller-upgrade process.
The one exception is repairing the evaluator while it refuses every PR, as it
did from the schema-2 `preparing` enrollment (`466426b`) until its trusted-gate
projection landed, and, because it never matched a real gate run, until gate
runs were matched by their PR head and controller reference. No controller
upgrade can be admitted then, so that repair
lands as one exact, completely reviewed commit through the same governance
process and limits as the first installation, followed by the same fresh-PR
exercise of both protected gates before any stable context is relied on.

PR #7 owns the canonical foundation on which this implementation was prepared;
PR #8 is an independent release-line port. Its existing release-base PR shape is
a one-time foundation under bootstrap authority, not precedent for steady-state
release contributions. Resolve artifact storage and obtain newest exact-head
Build and Packaged E2E success for every head before the current authorized
bootstrap process lands either foundation. Land or incorporate the reviewed
control plane only on top of the exact PR #7 state, while PR #8 may land
independently. After both lines and the controller are present, perform the
deliberate 1.21.1 exact-candidate reconciliation below and then resume normal
two-parent synchronization. That reconciliation is not an ordinary release PR.
A changed head invalidates the preceding evidence and must be rerun.

## Controller-upgrade procedure

Ordinary PRs cannot change their own protected evaluator. After this mechanism
already exists on the protected default branch, use this exact procedure for a
deliberate controller, workflow, E2E-oracle, visual-review, or shared security-test
upgrade:

1. Start from the exact current `master` and push a same-repository branch named
   `controller-upgrade/<purpose>`. Target only `master` and add the exact
   `controller-upgrade` label.
2. Keep the diff inside the controller roots enforced by
   `scripts/ci/pr_gate.py`: protected workflows/actions and CODEOWNERS, shared
   build/controller/E2E/evidence/visual/site/test code, Markdown documentation,
   and only the matrix-selected loaders' `build.gradle` or `src/e2e` trees.
   While the `master` matrix is schema 2 in `preparing` mode, ordinary and
   controller-upgrade evaluation take the PR's branch identity, the selected
   loaders and the parity-protected loader paths from its trusted-gate
   projection: the branch policy plus the two legacy lanes `fabric-1.20.1` and
   `forge-1.20.1`. The expected job graphs come from the full document's
   default `legacy` scope, the same two lanes. Both therefore equal the
   schema-1 gate's; `shared` mode (until its activation task), any other mode
   and a malformed matrix fail closed. The loader-bootstrap contract still
   binds every configured loader, NeoForge included, so an ordinary change to
   NeoForge's `build.gradle` or `src/e2e` must match that contract, which the
   schema-1 gate did not require.
   Product `src/main` code, unknown paths, submodules, symlinks,
   executable-mode additions, forbidden `.gradle`/`buildSrc` trees, the release
   matrix, dependency-verification metadata, and version shims are rejected.
3. Let the exact synthetic merge run Build and Packaged E2E. The protected old
   evaluator still requires its own exact job graphs and one immutable exact-run
   artifact from each successful newest attempt; candidate YAML cannot redefine
   that expected graph.
4. After reviewing the complete current-head diff, the repository owner
   `AkaNebur` posts one plain, single-line issue comment (no Markdown fence):
   `/controller-upgrade approve <40-character-lowercase-head-sha>`. A new commit
   always needs a new SHA-bound approval. The latest owner command for that exact
   head wins; `/controller-upgrade revoke <sha>`, editing the approval, or
   deleting it invalidates publication and wakes the protected handler.
5. Merge only while both ordinary stable contexts are current successes on that
   exact source head. The `pr-gate` environment writer first re-reads the open PR,
   current default/base/head, exact synthetic merge parents/tree, and approval
   digest with its read-only `GITHUB_TOKEN`. Only then does it mint the separate
   statuses-only App token. It checks out protected `master` code only and never
   candidate code; an authorization change is published as failure on the same
   immutable head.

`issue_comment` events are locators, not authority: the protected default-branch
handler ignores payload claims and re-queries GitHub. It never executes
candidate code; the underlying Build/E2E runs use their separately protected
`pull_request_target` controllers and disposable account. Repeated
create/edit/delete deliveries and Build/E2E wakes are serialized by PR and are
harmless. This procedure cannot bootstrap
itself after required contexts are enforced: install it before selecting those
contexts during the initial repository bootstrap, or use the repository's
existing authorized governance process without weakening an established gate.

Loader-bootstrap bytes have an additional two-generation constraint. The old
protected evaluator always checks a controller candidate's loader files against
the contract in its base commit. Therefore loader bytes and the contract that
first authorizes them must not change in the same PR. At that protected boundary
the order is contract policy first, loader bytes second. However, Build and
Packaged E2E also self-validate the candidate's own contract, so a naive PR that
simply replaces today's digest with a future digest will correctly fail. A real
content transition must use two controller upgrades:

1. PR A upgrades the contract schema/validator to a bounded reviewed
   `current`+`next` form, retains the exact current loader digest, and adds the
   one reviewed future digest. Loader files remain byte-identical. The old
   evaluator accepts the unchanged files under its base contract; candidate
   Build/E2E accept the same files through `current`.
2. After PR A merges, PR B changes only the applicable loader bootstrap bytes to
   exact `next` and collapses the contract back to the one new current digest.
   The now-protected transitional validator accepts `next`, while candidate
   Build/E2E accept the collapsed new contract. Both PRs need independent
   exact-head owner approval and both deterministic gates. Let each final shared
   state synchronize and attest on every enrolled release branch; never bypass
   the candidate bootstrap probe or leave a permanent dual-digest window.

The current schema is single-digest, so such a future migration must implement
and test the bounded transitional schema in PR A; the runbook is not permission
to pre-authorize unmatched bytes with the current parser.

## Bootstrap a release branch

Matrix discovery cannot safely infer a legacy release from its name. Bootstrap
`1.21.1-neoforge-fabric` once with a deliberate branch-specific matrix and the
shared controller/runtime implementation. Its matrix must identify that exact
branch, Fabric+NeoForge 1.21.1, and Java 21. Only then enable synchronization and
governance for it. PRs #7 and #8 are independent ports rather than an ancestry
chain. After both exact-head gates pass and both foundations land through the
current authorized bootstrap process, the first canonical-to-release
synchronization is expected to stop on real product-code conflicts.

For that one conflict reconciliation, do not open an ordinary PR into the
release branch. Under review, construct one exact merge commit with the exact
current release HEAD as first parent and exact current `master` HEAD as second
parent. Resolve only the intended product conflicts, preserve the target matrix
byte-for-byte and the 1.21.1 NeoForge/version-specific implementation, and keep
all protected controller paths in canonical parity. Derive the canonical
24-lowercase-hex branch token with the protected
`scripts/ci/gate_controller.py branch-token` policy for the exact release branch,
then push the candidate to `automation/release-sync/<token>`; if that rolling ref
already exists, replace only its expected exact value with force-with-lease.

Wake the protected synchronizer after the push. It re-reads current source and
target heads, accepts the candidate only if its ordered parents, tree, retained
matrix, loader-bootstrap policy, and controller parity are still exact, then
reuses the head, opens or updates the generated release-sync PR, dispatches Build
and Packaged E2E, and lets the protected handler merge and attest only the tested
head. If either long-lived head moved, discard and reconstruct the candidate.
Never merge it directly, invent ordinary-release PRT contexts, or broaden the
conflict allowlist to force this bootstrap.

## Recovery runbook

- **A gate failed:** inspect the newest exact-head run. Fix the root cause and
  dispatch a newer run. Never bless an older success or post a manual success
  context.
- **A gate is stale/pending:** reconcile the PR. The controller must keep it
  unmerged until the newest run attempt settles; a canceled notification can be
  recovered by the scheduled/manual reconciler.
- **The target head moved:** discard/update the automation candidate from the
  new exact base. Do not force the old tree through.
- **A protected conflict appeared:** leave synchronization blocked and use the
  exact two-parent candidate procedure above. The protected synchronizer, not an
  ordinary release PR or a direct push, must open, gate, merge, and attest the
  resulting release-sync PR. Do not add a broad conflict exception.
- **A protected controller/test must change:** use the separately authenticated
  controller-upgrade procedure above. Ordinary candidate workflow
  success cannot authorize changes to its own evaluator, tests, prompts, or
  policy. Never disable required contexts as an ad-hoc upgrade path.
- **A loader bootstrap changed:** update the matrix-driven build implementation
  first, then deliberately review the affected digest in
  `e2e/loader-bootstrap-contract.json`. Never snapshot or bless a digest from an
  untrusted release candidate. Missing, extra, executable, or differently
  bound harness files must remain a hard failure.
- **Dependency verification rejected a Loom-generated module:** confirm its
  coordinate matches one of the five exact generated-name exceptions and that
  every remote repository still rejects that namespace. Do not append the
  observed archive hash: Loom's locally generated ZIP is host-dependent. Any
  other coordinate remains a hard checksum failure and must be investigated.
- **Post-merge attestation failed:** freeze further synchronization, compare the
  final parent order/tree/matrix to the tested candidate, and revert or repair
  through a gated PR.
- **Visual queue stopped:** inspect the normalized 30-day owner-action report.
  Authentication, configuration, unknown provider output, and exhausted
  attempts intentionally retain the data-only queue without automatic paid
  retries. Fix the external condition, delete only the exact authenticated
  blocking report ID, and dispatch `visual-review-queue-wake`.
- **Claude returned 429/capacity/network failure:** keep the queue and its
  authenticated cooldown marker. The drain honors the greater of 30 minutes
  and bounded `Retry-After`; never delete the marker to force an early retry.
- **Visual artifact cleanup failed:** re-authenticate artifact name, owner run,
  attempt, digest, size, and exact numeric ID, then delete that ID only. A 404
  is idempotent success. Never rotate by a name wildcard. The failed run does
  not self-dispatch without a durable marker/report or successful cleanup; use
  the scheduled recovery after the underlying Actions API condition clears.
- **Pages promotion failed:** retain the prior rolling cache/site. Rotation is
  allowed only after a successful atomic deployment and cache publication for
  all current heads. The final same-run job may accept only its exact protected
  workflow run/attempt while it remains `in_progress` with no conclusion and
  every upstream job is successful; a `pages-rotate` recovery accepts only an
  exact historical owner that is already `completed/success`. Both paths keep
  the fixed lifecycle lock through exact-ID deletion.
- **Actions artifact quota is exhausted:** Build/E2E may finish compilation and
  staging but cannot cross the immutable-artifact boundary, so the gate must
  remain failed and packaged scenarios must not be represented as tested. In
  repository/account billing, remove only obsolete artifacts whose IDs and
  owners are understood or raise the Actions storage budget, then wait for
  GitHub's quota recalculation and rerun the exact failed head. Never disable
  uploads, evidence fan-in, the lossless anchor, or retention checks to get a
  green status.
- **The Claude Code token may be exposed:** delete the `CLAUDE_CODE_OAUTH_TOKEN`
  secret of the `visual-review` environment, revoke the token from the owner's
  Claude account, delete the single-use handoff by authenticated ID and audit
  the environment job, then store a fresh `claude setup-token` token before
  waking the queue. Deterministic gates remain valid because they never receive
  the token or model access.
