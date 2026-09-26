# Multi-version release architecture

## Trust zones

1. Branch-local matrices and protected controller code define expected work.
2. Untrusted candidate code, Python tests, Gradle and Minecraft run from a
   copied tree owned by a disposable Unix account with no sudo membership and
   an explicit empty environment. It cannot see Actions command files, runtime
   artifact/cache credentials, the runner action tree, model credentials,
   environments, or deployment credentials. The runner kills and locks that
   account, rejects special/symlink/hard-linked or oversized exports, and uses
   a second disposable account for protected revalidation before any upload
   action receives its runtime credential.
3. Protected secretless controllers authenticate exact run, attempt, job graph,
   commit, tree, matrix, artifact, report, screenshot, and capture identities.
4. Secretless protected code writes a data-only durable queue. After environment
   admission, a no-OIDC runner fully reauthenticates/decodes the queue and
   re-emits a handoff containing only that data plus exact protected
   client/preflight/prompts.
5. A separate fresh runner with no checkout, package manager, or image decoder
   gets a read token only for a final stdlib identity check, a hash-pinned
   Claude Code binary, and the owner's Claude Code token from the
   `visual-review` environment. Only normalized advisory JSON or a sanitized
   failure marker leaves it; CLI output and the token do not.
6. Dedicated writer jobs publish statuses, merge an exact head, delete an exact
   single-use artifact ID, or deploy an already-built Pages artifact. They do
   not execute candidate code.

## Branch lifecycle

The canonical matrix has `branch.role=integration` and synchronization disabled.
An enrolled release matrix has `branch.role=release`, its exact API branch name,
the canonical source, and synchronization enabled. Missing matrices are not
release claims. A valid JSON matrix that self-identifies as an enrolled release
but fails the complete schema aborts discovery.

Ordinary feature PRs and controller upgrades target only the canonical default
branch. Enrolled releases accept only the separately authenticated generated
release-sync bridge contexts; they do not consume an ordinary release-base
`pull_request_target` run.

The synchronizer binds each plan to the exact source commit/tree and target
commit/tree/matrix blob. Its merge candidate has exactly those two ordered
parents: target first and canonical source second. The target matrix remains
byte-identical. A protected controller-path inventory must match the canonical
source. Unknown conflicts stop publication. A reviewed conflict resolution may
be constructed manually only with those same exact parents and invariants, then
pushed to the one deterministic `automation/release-sync/<branch-token>` ref.
The protected synchronizer must reauthenticate and reuse it, open the generated
PR, dispatch both exact-head gates, and hand it to the protected merge/attestation
controller; the candidate is never an ordinary release PR or a direct-merge
exception.

Because a pull request created with `GITHUB_TOKEN` is not a dependable trigger
for every downstream workflow configuration, the publisher explicitly
dispatches Build and Packaged E2E from the protected default branch. Exact
candidate branch/commit/tree and target/source parents travel as inputs; the
protected controller authenticates them before checking out the candidate as
inert data. Run titles and immutable artifact names bind the tested candidate
SHA and run attempt even though the Actions run head remains the default
controller. The trusted result handler ignores its wake-up payload beyond using
it as a locator and re-queries GitHub for the newest exact runs and attempts.
One global non-cancelling handler lock serializes every merge-sensitive release
operation even when different authenticated candidate SHAs target the same
mutable release ref; the periodic reconciler recovers any missed wake-up.

## Artifact chain

Gradle builds reproducible remapped production and physically separate remapped
harness JARs. `scripts/release/verify_release.py` stages immutable copies and an
exact manifest. Each packaged lane revalidates that manifest, installs genuine
loader clients and a dedicated server, installs only hash-verified matrix
dependencies, and places the harness on clients only.

Schema-2 matrices use schema-3 manifests with an explicit caller scope:
`verify_release.py --artifact-node fabric-1.20.1`, `--scope legacy` while preparing,
or `--scope full` for all twelve configured lanes. Reverification adds
`--verify-staged` with the same selection. Both archives must already embed the
matching lane/build identity; these commands do not build, qualify or publish a
lane. Schema-1 historical staging keeps its existing unscoped interface.
Scoped staging currently requires POSIX no-follow directory descriptors;
unsupported platforms fail before modifying staged outputs.

The branch matrix owns the Gradle JVM independently from each artifact/runtime
Java toolchain, plus the mod version and all full runtime dependency
coordinates. This lets modern Loom run on Java 21 while Minecraft 1.20.1 output
remains compiled for Java 17. `e2e/loader-bootstrap-contract.json` is a protected security
allowlist, not a second release matrix: it contains one reviewed build-script
digest and exact E2E entrypoint/resource inventory per supported loader.
`scripts/ci/loader_bootstrap.py` derives the active loaders from the matrix,
reads the exact tested Git commit, rejects extra/missing/executable files, and
requires one final binding to the physically separate harness convention. The
trusted release handler validates a candidate against the contract from the
canonical protected commit.

Gradle dependency verification checksum-locks every artifact that can arrive
over the network. Loom-generated layered mappings, merged Minecraft modules,
transformed Forge and NeoForge loaders, and remapped modules are the only exact
trust exceptions because their archive bytes vary across hosts. The protected
`gradle/repository-policy.gradle` allows only reviewed HTTPS hosts with narrow
content filters and rejects those generated namespaces from every remote
repository; `scripts/ci/dependency_policy.py` rejects any broader exception
before Gradle starts. Each permitted local repository name is also bound to the
exact Loom cache path, while tracked `.gradle` content and implicit `buildSrc`
builds are rejected by both the candidate gate and protected controller
parity. Local generation inputs remain checksum-locked.

Reports and screenshots are accepted only after exact scenario, role, ordered
step, assertion, capture basename, digest, size, image decode, dimensions, pixel
probe, and full inventory validation. An extra file is evidence corruption, not
harmless diagnostics.

The canonical `master` / `fabric-1.20.1` baseline is a separate 90-day
lossless anchor, not the lossy public gallery cache. Its original PNG bytes are
content-addressed and bound to the exact current branch head/tree, with the
packaged producer run/attempt in both its artifact name and manifest, plus the
matrix and contract. Candidate evidence is paired 1:1 by semantic
capture identity. The ordinary aggregate/raw handoff remains short lived.

## Local lane release plan

The canonical-only planner requires its own implementation to be the exact clean
GitHub default-branch commit, a schema-2 integration matrix, no inherited `GIT_*`
variables, and `GH_TOKEN` with read access to the repository and Actions evidence.
It refuses an undeployed foundation candidate. After those prerequisites hold:

```sh
python3 scripts/release/plan_release.py --repository The-Plum-Team/Block-Pops-Minecraft-Mod \
  --artifact-node fabric-1.20.1 --build-scope legacy --e2e-scope lane
```

Both producer scopes are explicit and may differ. The command authenticates the
newest exact-head Build and Packaged E2E runs, complete job graphs, ZIP digests,
scoped bundles, Build report, and E2E aggregate. It chooses the E2E-tested
production JAR with that lane's own mod version, loader, Minecraft and Java.
Only after final API/source and byte checks does it print a new
`build/release-plan-<uuid>/plan.json` path. `--output` may name a new direct child
of `build`; existing outputs and earlier acquired evidence are preserved on failure.
The plan records all matrix targets and the remaining unselected lanes. It does
not establish AUTH-1 admission, complete the migration, or authorize publication.

## Gate and advisory policy

Build and Packaged E2E are deterministic required gates. The visual model is
asked about semantic UI defects—missing widgets, blur, clipping, transparency,
text/state/layout errors, or material render differences. Whole-frame pixel
inequality alone is not a defect and never makes the model authoritative.

Visual review uses a globally serialized artifact queue. Every input name and
manifest bind the queue producer's exact run attempt, making re-runs distinct
and allowing only attempts from one authenticated producer to coalesce.
Exact-identical pairs
consume no model calls; bounded changed chunks go to Claude Opus 5.5 for triage, and only
anomalous/uncertain pairs escalate to an independent Opus 5.5 verification. Protected code verifies
structured output, usage/cost telemetry and the exact client/prompt digests.
Like Quick Skin, the review runs on the owner's Claude subscription through a
hash-pinned Claude Code CLI; its token is a secret of the `visual-review`
environment, never a repository secret, and no API key is accepted. Retryable failures retain the queue behind authenticated
cooldown state, while ambiguous nonretryable failures require owner action.
See [Advisory visual review](visual-review.md).

Release-sync PRs use bridge contexts `Release sync / Build and verify` and
`Release sync / Packaged E2E gate`. This prevents an incidental approval-held
PR run with the same check name from colliding with authenticated dispatched
runs. The handler posts a bridge status only for the exact tested head.

Ordinary PR workflow YAML cannot authenticate itself. Ordinary same-repository
PRs into `master` therefore enter through protected-default
`pull_request_target` controllers: they re-read the PR, authenticate the current
synthetic merge parents/tree, and execute candidate bytes only inside the
disposable account.
A protected default-branch `workflow_run` evaluator then treats completion
events only as locators, repeats that identity check, requires the matrix and
dependency-verification metadata to match the current base, verifies protected
controller/bootstrap parity, selects the newest exact Build and Packaged E2E
attempts, and authenticates their complete job graphs and artifacts. GitHub
records a `pull_request_target` run under the PR's head branch and commit, never
the controller that ran it. A gate run is evidence only when it names the PR's
current head and its `referenced_workflows` entry for the gates'
repository-local `verify-gate-attestation.yml` call is the exact current default
commit: GitHub runs `pull_request_target` from the default branch at event time,
whatever the PR's base, and resolves that call there. A cancelled run never
shadows a run of the same head that ran. A separate
status-only GitHub App emits `Trusted PR / Build and verify` and
`Trusted PR / Packaged E2E gate` on the current source head. The App writer has
only an exact protected-default checkout for final reauthentication and has no
candidate checkout or execution surface. Missing App credentials produce no
trusted context and fail closed.

A narrowly separate controller-upgrade mode prevents that parity rule from
making the control plane permanently immutable. It exists only for an open
same-repository PR into the exact current default head with the exact
`controller-upgrade/` branch prefix, exact `controller-upgrade` label, and the
latest exact-head command from the sole repository owner. The protected old
evaluator—not candidate code—bounds the diff to controller/docs/test and active
loader bootstrap roots, keeps the branch matrix, dependency-verification file,
version shims, unsafe modes and forbidden trees immutable, enforces the old
loader-bootstrap contract, and authenticates the old exact Build/E2E job graphs
and artifacts. `issue_comment` create/edit/delete wakes run protected default
code and never `pull_request_target` code. Immediately before minting the
statuses-only App token, the environment writer reauthenticates the open PR,
current default/base/head, synthetic merge and SHA-bound approval digest with a
read-only token. A changed/revoked approval yields restrictive failure contexts;
a changed commit topology yields no stale status. Ordinary PR parity is
unchanged.

Loader bootstrap changes use two protected generations because the evaluator
authenticates candidate loader bytes with the base contract. The candidate
Build/E2E gates independently authenticate their own contract, so a simple
future-digest pre-pin cannot pass. A reviewed first upgrade must retain current
bytes while introducing a bounded `current`+`next` transition; the second moves
the bytes to `next` and removes the old digest. This keeps both old-policy and
candidate-policy validation meaningful throughout; details are in the
[operations runbook](operations.md#controller-upgrade-procedure).

Release synchronization has its own protected default-branch handler that
authenticates exact topology, controller parity, loader bootstrap, run attempt,
and job graph before merging only the tested automation head. It dispatches
post-merge attestations from the protected default branch and proves the final
release head has the exact tested tree; it never executes a release-sync
candidate workflow definition.
