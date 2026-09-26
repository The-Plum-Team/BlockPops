from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
import urllib.request
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.ci.e2e_job_graph import expected_jobs
from scripts.ci.e2e_fanin import aggregate_artifact_name
from scripts.ci.loader_bootstrap import HARNESS_BINDING
from scripts.ci.tests.matrix_fixtures import SCHEMA1_MATRIX_PATH, schema2_configuration
from scripts.ci.pr_gate import (
    CONTROLLER_UPGRADE_REQUIRED,
    CONTEXTS,
    CONTROLLER_ANCHOR_WORKFLOW,
    EXACT_BASE_OWNED_PATHS,
    GateResult,
    GitHubApi,
    NotEligible,
    PrGateError,
    PullIdentity,
    RESTRICTED_TRANSITION_SCOPES,
    SelectedRun,
    UpgradeAuthorization,
    _source_outputs,
    _upgrade_path_allowed,
    bind_restricted_transition_decision,
    controller_upgrade_authorization,
    evaluate_restricted_transition,
    _gate_result,
    _result,
    main as pr_gate_main,
    parse_restricted_transition,
    read_restricted_transition_owner_decision,
    reauthorize,
    runs_default_controller,
    resolve_dispatch_source,
    resolve_pull_identity,
    select_newest_pull_run,
    validate_exact_artifact,
    validate_controller_upgrade_tree,
    validate_pr_tree,
    validate_restricted_loader_transition,
    validate_restricted_transition_tree,
)


REPO = Path(__file__).resolve().parents[3]
MATRIX = SCHEMA1_MATRIX_PATH
MATRIX_IDENTITY = json.loads(MATRIX.read_text(encoding="utf-8"))["branch"]
MERGE = "d" * 40
HEAD = "c" * 40
BASE = "b" * 40
DEFAULT = "a" * 40


def identity(**overrides: object) -> PullIdentity:
    values: dict[str, object] = {
        "number": 17,
        "default_branch": "master",
        "default_sha": DEFAULT,
        "base_branch": "master",
        "base_sha": BASE,
        "head_branch": "feature/ui",
        "head_sha": HEAD,
        "merge_sha": MERGE,
        "merge_tree": "e" * 40,
    }
    values.update(overrides)
    return PullIdentity(**values)  # type: ignore[arg-type]


def anchor(
    controller: str = DEFAULT, *, repository: str = "owner/repo", branch: str = "master"
) -> dict[str, str]:
    """The ``referenced_workflows`` entry GitHub records for the gates' local reusable call."""

    return {
        "path": f"{repository}/{CONTROLLER_ANCHOR_WORKFLOW}@{controller}",
        "ref": f"refs/heads/{branch}",
        "sha": controller,
    }


def run(
    run_id: int,
    *,
    workflow: str = "build-gate.yml",
    attempt: int = 1,
    status: str = "completed",
    conclusion: str | None = "success",
    created_at: str = "2026-08-10T10:00:00Z",
    pull: int = 17,
    branch: str = "feature/ui",
    head: str = HEAD,
    controller: str = DEFAULT,
    repository: str = "owner/repo",
    event: str = "pull_request_target",
) -> dict[str, object]:
    """A gate run as GitHub records it: under the PR head, naming its controller by reference."""

    return {
        "id": run_id,
        "run_attempt": attempt,
        "path": f".github/workflows/{workflow}",
        "event": event,
        "head_branch": branch,
        "head_sha": head,
        "status": status,
        "conclusion": conclusion,
        "created_at": created_at,
        "repository": {"full_name": repository},
        "head_repository": {"full_name": repository},
        "pull_requests": [{"number": pull}],
        "referenced_workflows": [anchor(controller, repository=repository)],
    }


class RestrictedTransitionDeclarationTests(unittest.TestCase):
    def declaration(self, **overrides: object) -> dict[str, object]:
        return {
            "schema_version": 1, "controller_generation": 1, "controller_sha": BASE,
            "base_sha": BASE, "head_sha": HEAD, "scope": "matrix",
            "paths": ["release/release-matrix.json"], **overrides,
        }

    def parse(self, declaration=None, **overrides):
        arguments = {
            "identity": identity(default_sha=BASE), "deployed_controller_sha": BASE,
            "deployed_generation": 1, **overrides,
        }
        raw = json.dumps(self.declaration() if declaration is None else declaration).encode()
        return parse_restricted_transition(raw, **arguments)

    def decision(self, transition, **overrides):
        return {
            "schema_version": 1, "purpose": "restricted-transition-owner-authorization",
            "repository": "The-Plum-Team/Block-Pops-Minecraft-Mod", "pull_request": 17, "owner": "AkaNebur",
            "decision": "approve", "controller_generation": 1, "controller_sha": BASE,
            "base_sha": BASE, "head_sha": HEAD, "declaration_sha256": transition.digest,
            "comment_id": 91, "comment_updated_at": "2026-09-19T10:00:00Z",
            "comment_created_at": "2026-09-19T10:00:00Z",
            "comment_body": f"/restricted-transition approve 1 {HEAD} {transition.digest}", **overrides,
        }

    def bind(self, transition, decision):
        return bind_restricted_transition_decision(
            transition, repository="The-Plum-Team/Block-Pops-Minecraft-Mod", pull_number=17,
            authenticated_owner_decision=decision)

    def test_exact_static_scopes_and_external_deployment_bind_inert_proposals(self):
        self.assertEqual(
            {"matrix", "verification", "vanilla-shim", "datapack-metadata", "stonecutter-bootstrap",
             "fabric-contract", "forge-contract", "neoforge-contract", "fabric-next", "forge-next", "neoforge-next"},
            set(RESTRICTED_TRANSITION_SCOPES))
        self.assertTrue(set(EXACT_BASE_OWNED_PATHS).issubset(
            {path for paths in RESTRICTED_TRANSITION_SCOPES.values() for path in paths}))
        for scope, paths in RESTRICTED_TRANSITION_SCOPES.items():
            with self.subTest(scope=scope):
                result = self.parse(self.declaration(scope=scope, paths=sorted(paths)))
                self.assertEqual(tuple(sorted(paths)), result.paths)
                self.assertRegex(self.bind(result, self.decision(result)), r"^[0-9a-f]{64}$")
                self.assertTrue(all(not path.startswith(("scripts/", ".github/")) for path in paths))

    def test_bounded_strict_json_rejects_malformed_duplicate_and_extra_fields(self):
        for raw in (b"", b"[", b"\xff", b"{}", b"[]", b'{"scope":"matrix","scope":"matrix"}',
                    b'{"schema_version":NaN}', b" " * 8193, "{}"):
            with self.subTest(raw=repr(raw)[:80]), self.assertRaises(PrGateError):
                parse_restricted_transition(raw, identity=identity(default_sha=BASE),
                                            deployed_controller_sha=BASE, deployed_generation=1)
        for value in (self.declaration(authority=True), {"schema_version": 1}):
            with self.assertRaises(PrGateError):
                self.parse(value)

    def test_unknown_versions_generations_and_self_reported_deployment_fail(self):
        for field in ("schema_version", "controller_generation"):
            for value in (True, "1", 0, 2, None):
                with self.subTest(field=field, value=value), self.assertRaises(PrGateError):
                    self.parse(self.declaration(**{field: value}))
        for arguments in ({"deployed_generation": True}, {"deployed_generation": 2},
                          {"deployed_controller_sha": HEAD}, {"deployed_controller_sha": "bad"},
                          {"identity": identity()}, {"identity": identity(default_sha=BASE, base_branch="1.20.1")},
                          {"identity": identity(default_sha=HEAD, base_sha=HEAD), "deployed_controller_sha": HEAD}):
            with self.subTest(arguments=arguments), self.assertRaises(PrGateError):
                self.parse(**arguments)
        with self.assertRaisesRegex(PrGateError, "distinct candidate"):
            self.parse(self.declaration(head_sha=BASE), identity=identity(default_sha=BASE, head_sha=BASE))

    def test_paths_cannot_be_inferred_expanded_aliased_duplicated_or_cross_loader(self):
        for paths in ([], ["release/*"], ["release"], ["release/release-matrix.json/"],
                      ["./release/release-matrix.json"], ["release/../release/release-matrix.json"],
                      ["release\\release-matrix.json"], ["release/release-matrix.json"] * 2,
                      ["release/release-matrix.json", "scripts/ci/pr_gate.py"], [None], [{}], "matrix"):
            with self.subTest(paths=paths), self.assertRaises(PrGateError):
                self.parse(self.declaration(paths=paths))
        for declaration in (self.declaration(scope="future"), self.declaration(scope=[]),
                            self.declaration(scope="fabric-next", paths=["forge/build.gradle"]),
                            self.declaration(scope="neoforge-contract", paths=["neoforge/build.gradle"]),
                            self.declaration(scope="stonecutter-bootstrap", paths=["settings.gradle", "build.gradle"])):
            with self.subTest(declaration=declaration), self.assertRaises(PrGateError):
                self.parse(declaration)
        result = self.parse(self.declaration(scope="stonecutter-bootstrap", paths=["stonecutter.gradle"]))
        self.assertEqual(("stonecutter.gradle",), result.paths)

    def test_declaration_and_owner_decision_bind_every_identity_and_generation(self):
        for field in ("controller_sha", "base_sha", "head_sha"):
            with self.subTest(field=field), self.assertRaises(PrGateError):
                self.parse(self.declaration(**{field: "f" * 40}))
        transition = self.parse()
        mutations = {"schema_version": True, "purpose": "controller-upgrade-owner-authorization",
                     "repository": "other/repo", "pull_request": 18, "owner": "collaborator",
                     "decision": "revoke", "controller_generation": 2, "controller_sha": HEAD,
                     "base_sha": HEAD, "head_sha": BASE, "declaration_sha256": "0" * 64,
                     "comment_id": True, "comment_updated_at": "yesterday", "extra": True,
                     "comment_created_at": "2026-09-19T09:00:00Z", "comment_body": "approve"}
        for field, value in mutations.items():
            with self.subTest(field=field), self.assertRaises(PrGateError):
                self.bind(transition, self.decision(transition, **{field: value}))
        for decision in ({}, None, self.decision(transition, controller_generation=True)):
            with self.assertRaises(PrGateError):
                self.bind(transition, decision)
        other = self.parse(self.declaration(scope="verification", paths=["gradle/verification-metadata.xml"]))
        with self.assertRaises(PrGateError):
            self.bind(other, self.decision(transition))
        self.assertNotEqual(self.bind(transition, self.decision(transition)),
                            self.bind(transition, self.decision(transition, comment_id=92)))
        narrowed = self.parse(self.declaration(scope="stonecutter-bootstrap", paths=["stonecutter.gradle"]))
        expanded = self.parse(self.declaration(scope="stonecutter-bootstrap", paths=["build.gradle", "stonecutter.gradle"]))
        with self.assertRaises(PrGateError):
            self.bind(expanded, self.decision(narrowed))


class RunSelectionTests(unittest.TestCase):
    def test_authenticated_api_disables_environment_proxies_and_redirects(self) -> None:
        with mock.patch(
            "scripts.ci.pr_gate.urllib.request.build_opener",
            wraps=urllib.request.build_opener,
        ) as build_opener:
            GitHubApi(
                repository="owner/repo",
                token="test-token",
                api_url="https://api.github.invalid",
            )
        handlers = build_opener.call_args.args
        self.assertTrue(
            any(
                isinstance(handler, urllib.request.ProxyHandler)
                and handler.proxies == {}
                for handler in handlers
            )
        )
        self.assertTrue(any(type(handler).__name__ == "_NoRedirect" for handler in handlers))

    def test_newest_pending_attempt_supersedes_an_older_success(self) -> None:
        old = run(10)
        current = run(
            11,
            attempt=2,
            status="in_progress",
            conclusion=None,
            created_at="2026-08-10T10:01:00Z",
        )
        selected = select_newest_pull_run(
            [old, current],
            workflow="build-gate.yml",
            repository="owner/repo",
            identity=identity(),
        )
        self.assertEqual(SelectedRun(11, 2, "in_progress", None, current["created_at"]), selected)

    def test_wrong_pr_repository_and_default_controller_are_not_evidence(self) -> None:
        wrong_pr = run(10, pull=99)
        wrong_head = run(11, head="f" * 40)
        foreign = run(12)
        foreign["head_repository"] = {"full_name": "attacker/repo"}
        self.assertIsNone(
            select_newest_pull_run(
                [wrong_pr, wrong_head, foreign],
                workflow="build-gate.yml",
                repository="owner/repo",
                identity=identity(),
            )
        )

    def test_runs_name_their_controller_only_through_the_local_anchor(self) -> None:
        # The shape GitHub records (run 36249851051): PR head branch and commit, controller by reference.
        self.assertEqual(
            SelectedRun(10, 1, "completed", "success", "2026-08-10T10:00:00Z"),
            select_newest_pull_run(
                [run(10)], workflow="build-gate.yml", repository="owner/repo", identity=identity()
            ),
        )
        legacy_shape = run(11, branch="master", head=DEFAULT)
        stale_controller = run(12, controller="f" * 40)
        other_ref = run(13)
        other_ref["referenced_workflows"] = [{**anchor(), "ref": "refs/heads/feature/ui"}]
        other_sha = run(20)
        other_sha["referenced_workflows"] = [{**anchor(), "sha": "f" * 40}]
        # A remote reference names a branch: GitHub records its resolved commit but not in the path.
        remote_ref = run(21)
        remote_ref["referenced_workflows"] = [
            {**anchor(), "path": f"owner/repo/{CONTROLLER_ANCHOR_WORKFLOW}@master"}
        ]
        doubled_reversed = run(22)
        doubled_reversed["referenced_workflows"] = [anchor("f" * 40), anchor()]
        default_branch_only = run(23, branch="master")
        default_head_only = run(24, head=DEFAULT)
        unreferenced = run(14)
        del unreferenced["referenced_workflows"]
        doubled = run(15)
        doubled["referenced_workflows"] = [anchor(), anchor("f" * 40)]
        foreign_anchor = run(16)
        foreign_anchor["referenced_workflows"] = [anchor(repository="attacker/repo")]
        other_head = run(17, head="f" * 40)
        other_branch = run(18, branch="feature/other")
        for record in (
            legacy_shape, stale_controller, other_ref, other_sha, remote_ref, unreferenced,
            doubled, doubled_reversed, foreign_anchor, other_head, other_branch,
            default_branch_only, default_head_only,
        ):
            with self.subTest(record=record["id"]):
                self.assertIsNone(
                    select_newest_pull_run(
                        [record], workflow="build-gate.yml", repository="owner/repo",
                        identity=identity(),
                    )
                )
        extra = run(19)
        extra["referenced_workflows"].append(
            {"path": "owner/repo/.github/workflows/other.yml@" + DEFAULT,
             "ref": "refs/heads/master", "sha": DEFAULT}
        )
        self.assertTrue(
            runs_default_controller(
                extra, repository="owner/repo", default_branch="master", default_sha=DEFAULT
            )
        )
        for malformed in (None, "anchor", [None], [{"path": 7}]):
            with self.subTest(malformed=malformed):
                self.assertFalse(
                    runs_default_controller(
                        {"referenced_workflows": malformed}, repository="owner/repo",
                        default_branch="master", default_sha=DEFAULT,
                    )
                )

    def test_a_cancelled_concurrency_sibling_never_shadows_a_run_that_ran(self) -> None:
        # PR 15's Build pair: opened + labeled started 92 and 93 in the same second, and the
        # concurrency group cancelled 93 although it has the higher id.
        survivor = run(36251236264, created_at="2026-09-26T15:14:24Z")
        cancelled = run(36251236289, created_at="2026-09-26T15:14:24Z", conclusion="cancelled")
        later_cancelled = run(36251236290, created_at="2026-09-26T15:14:25Z", conclusion="cancelled")
        for records in ([survivor, cancelled], [cancelled, survivor], [survivor, later_cancelled]):
            with self.subTest(records=[record["id"] for record in records]):
                self.assertEqual(
                    36251236264,
                    select_newest_pull_run(
                        records, workflow="build-gate.yml", repository="owner/repo",
                        identity=identity(),
                    ).run_id,
                )
        newer_failure = run(36251236300, created_at="2026-09-26T15:20:00Z", conclusion="failure")
        newer_pending = run(
            36251236301, created_at="2026-09-26T15:21:00Z", status="in_progress", conclusion=None
        )
        for newer in (newer_failure, newer_pending):
            with self.subTest(newer=newer["id"]):
                self.assertEqual(
                    newer["id"],
                    select_newest_pull_run(
                        [survivor, cancelled, newer], workflow="build-gate.yml",
                        repository="owner/repo", identity=identity(),
                    ).run_id,
                )
        only_cancelled = select_newest_pull_run(
            [cancelled, later_cancelled], workflow="build-gate.yml", repository="owner/repo",
            identity=identity(),
        )
        self.assertEqual((36251236290, "cancelled"), (only_cancelled.run_id, only_cancelled.conclusion))

    def test_legacy_pull_request_run_is_not_protected_evidence(self) -> None:
        self.assertIsNone(
            select_newest_pull_run(
                [run(10, event="pull_request")],
                workflow="build-gate.yml",
                repository="owner/repo",
                identity=identity(),
            )
        )

    def test_workflow_run_inventory_is_prt_only_without_head_sha_query(self) -> None:
        api = object.__new__(GitHubApi)
        api.pages = mock.Mock(return_value=[])
        self.assertEqual([], api.workflow_runs("build-gate.yml"))
        suffix = api.pages.call_args.args[0]
        self.assertIn("event=pull_request_target", suffix)
        self.assertNotIn("head_sha", suffix)

    def test_duplicate_current_run_id_fails_closed_even_with_another_attempt(self) -> None:
        current = run(10)
        repeated = copy.deepcopy(current)
        repeated["run_attempt"] = 2
        with self.assertRaisesRegex(PrGateError, "repeats"):
            select_newest_pull_run(
                [current, repeated],
                workflow="build-gate.yml",
                repository="owner/repo",
                identity=identity(),
            )


class ArtifactAndGraphTests(unittest.TestCase):
    def artifact(self, name: str, *, run_id: int = 51) -> dict[str, object]:
        return {
            "id": 701,
            "name": name,
            "expired": False,
            "size_in_bytes": 4096,
            "digest": "sha256:" + "9" * 64,
            "workflow_run": {"id": run_id},
        }

    def test_artifact_identity_binds_tested_merge_attempt_and_owner(self) -> None:
        expected = f"staged-release-bundle-{MERGE}-3"
        artifact = self.artifact(expected)
        self.assertEqual(
            701,
            validate_exact_artifact([artifact], expected_name=expected, run_id=51)["id"],
        )
        for label, mutate in (
            ("stale merge", lambda value: value.__setitem__("name", f"staged-release-bundle-{HEAD}-3")),
            ("wrong owner", lambda value: value.__setitem__("workflow_run", {"id": 52})),
            ("expired", lambda value: value.__setitem__("expired", True)),
            ("no digest", lambda value: value.__setitem__("digest", None)),
        ):
            broken = copy.deepcopy(artifact)
            mutate(broken)
            with self.subTest(label=label), self.assertRaises(PrGateError):
                validate_exact_artifact([broken], expected_name=expected, run_id=51)

    def test_success_requires_exact_job_graph_and_artifact(self) -> None:
        selected = SelectedRun(51, 3, "completed", "success", "2026-08-10T10:00:00Z")
        graph = expected_jobs(
            MATRIX,
            "build-gate.yml",
            event="pull_request_target",
            source_branch="master",
        )
        jobs = [
            {
                "id": index + 1,
                "name": item.name,
                "run_attempt": 3,
                "status": "completed",
                "conclusion": item.conclusion,
            }
            for index, item in enumerate(graph)
        ]
        expected_name = f"staged-release-bundle-{MERGE}-3"

        class Api:
            def __init__(self, values: list[dict[str, object]]) -> None:
                self.values = values

            def jobs(self, _run_id: int):
                return self.values

            def artifacts(self, _run_id: int):
                return [ArtifactAndGraphTests().artifact(expected_name)]

        accepted = _gate_result(
            Api(jobs),
            kind="build",
            identity=identity(),
            matrix_path=MATRIX,
            selected=selected,
        )
        self.assertEqual("success", accepted.state)
        rejected = _gate_result(
            Api([*jobs, {"id": 99, "name": "invented", "run_attempt": 3, "status": "completed", "conclusion": "success"}]),
            kind="build",
            identity=identity(),
            matrix_path=MATRIX,
            selected=selected,
        )
        self.assertEqual("failure", rejected.state)


class ControllerAnchorWorkflowTests(unittest.TestCase):
    def test_both_gates_call_the_anchor_through_a_repository_local_reference(self) -> None:
        # A pull_request_target run resolves a local ``uses:`` from the default branch at its exact commit.
        self.assertTrue((REPO / CONTROLLER_ANCHOR_WORKFLOW).is_file())
        for workflow in ("build-gate.yml", "on-demand-e2e.yml"):
            text = (REPO / ".github/workflows" / workflow).read_text(encoding="utf-8")
            with self.subTest(workflow=workflow):
                self.assertEqual(1, text.count(f"    uses: ./{CONTROLLER_ANCHOR_WORKFLOW}\n"))


class PullIdentityTests(unittest.TestCase):
    class Api:
        repository = "owner/repo"

        def __init__(
            self,
            *,
            head_branch: str = "feature/ui",
            run_record: dict[str, object] | None = None,
            fork_pull: bool = False,
        ) -> None:
            self.head_branch = head_branch
            self.run_record = run(51) if run_record is None else run_record
            self.fork_pull = fork_pull

        def run(self, run_id: int):
            value = copy.deepcopy(self.run_record)
            value["id"] = run_id
            return value

        def repository_record(self):
            return {"full_name": self.repository, "default_branch": "master"}

        def pull(self, number: int):
            return {
                "number": number,
                "state": "open",
                "head": {
                    "ref": self.head_branch,
                    "sha": HEAD,
                    "repo": {
                        "full_name": "attacker/repo" if self.fork_pull else self.repository
                    },
                },
                "base": {
                    "ref": "ship/stable",
                    "sha": BASE,
                    "repo": {"full_name": self.repository},
                },
                "merge_commit_sha": MERGE,
            }

        def branch_sha(self, branch: str):
            return {
                "master": DEFAULT,
                "ship/stable": BASE,
                self.head_branch: HEAD,
            }[branch]

        def commit_identity(self, commit: str):
            self.assert_commit = commit
            return "e" * 40, (BASE, HEAD)

    def test_trigger_authenticates_default_controller_and_current_merge_parents(self) -> None:
        current = resolve_pull_identity(
            self.Api(), trigger_run_id=51, implementation_sha=DEFAULT
        )
        self.assertEqual(
            identity(base_branch="ship/stable"),
            current,
        )

    def test_source_locator_needs_no_trigger_and_exports_complete_identity(self) -> None:
        current = resolve_pull_identity(
            self.Api(), pr_number=17, implementation_sha=DEFAULT
        )
        self.assertEqual(
            {
                "eligible": True,
                "pr_number": 17,
                "default_branch": "master",
                "default_sha": DEFAULT,
                "base_branch": "ship/stable",
                "base_sha": BASE,
                "head_branch": "feature/ui",
                "head_sha": HEAD,
                "merge_sha": MERGE,
                "merge_tree": "e" * 40,
            },
            _source_outputs(current),
        )

    def test_trigger_rejects_legacy_event_path_repository_and_controller(self) -> None:
        invalid: list[dict[str, object]] = []
        legacy = run(51, event="pull_request")
        invalid.append(legacy)
        invalid.append(run(51, workflow="untrusted.yml"))
        foreign = run(51)
        foreign["head_repository"] = {"full_name": "attacker/repo"}
        invalid.append(foreign)
        invalid.append(run(51, branch="ship/stable"))
        invalid.append(run(51, branch="master"))
        invalid.append(run(51, controller="f" * 40))
        unreferenced = run(51)
        del unreferenced["referenced_workflows"]
        invalid.append(unreferenced)
        for record in invalid:
            with self.subTest(record=record), self.assertRaises(NotEligible):
                resolve_pull_identity(
                    self.Api(run_record=record),
                    trigger_run_id=51,
                    implementation_sha=DEFAULT,
                )

    def test_trigger_from_an_older_head_still_evaluates_the_current_head(self) -> None:
        current = resolve_pull_identity(
            self.Api(run_record=run(51, head="f" * 40)), trigger_run_id=51, implementation_sha=DEFAULT
        )
        self.assertEqual(identity(base_branch="ship/stable"), current)

    def test_trigger_and_pull_associations_are_exactly_one_and_same_repository(self) -> None:
        ambiguous = run(51)
        ambiguous["pull_requests"] = [{"number": 17}, {"number": 18}]
        with self.assertRaisesRegex(PrGateError, "exactly one"):
            resolve_pull_identity(
                self.Api(run_record=ambiguous),
                trigger_run_id=51,
                implementation_sha=DEFAULT,
            )
        with self.assertRaisesRegex(NotEligible, "wholly same-repository"):
            resolve_pull_identity(
                self.Api(fork_pull=True),
                trigger_run_id=51,
                implementation_sha=DEFAULT,
            )

    def test_default_implementation_and_ordered_merge_parents_fail_closed(self) -> None:
        with self.assertRaisesRegex(NotEligible, "default branch advanced"):
            resolve_pull_identity(
                self.Api(), pr_number=17, implementation_sha="f" * 40
            )
        api = self.Api()
        api.commit_identity = lambda _commit: ("e" * 40, (HEAD, BASE))
        with self.assertRaisesRegex(PrGateError, "exact current base/head parents"):
            resolve_pull_identity(api, pr_number=17, implementation_sha=DEFAULT)

    def test_release_sync_heads_are_explicitly_ineligible(self) -> None:
        api = self.Api(head_branch="automation/release-sync/abc")
        with self.assertRaisesRegex(NotEligible, "release synchronization"):
            resolve_pull_identity(api, trigger_run_id=51, implementation_sha=DEFAULT)


class ResolveSourceCliTests(unittest.TestCase):
    def arguments(self, output: Path) -> list[str]:
        return [
            "resolve-source",
            "--repository-name",
            "owner/repo",
            "--implementation-sha",
            DEFAULT,
            "--pr-number",
            "17",
            "--github-output",
            str(output),
        ]

    def test_cli_exports_every_authenticated_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "github-output"
            with mock.patch("scripts.ci.pr_gate.GitHubApi"), mock.patch(
                "scripts.ci.pr_gate.resolve_pull_identity",
                return_value=identity(base_branch="ship/stable"),
            ), mock.patch("sys.stdout"):
                self.assertEqual(0, pr_gate_main(self.arguments(output)))
            values = dict(
                line.split("=", 1)
                for line in output.read_text("utf-8").splitlines()
            )
            self.assertEqual("true", values["eligible"])
            self.assertEqual("17", values["pr_number"])
            self.assertEqual("master", values["default_branch"])
            self.assertEqual(DEFAULT, values["default_sha"])
            self.assertEqual("ship/stable", values["base_branch"])
            self.assertEqual(BASE, values["base_sha"])
            self.assertEqual("feature/ui", values["head_branch"])
            self.assertEqual(HEAD, values["head_sha"])
            self.assertEqual(MERGE, values["merge_sha"])
            self.assertEqual("e" * 40, values["merge_tree"])

    def test_ineligible_source_is_a_hard_gate_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "github-output"
            with mock.patch("scripts.ci.pr_gate.GitHubApi"), mock.patch(
                "scripts.ci.pr_gate.resolve_pull_identity",
                side_effect=NotEligible("stale source"),
            ), mock.patch("sys.stderr"):
                self.assertEqual(2, pr_gate_main(self.arguments(output)))
            self.assertFalse(output.exists())


class DispatchSourceTests(unittest.TestCase):
    CANDIDATE_BRANCH = "automation/release-sync/ship-stable"
    TARGET_BRANCH = "ship/stable"

    class Api:
        repository = "owner/repo"

        def __init__(
            self,
            *,
            default_sha: str = DEFAULT,
            target_sha: str = BASE,
            candidate_sha: str = MERGE,
            candidate_tree: str = "e" * 40,
            parents: tuple[str, ...] = (BASE, DEFAULT),
        ) -> None:
            self.branches = {
                "master": default_sha,
                DispatchSourceTests.TARGET_BRANCH: target_sha,
                DispatchSourceTests.CANDIDATE_BRANCH: candidate_sha,
            }
            self.candidate_tree = candidate_tree
            self.parents = parents

        def repository_record(self):
            return {"full_name": self.repository, "default_branch": "master"}

        def branch_sha(self, branch: str):
            return self.branches[branch]

        def commit_identity(self, commit: str):
            if commit != MERGE:
                raise AssertionError("unexpected candidate commit")
            return self.candidate_tree, self.parents

    @classmethod
    def arguments(cls, **overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "implementation_sha": DEFAULT,
            "expected_source_sha": DEFAULT,
            "target_branch": cls.TARGET_BRANCH,
            "expected_target_sha": BASE,
            "candidate_branch": cls.CANDIDATE_BRANCH,
            "expected_candidate_sha": MERGE,
            "expected_candidate_tree": "e" * 40,
        }
        values.update(overrides)
        return values

    def test_exact_dispatch_source_exports_resolve_source_compatible_identity(self) -> None:
        current = resolve_dispatch_source(self.Api(), **self.arguments())
        self.assertEqual(
            {
                "eligible": True,
                "pr_number": 0,
                "default_branch": "master",
                "default_sha": DEFAULT,
                "base_branch": self.TARGET_BRANCH,
                "base_sha": BASE,
                "head_branch": self.CANDIDATE_BRANCH,
                "head_sha": MERGE,
                "merge_sha": MERGE,
                "merge_tree": "e" * 40,
            },
            _source_outputs(current),
        )

    def test_cli_exposes_the_exact_dispatch_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "github-output"
            argv = [
                "resolve-dispatch-source",
                "--repository-name",
                "owner/repo",
                "--implementation-sha",
                DEFAULT,
                "--expected-source-sha",
                DEFAULT,
                "--target-branch",
                self.TARGET_BRANCH,
                "--expected-target-sha",
                BASE,
                "--candidate-branch",
                self.CANDIDATE_BRANCH,
                "--expected-candidate-sha",
                MERGE,
                "--expected-candidate-tree",
                "e" * 40,
                "--github-output",
                str(output),
            ]
            with mock.patch("scripts.ci.pr_gate.GitHubApi"), mock.patch(
                "scripts.ci.pr_gate.resolve_dispatch_source",
                return_value=identity(
                    number=0,
                    base_branch=self.TARGET_BRANCH,
                    head_branch=self.CANDIDATE_BRANCH,
                    head_sha=MERGE,
                ),
            ), mock.patch("sys.stdout"):
                self.assertEqual(0, pr_gate_main(argv))
            values = dict(
                line.split("=", 1)
                for line in output.read_text("utf-8").splitlines()
            )
            self.assertEqual("0", values["pr_number"])
            self.assertEqual(MERGE, values["merge_sha"])
            self.assertEqual("e" * 40, values["merge_tree"])

    def test_default_source_target_candidate_and_tree_drift_are_ineligible(self) -> None:
        cases = (
            (self.Api(default_sha="f" * 40), self.arguments()),
            (self.Api(), self.arguments(expected_source_sha="f" * 40)),
            (self.Api(target_sha="f" * 40), self.arguments()),
            (self.Api(candidate_sha="f" * 40), self.arguments()),
            (self.Api(candidate_tree="f" * 40), self.arguments()),
        )
        for api, arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(NotEligible):
                resolve_dispatch_source(api, **arguments)

    def test_dispatch_candidate_prefix_and_ordered_parents_fail_closed(self) -> None:
        with self.assertRaisesRegex(PrGateError, "protected prefix"):
            resolve_dispatch_source(
                self.Api(),
                **self.arguments(candidate_branch="feature/not-sync"),
            )
        with self.assertRaisesRegex(PrGateError, "ordered target/default parents"):
            resolve_dispatch_source(
                self.Api(parents=(DEFAULT, BASE)),
                **self.arguments(),
            )


class RestrictedTransitionOwnerTests(unittest.TestCase):
    class MockGitHub(PullIdentityTests.Api, GitHubApi):
        repository = "The-Plum-Team/Block-Pops-Minecraft-Mod"
        api_url = "https://api.github.test"

        def __init__(self, comments):
            PullIdentityTests.Api.__init__(self)
            self.comments, self.calls = copy.deepcopy(comments), []
            self.owner = {"login": "The-Plum-Team", "type": "Organization"}

        def repository_record(self):
            return {**super().repository_record(), "owner": self.owner}

        def pull(self, number):
            value = super().pull(number)
            value["base"]["ref"] = "master"
            return value

        def branch_sha(self, branch):
            return BASE if branch == "master" else super().branch_sha(branch)

        def json(self, suffix, *, label):
            self.calls.append(suffix)
            if suffix.startswith("/issues/17/comments?"):
                page = int(suffix.rsplit("page=", 1)[1])
                return copy.deepcopy(self.comments[(page - 1) * 100:page * 100])
            for comment in self.comments:
                if suffix == f"/issues/comments/{comment['id']}":
                    return copy.deepcopy(comment)
            raise PrGateError("issue comment API returned HTTP 404")

    def setUp(self):
        fixture = RestrictedTransitionDeclarationTests()
        self.transition = fixture.parse()
        self.declaration = json.dumps(fixture.declaration()).encode()

    def comment(self, **overrides):
        return {
            "id": 91, "user": {"login": "AkaNebur", "type": "User"},
            "body": f"/restricted-transition approve 1 {HEAD} {self.transition.digest}",
            "created_at": "2026-09-19T10:00:00Z", "updated_at": "2026-09-19T10:00:00Z",
            "issue_url": f"{self.MockGitHub.api_url}/repos/{self.MockGitHub.repository}/issues/17",
            "author_association": "MEMBER", "performed_via_github_app": None, **overrides,
        }

    def read(self, api, **overrides):
        return read_restricted_transition_owner_decision(api, identity(default_sha=BASE), **{
            "declaration": self.declaration, "deployed_controller_sha": BASE,
            "deployed_generation": 1, **overrides})

    def test_fresh_owner_record_binds_complete_decision_without_gate_admission(self):
        api = self.MockGitHub([self.comment()])
        decision = self.read(api)
        self.assertEqual(RestrictedTransitionDeclarationTests().decision(self.transition), decision)
        self.assertEqual(["/issues/17/comments?per_page=100&page=1", "/issues/comments/91",
                          "/issues/17/comments?per_page=100&page=1"], api.calls)
        self.assertRegex(bind_restricted_transition_decision(
            self.transition, repository=api.repository, pull_number=17,
            authenticated_owner_decision=decision), r"^[0-9a-f]{64}$")

    def test_grammar_purpose_generation_head_digest_and_edits_are_exact(self):
        body = self.comment()["body"]
        mutations = [{"body": value} for value in (
            body.replace("approve", "revoke"), body.replace(" 1 ", " 2 "),
            body.replace(HEAD, BASE), body.replace(self.transition.digest, "0" * 64),
            body + "\n", " " + body, f"/controller-upgrade approve {HEAD}")]
        mutations += [{"created_at": "2026-09-19T09:00:00Z"}, {"created_at": None},
                      {"updated_at": "yesterday"}, {"id": True}]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(PrGateError):
                self.read(self.MockGitHub([self.comment(**mutation)]))

    def test_only_exact_owner_user_direct_comment_on_this_pull_is_authority(self):
        mutations = ({"user": {"login": "collaborator", "type": "User"}},
                     {"user": {"login": "AkaNebur", "type": "Bot"}},
                     {"performed_via_github_app": {"id": 1}}, {"author_association": "COLLABORATOR"},
                     {"author_association": "OWNER"},
                     {"issue_url": "https://api.github.test/repos/other/repo/issues/17"},
                     {"issue_url": self.comment()["issue_url"].replace("/17", "/18")})
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(PrGateError):
                self.read(self.MockGitHub([self.comment(**mutation)]))
        # AkaNebur owned the repository before it moved to the organization.
        for owner in ({"login": "other", "type": "Organization"}, {"login": "The-Plum-Team", "type": "User"},
                      {"login": "AkaNebur", "type": "User"}):
            api = self.MockGitHub([self.comment()])
            api.owner = owner
            with self.assertRaisesRegex(PrGateError, "repository owner"):
                self.read(api)

    def test_latest_owned_command_never_falls_back_after_revoke_stale_or_malformed(self):
        for body in (self.comment()["body"].replace("approve", "revoke"),
                     self.comment()["body"].replace(HEAD, BASE), "/restricted-transition invalid"):
            with self.subTest(body=body), self.assertRaises(PrGateError):
                self.read(self.MockGitHub([self.comment(id=92, body=body), self.comment()]))
        self.assertEqual(92, self.read(self.MockGitHub([self.comment(id=92), self.comment()]))["comment_id"])

    def test_selected_comment_requires_fresh_get_and_cannot_disappear_or_change(self):
        for mutation in ({"body": "edited"}, {"updated_at": "2026-09-19T10:01:00Z"},
                         {"id": 92}, {"user": None}, {"issue_url": "wrong"}):
            api = self.MockGitHub([self.comment()])
            with self.subTest(mutation=mutation), mock.patch.object(
                    api, "issue_comment", return_value=self.comment(**mutation)), self.assertRaises(PrGateError):
                self.read(api)
        api = self.MockGitHub([self.comment()])
        with mock.patch.object(api, "issue_comment", side_effect=PrGateError("HTTP 404")), self.assertRaises(PrGateError):
            self.read(api)

    def test_editing_away_a_command_blocks_older_approval_until_a_fresh_decision(self):
        edited = self.comment(id=92, body="command removed", updated_at="2026-09-19T10:01:00Z")
        api = self.MockGitHub([self.comment(), edited])
        with self.assertRaises(PrGateError):
            self.read(api)
        with self.assertRaises(PrGateError):
            self.read(self.MockGitHub([self.comment(), self.comment(
                id=90, body="command removed", created_at="2026-09-19T09:00:00Z")]))
        api.comments.append(self.comment(id=93, created_at="2026-09-19T10:02:00Z",
                                         updated_at="2026-09-19T10:02:00Z"))
        self.assertEqual(93, self.read(api)["comment_id"])

    def test_reinventory_catches_deletion_edit_and_new_revocation_during_read(self):
        for comments in ([], [self.comment(body="edited")], [self.comment(), self.comment(
                id=92, body=self.comment()["body"].replace("approve", "revoke"))]):
            api = self.MockGitHub([self.comment()])
            def fresh(_comment_id):
                api.comments = comments
                return self.comment()
            with self.subTest(comments=comments), mock.patch.object(
                    api, "issue_comment", side_effect=fresh), self.assertRaises(PrGateError):
                self.read(api)

    def test_current_pull_and_deployed_controller_are_rechecked(self):
        api = self.MockGitHub([self.comment()])
        for overrides in ({"deployed_controller_sha": HEAD}, {"deployed_generation": 2}):
            with self.assertRaises(PrGateError):
                self.read(api, **overrides)
        with mock.patch.object(api, "pull", return_value={}), self.assertRaises(PrGateError):
            self.read(api)
        original = api.branch_sha
        def changed(branch):
            return "f" * 40 if api.calls and branch == api.head_branch else original(branch)
        with mock.patch.object(api, "branch_sha", side_effect=changed), self.assertRaises(PrGateError):
            self.read(api)

    def test_paginated_inventory_duplicate_ids_and_limit_fail_closed(self):
        comments = [self.comment(id=index + 100, body="discussion") for index in range(100)]
        api = self.MockGitHub(comments + [self.comment()])
        self.read(api)
        self.assertEqual(2, api.calls.count("/issues/17/comments?per_page=100&page=2"))
        for comments in ([self.comment()] * 2,
                         [self.comment(id=index + 100) for index in range(1000)]):
            with self.subTest(count=len(comments)), self.assertRaises(PrGateError):
                self.read(self.MockGitHub(comments))


class ControllerUpgradeAuthorizationTests(unittest.TestCase):
    class Api:
        repository = "The-Plum-Team/Block-Pops-Minecraft-Mod"

        def __init__(self, comments: list[dict[str, object]], *, labelled: bool = True) -> None:
            self.comments = comments
            self.labelled = labelled

        def pull(self, number: int):
            return {
                "number": number,
                "labels": [{"name": "controller-upgrade"}] if self.labelled else [],
            }

        def repository_record(self):
            return {
                "full_name": self.repository,
                "owner": {"login": "The-Plum-Team", "type": "Organization"},
            }

        def issue_comments(self, _number: int):
            return self.comments

    @staticmethod
    def comment(
        comment_id: int,
        decision: str,
        *,
        head: str = HEAD,
        actor: str = "AkaNebur",
        association: str = "MEMBER",
        updated: str = "2026-08-11T10:00:00Z",
    ) -> dict[str, object]:
        return {
            "id": comment_id,
            "body": f"/controller-upgrade {decision} {head}",
            "updated_at": updated,
            "author_association": association,
            "user": {"login": actor, "type": "User"},
        }

    @staticmethod
    def current() -> PullIdentity:
        return identity(
            default_sha=BASE,
            base_sha=BASE,
            head_branch="controller-upgrade/visual-gate",
        )

    def test_exact_current_head_owner_approval_is_digest_bound(self) -> None:
        api = self.Api([self.comment(91, "approve")])
        authorization = controller_upgrade_authorization(api, self.current())
        self.assertEqual(91, authorization.comment_id)
        self.assertEqual(HEAD, authorization.head_sha)
        self.assertRegex(authorization.digest, r"^[0-9a-f]{64}$")

    def test_latest_exact_head_revoke_wins(self) -> None:
        api = self.Api(
            [
                self.comment(91, "approve"),
                self.comment(92, "revoke", updated="2026-08-11T10:01:00Z"),
            ]
        )
        with self.assertRaisesRegex(PrGateError, "revokes"):
            controller_upgrade_authorization(api, self.current())

    def test_stale_or_non_owner_commands_cannot_authorize(self) -> None:
        for comment in (
            self.comment(91, "approve", head="f" * 40),
            self.comment(91, "approve", actor="collaborator", association="MEMBER"),
            self.comment(91, "approve", association="COLLABORATOR"),
        ):
            with self.subTest(comment=comment), self.assertRaisesRegex(
                PrGateError, "lacks"
            ):
                controller_upgrade_authorization(self.Api([comment]), self.current())

    def test_label_and_exact_branch_prefix_are_both_required(self) -> None:
        with self.assertRaisesRegex(PrGateError, "label and branch prefix"):
            controller_upgrade_authorization(
                self.Api([self.comment(91, "approve")], labelled=False), self.current()
            )


class FinalReauthorizationTests(unittest.TestCase):
    def expected(self, **overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "implementation_sha": DEFAULT,
            "expected_pr_number": 17,
            "expected_default_branch": "master",
            "expected_default_sha": DEFAULT,
            "expected_base_branch": "master",
            "expected_base_sha": BASE,
            "expected_head_branch": "feature/ui",
            "expected_head_sha": HEAD,
            "expected_merge_sha": MERGE,
            "expected_merge_tree": "e" * 40,
            "expected_policy_mode": "ordinary",
            "expected_authorization_digest": "0" * 64,
            "expected_authorization_comment_id": 0,
        }
        values.update(overrides)
        return values

    def test_ordinary_identity_and_policy_are_reauthenticated(self) -> None:
        with mock.patch(
            "scripts.ci.pr_gate.resolve_pull_identity", return_value=identity()
        ), mock.patch("scripts.ci.pr_gate._upgrade_requested", return_value=False):
            value = reauthorize(mock.Mock(), **self.expected())
        self.assertTrue(value["authorization_current"])
        self.assertEqual(HEAD, value["head_sha"])

    def test_any_changed_branch_sha_or_tree_identity_is_ineligible_before_app_token(self) -> None:
        mutations = (
            identity(default_branch="mainline"),
            identity(default_sha="f" * 40),
            identity(base_branch="ship/other"),
            identity(base_sha="f" * 40),
            identity(head_branch="feature/renamed"),
            identity(head_sha="f" * 40),
            identity(merge_sha="f" * 40),
            identity(merge_tree="f" * 40),
        )
        for moved in mutations:
            with self.subTest(moved=moved), mock.patch(
                "scripts.ci.pr_gate.resolve_pull_identity", return_value=moved
            ):
                with self.assertRaisesRegex(NotEligible, "identity changed"):
                    reauthorize(mock.Mock(), **self.expected())

    def test_upgrade_digest_and_comment_must_still_match(self) -> None:
        authorization = UpgradeAuthorization(91, "2026-08-11T10:00:00Z", HEAD, "9" * 64)
        expected = self.expected(
            expected_policy_mode="controller-upgrade",
            expected_authorization_digest=authorization.digest,
            expected_authorization_comment_id=authorization.comment_id,
        )
        with mock.patch(
            "scripts.ci.pr_gate.resolve_pull_identity", return_value=identity()
        ), mock.patch(
            "scripts.ci.pr_gate.controller_upgrade_authorization",
            return_value=authorization,
        ):
            self.assertTrue(reauthorize(mock.Mock(), **expected)["authorization_current"])
        with mock.patch(
            "scripts.ci.pr_gate.resolve_pull_identity", return_value=identity()
        ), mock.patch(
            "scripts.ci.pr_gate.controller_upgrade_authorization",
            return_value=UpgradeAuthorization(92, authorization.comment_updated_at, HEAD, "8" * 64),
        ):
            self.assertFalse(reauthorize(mock.Mock(), **expected)["authorization_current"])


class TreePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        self.git("init", "-q", "-b", "master")
        self.git("config", "user.name", "Tests")
        self.git("config", "user.email", "tests@invalid.test")
        for relative in EXACT_BASE_OWNED_PATHS:
            target = self.repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            source = MATRIX if relative == "release/release-matrix.json" else REPO / relative
            if source.is_file():
                shutil.copyfile(source, target)
            else:
                target.write_text("base-owned\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(self.repository), *arguments], text=True
        ).strip()

    def merged(self, mutation: str | None = None) -> PullIdentity:
        self.git("switch", "-qc", "feature")
        if mutation is None:
            (self.repository / "product.txt").write_text("candidate\n", encoding="utf-8")
        else:
            path = self.repository / mutation
            path.write_text(path.read_text("utf-8") + "candidate\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "candidate")
        head = self.git("rev-parse", "HEAD")
        self.git("switch", "-q", "master")
        self.git("merge", "--no-ff", "--no-edit", "feature")
        merge = self.git("rev-parse", "HEAD")
        tree = self.git("rev-parse", "HEAD^{tree}")
        return identity(
            default_sha=self.base,
            default_branch=MATRIX_IDENTITY["canonical"],
            base_branch=MATRIX_IDENTITY["name"],
            base_sha=self.base,
            head_sha=head,
            merge_sha=merge,
            merge_tree=tree,
        )

    def test_default_to_base_and_base_to_merge_parity_are_both_required(self) -> None:
        current = self.merged()
        with mock.patch("scripts.ci.pr_gate.validate_controller_parity") as parity:
            matrix = validate_pr_tree(self.repository, current)
        self.assertEqual(MATRIX.read_bytes(), matrix)
        self.assertEqual(
            [
                mock.call(self.repository.resolve(), protected_sha=self.base, candidate_sha=self.base),
                mock.call(self.repository.resolve(), protected_sha=self.base, candidate_sha=current.merge_sha),
            ],
            parity.call_args_list,
        )

    def test_matrix_verification_and_version_specific_mutations_fail_closed(self) -> None:
        for path in EXACT_BASE_OWNED_PATHS:
            with self.subTest(path=path):
                # Each mutation needs an isolated repository because merged() advances master.
                self.tearDown()
                self.setUp()
                current = self.merged(path)
                with mock.patch("scripts.ci.pr_gate.validate_controller_parity"):
                    with self.assertRaisesRegex(PrGateError, "base-owned"):
                        validate_pr_tree(self.repository, current)

    def test_enrolled_opaque_release_base_is_authenticated_from_default_policy(self) -> None:
        # Start again from the integration base, then create a branch-local release matrix whose
        # name contains no Minecraft or loader assumptions.
        self.tearDown()
        self.setUp()
        integration = self.base
        self.git("switch", "-qc", "ship/aurora-ui")
        matrix_path = self.repository / "release/release-matrix.json"
        matrix = json.loads(matrix_path.read_text("utf-8"))
        matrix["branch"] = {
            "role": "release",
            "name": "ship/aurora-ui",
            "canonical": "master",
            "sync": {"enabled": True, "source": "master"},
        }
        matrix_path.write_text(json.dumps(matrix) + "\n", encoding="utf-8")
        self.git("add", "release/release-matrix.json")
        self.git("commit", "-qm", "opaque release matrix")
        release_base = self.git("rev-parse", "HEAD")
        self.git("switch", "-qc", "ordinary-change")
        (self.repository / "product.txt").write_text("candidate\n", encoding="utf-8")
        self.git("add", "product.txt")
        self.git("commit", "-qm", "ordinary release PR")
        head = self.git("rev-parse", "HEAD")
        self.git("switch", "-q", "ship/aurora-ui")
        self.git("merge", "--no-ff", "--no-edit", "ordinary-change")
        merge = self.git("rev-parse", "HEAD")
        current = identity(
            default_sha=integration,
            base_branch="ship/aurora-ui",
            base_sha=release_base,
            head_sha=head,
            merge_sha=merge,
            merge_tree=self.git("rev-parse", "HEAD^{tree}"),
        )
        with mock.patch("scripts.ci.pr_gate.validate_controller_parity") as parity:
            validate_pr_tree(self.repository, current)
        self.assertEqual(
            [
                mock.call(
                    self.repository.resolve(),
                    protected_sha=integration,
                    candidate_sha=release_base,
                ),
                mock.call(
                    self.repository.resolve(),
                    protected_sha=release_base,
                    candidate_sha=merge,
                ),
            ],
            parity.call_args_list,
        )


class RestrictedTransitionTreeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        self.git("init", "-q", "-b", "master")
        self.git("config", "user.name", "Tests")
        self.git("config", "user.email", "tests@invalid.test")
        for path in ("release/release-matrix.json", "settings.gradle", "scripts/ci/pr_gate.py"):
            self.write(path, "base\n")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")
        self.addCleanup(self.temporary.cleanup)

    def git(self, *arguments):
        return subprocess.check_output(["git", "-C", str(self.repository), *arguments], text=True).strip()

    def write(self, path, content):
        target = self.repository / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink() or target.is_file():
            target.unlink()
        if content is not None:
            target.write_text(content, encoding="utf-8")

    def merged(self, changes, *, mode=None, head_base=None, merge_tree=None):
        self.git("switch", "--discard-changes", "-qC", "candidate", head_base or self.base)
        for path, content in changes.items():
            self.write(path, content)
        self.git("add", "-A")
        if mode is not None:
            path, bits = mode
            oid = self.base if bits == "160000" else self.git("hash-object", "-w", "settings.gradle")
            self.git("update-index", "--add", "--cacheinfo", f"{bits},{oid},{path}")
        self.git("commit", "--allow-empty", "-qm", "candidate")
        head = self.git("rev-parse", "HEAD")
        tree = merge_tree or self.git("rev-parse", "HEAD^{tree}")
        merge = self.git("commit-tree", tree, "-p", self.base, "-p", head, "-m", "synthetic merge")
        self.git("checkout", "-qf", merge)
        return identity(default_sha=self.base, base_sha=self.base, head_sha=head,
                        merge_sha=merge, merge_tree=tree)

    def validate(self, current, paths, *, scope="stonecutter-bootstrap"):
        declaration = {"schema_version": 1, "controller_generation": 1, "scope": scope,
                       "paths": sorted(paths), "controller_sha": self.base,
                       "base_sha": self.base, "head_sha": current.head_sha}
        return validate_restricted_transition_tree(
            self.repository, current, declaration=json.dumps(declaration).encode(),
            deployed_controller_sha=self.base, deployed_generation=1)

    def test_exact_add_modify_delete_and_immutable_objects(self):
        current = self.merged({"settings.gradle": "changed\n", "stonecutter.gradle": "new\n"})
        self.write("settings.gradle", "uncommitted attacker bytes\n")
        result = self.validate(current, ["settings.gradle", "stonecutter.gradle"])
        self.assertEqual(("settings.gradle", "stonecutter.gradle"), result.paths)
        self.git("restore", "settings.gradle")
        current = self.merged({"settings.gradle": None})
        self.validate(current, ["settings.gradle"])

    def test_extras_authority_updates_undeclared_and_unchanged_paths_fail(self):
        for changes, declared in (
            ({"settings.gradle": "next", "product.txt": "extra"}, ["settings.gradle"]),
            ({"settings.gradle": "next", "scripts/ci/pr_gate.py": "self-authorize"}, ["settings.gradle"]),
            ({"settings.gradle": "next"}, ["settings.gradle", "stonecutter.gradle"]),
            ({"stonecutter.gradle": "next"}, ["settings.gradle"]),
            ({}, ["settings.gradle"]),
        ):
            with self.subTest(changes=changes), self.assertRaises(PrGateError):
                self.validate(self.merged(changes), declared)

    def test_rename_detection_cannot_widen_scope(self):
        self.git("config", "diff.renames", "true")
        current = self.merged({"settings.gradle": None, "outside.gradle": "base\n"})
        with self.assertRaises(PrGateError):
            self.validate(current, ["settings.gradle"])

    def test_symlink_gitlink_and_executable_entries_fail(self):
        for mode in ("120000", "160000", "100755"):
            with self.subTest(mode=mode):
                current = self.merged({}, mode=("stonecutter.gradle", mode))
                with self.assertRaisesRegex(PrGateError, "non-executable blobs"):
                    self.validate(current, ["stonecutter.gradle"])

    def test_local_config_cannot_hide_an_out_of_scope_submodule(self):
        self.git("config", "diff.ignoreSubmodules", "all")
        current = self.merged({"settings.gradle": "next"}, mode=("hidden", "160000"))
        with self.assertRaises(PrGateError):
            self.validate(current, ["settings.gradle"])

    def test_replacement_base_cannot_hide_an_extra_candidate_path(self):
        current = self.merged({"settings.gradle": "next", "product.txt": "extra"})
        base_blob = self.git("rev-parse", f"{self.base}:settings.gradle")
        self.git("read-tree", current.merge_sha)
        self.git("update-index", "--cacheinfo", f"100644,{base_blob},settings.gradle")
        replacement = self.git("commit-tree", self.git("write-tree"), "-m", "forged base")
        self.git("replace", self.base, replacement)
        with self.assertRaises(PrGateError):
            self.validate(current, ["settings.gradle"])

    def test_grafts_cannot_invent_base_ancestry(self):
        base_tree = self.git("rev-parse", f"{self.base}^{{tree}}")
        unrelated = self.git("commit-tree", base_tree, "-m", "unrelated root")
        current = self.merged({"settings.gradle": "next"}, head_base=unrelated)
        grafts = self.repository / ".git/info/grafts"
        grafts.write_text(f"{current.head_sha} {self.base}\n", encoding="utf-8")
        with self.assertRaises(PrGateError):
            self.validate(current, ["settings.gradle"])

    def test_mode_and_type_changes_fail_even_for_an_exact_declared_path(self):
        for mode in ("100755", "120000", "160000"):
            with self.subTest(mode=mode):
                current = self.merged({}, mode=("settings.gradle", mode))
                with self.assertRaises(PrGateError):
                    self.validate(current, ["settings.gradle"])

    def test_stale_checkout_tree_parents_and_divergent_head_fail(self):
        current = self.merged({"settings.gradle": "next"})
        with self.assertRaisesRegex(PrGateError, "tree disagrees"):
            self.validate(replace(current, merge_tree="f" * 40), ["settings.gradle"])
        self.git("checkout", "-q", current.head_sha)
        with self.assertRaisesRegex(PrGateError, "exact current synthetic merge"):
            self.validate(current, ["settings.gradle"])
        bad_merge = self.git("commit-tree", current.merge_tree, "-p", current.head_sha,
                             "-p", self.base, "-m", "reordered")
        self.git("checkout", "-q", bad_merge)
        with self.assertRaisesRegex(PrGateError, "stale or reordered parents"):
            self.validate(replace(current, merge_sha=bad_merge), ["settings.gradle"])
        base_tree = self.git("rev-parse", f"{self.base}^{{tree}}")
        mismatch = self.merged({"settings.gradle": "next"}, merge_tree=base_tree)
        with self.assertRaisesRegex(PrGateError, "different trees"):
            self.validate(mismatch, ["settings.gradle"])
        unrelated = self.git("commit-tree", base_tree, "-m", "unrelated root")
        divergent = self.merged({"settings.gradle": "next"}, head_base=unrelated)
        with self.assertRaises(PrGateError):
            self.validate(divergent, ["settings.gradle"])


class RestrictedTransitionEvaluationTests(unittest.TestCase):
    git = RestrictedTransitionTreeTests.git
    write = RestrictedTransitionTreeTests.write
    merged = RestrictedTransitionTreeTests.merged

    class MockGitHub(RestrictedTransitionOwnerTests.MockGitHub):
        def __init__(self, current, comments):
            super().__init__(comments)
            self.current, self.runs, self.job_records, self.artifact_records = current, {}, {}, {}
            for run_id, workflow in ((51, "build-gate.yml"), (52, "on-demand-e2e.yml")):
                value = run(run_id, workflow=workflow, branch=current.head_branch,
                            head=current.head_sha, controller=current.default_sha,
                            repository=self.repository)
                self.runs[workflow] = [value]
                self.job_records[run_id] = [
                    {"id": run_id * 100 + index, "name": item.name, "run_attempt": 1,
                     "status": "completed", "conclusion": item.conclusion}
                    for index, item in enumerate(expected_jobs(MATRIX, workflow,
                        event="pull_request_target", source_branch=current.base_branch))]
                name = (f"staged-release-bundle-{current.merge_sha}-1" if run_id == 51
                        else aggregate_artifact_name(current.merge_sha, 1))
                self.artifact_records[run_id] = [ArtifactAndGraphTests().artifact(name, run_id=run_id)]

        def pull(self, number):
            value = super().pull(number)
            value["head"]["sha"], value["base"]["sha"] = self.current.head_sha, self.current.base_sha
            value["merge_commit_sha"] = self.current.merge_sha
            return value

        def branch_sha(self, branch):
            return self.current.default_sha if branch == "master" else self.current.head_sha

        def commit_identity(self, _commit):
            return self.current.merge_tree, (self.current.base_sha, self.current.head_sha)

        def workflow_runs(self, workflow):
            return copy.deepcopy(self.runs[workflow])

        def jobs(self, run_id):
            return copy.deepcopy(self.job_records[run_id])

        def artifacts(self, run_id):
            return copy.deepcopy(self.artifact_records[run_id])

    def setUp(self):
        RestrictedTransitionTreeTests.setUp(self)
        self.write("release/release-matrix.json", MATRIX.read_text())
        self.write("gradle/verification-metadata.xml", "base verification\n")
        self.git("add", ".")
        self.git("commit", "--amend", "--no-edit", "-q")
        self.base = self.git("rev-parse", "HEAD")

    def candidate(self, changes=None, *, scope="verification", paths=None):
        changes = {"gradle/verification-metadata.xml": "next verification\n"} if changes is None else changes
        self.current = self.merged(changes)
        self.declaration = json.dumps({"schema_version": 1, "controller_generation": 1,
            "controller_sha": self.base, "base_sha": self.base, "head_sha": self.current.head_sha,
            "scope": scope, "paths": sorted(changes if paths is None else paths)}).encode()
        self.transition = parse_restricted_transition(self.declaration, identity=self.current,
            deployed_controller_sha=self.base, deployed_generation=1)
        comment = RestrictedTransitionOwnerTests.comment(self,
            body=f"/restricted-transition approve 1 {self.current.head_sha} {self.transition.digest}")
        self.api = self.MockGitHub(self.current, [comment])

    def evaluate(self, **overrides):
        return evaluate_restricted_transition(self.api, **{
            "repository": self.repository, "identity": self.current, "declaration": self.declaration,
            "deployed_controller_sha": self.base, "deployed_generation": 1, **overrides})

    def test_real_git_and_fresh_api_compose_bound_evidence_without_admission(self):
        self.candidate()
        self.write("release/release-matrix.json", "untrusted worktree policy")
        result = self.evaluate()
        self.assertEqual("evidence-validated", result["status"])
        self.assertIs(False, result["admission"])
        self.assertEqual(self.base, result["matrix"]["commit"])
        base_bytes = subprocess.check_output(["git", "-C", str(self.repository), "show", f"{self.base}:release/release-matrix.json"])
        self.assertEqual(hashlib.sha256(base_bytes).hexdigest(), result["matrix"]["sha256"])
        self.assertEqual(self.current.merge_tree, result["identity"]["merge_tree"])
        self.assertEqual(self.transition.digest, result["declaration_sha256"])
        self.assertEqual(3, self.api.calls.count("/issues/comments/91"))
        for kind, run_id in (("build", 51), ("e2e", 52)):
            gate = result["gates"][kind]
            self.assertEqual(CONTEXTS[kind], gate["context"])
            self.assertEqual(run_id, gate["evidence"]["run_id"])
            self.assertEqual("sha256:" + "9" * 64, gate["evidence"]["artifact"]["digest"])
            self.assertRegex(gate["evidence"]["jobs"]["sha256"], r"^[0-9a-f]{64}$")

    def test_candidate_authority_extra_paths_and_bad_generation_fail_before_evidence(self):
        self.candidate({"gradle/verification-metadata.xml": "next", "scripts/ci/pr_gate.py": "authority"},
                       paths=["gradle/verification-metadata.xml"])
        with mock.patch.object(self.api, "workflow_runs") as reads, self.assertRaises(PrGateError):
            self.evaluate()
        reads.assert_not_called()
        self.candidate()
        for overrides in ({"deployed_generation": 2}, {"deployed_controller_sha": self.current.head_sha},
                          {"identity": replace(self.current, head_sha="f" * 40)}):
            with self.subTest(overrides=overrides), self.assertRaises(PrGateError):
                self.evaluate(**overrides)

    def test_missing_owner_decision_cannot_be_replaced_by_successful_gates(self):
        self.candidate()
        self.api.comments = []
        with mock.patch.object(self.api, "workflow_runs") as reads, self.assertRaises(PrGateError):
            self.evaluate()
        reads.assert_not_called()

    def test_loader_scopes_require_real_contract_then_exact_next_semantics(self):
        fixture = RestrictedLoaderTransitionTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.repository, self.base = fixture.repository, fixture.base
        document, changes = fixture.proposal("fabric")
        self.candidate({fixture.contract_path: json.dumps(document)}, scope="fabric-contract")
        self.assertEqual("evidence-validated", self.evaluate()["status"])
        prepared = self.current.merge_sha
        self.base = prepared
        self.candidate({**changes, fixture.contract_path: json.dumps(document["next"])}, scope="fabric-next")
        self.assertEqual("evidence-validated", self.evaluate()["status"])
        changes["fabric/build.gradle"] += "// bytes absent from protected next\n"
        self.candidate({**changes, fixture.contract_path: json.dumps(document["next"])}, scope="fabric-next")
        with mock.patch.object(self.api, "workflow_runs") as reads, self.assertRaises(PrGateError):
            self.evaluate()
        reads.assert_not_called()
        self.base = fixture.base
        document["current"]["loaders"]["fabric"]["build_sha256"] = "0" * 64
        self.candidate({fixture.contract_path: json.dumps(document)}, scope="fabric-contract")
        with self.assertRaises(PrGateError): self.evaluate()

    def test_matrix_transitions_and_schema2_base_have_no_candidate_selected_graph(self):
        self.candidate({"release/release-matrix.json": MATRIX.read_text() + "\n"}, scope="matrix")
        with mock.patch.object(self.api, "workflow_runs") as reads, self.assertRaisesRegex(PrGateError, "evidence graph"):
            self.evaluate()
        reads.assert_not_called()
        self.git("checkout", "-qf", self.base)
        self.write("release/release-matrix.json", json.dumps(schema2_configuration()))
        self.git("add", "."); self.git("commit", "-qm", "schema2 protected fixture")
        self.base = self.git("rev-parse", "HEAD")
        self.candidate()
        with mock.patch.object(self.api, "workflow_runs") as reads, self.assertRaises(ValueError):
            self.evaluate()
        reads.assert_not_called()

    def test_missing_failed_pending_stale_or_duplicate_run_evidence_is_rejected(self):
        self.candidate()
        baseline = copy.deepcopy(self.api.runs)
        for kind in baseline:
            value = baseline[kind][0]
            pending = {**value, "id": value["id"] + 100, "status": "in_progress", "conclusion": None,
                       "created_at": "2026-08-11T10:00:00Z"}
            for rows in ([], [{**value, "conclusion": "failure"}], [value, pending],
                         [{**value, "head_sha": "f" * 40}], [value, value]):
                self.api.runs = {**copy.deepcopy(baseline), kind: rows}
                with self.subTest(kind=kind, rows=rows), self.assertRaises(PrGateError):
                    self.evaluate()

    def test_skipped_missing_extra_jobs_and_stale_or_mixed_artifacts_fail(self):
        self.candidate()
        for run_id in (51, 52):
            jobs, artifacts = copy.deepcopy(self.api.job_records[run_id]), copy.deepcopy(self.api.artifact_records[run_id])
            for rows in (jobs[:-1], jobs + [{**jobs[0], "id": 9999, "name": "invented"}],
                         [{**jobs[0], "conclusion": "skipped"}, *jobs[1:]],
                         [{**job, "run_attempt": 2} for job in jobs]):
                self.api.job_records[run_id] = rows
                with self.subTest(run_id=run_id, jobs=rows), self.assertRaises(PrGateError): self.evaluate()
            self.api.job_records[run_id] = jobs
            for mutation in ({"expired": True}, {"digest": None}, {"workflow_run": {"id": 999}},
                             {"name": artifacts[0]["name"].replace(self.current.merge_sha, self.current.head_sha)}):
                self.api.artifact_records[run_id] = [{**artifacts[0], **mutation}]
                with self.subTest(run_id=run_id, mutation=mutation), self.assertRaises(PrGateError): self.evaluate()
            self.api.artifact_records[run_id] = artifacts

    def test_reselection_binds_artifact_id_digest_and_job_identity(self):
        self.candidate()
        for field in ("id", "digest", "job"):
            reads = []
            original = self.api.artifacts
            def artifacts(run_id):
                rows = original(run_id)
                reads.append(run_id)
                if run_id == 52 and reads.count(52) == 1 and field == "job":
                    self.api.job_records[51][0]["id"] += 10000
                if run_id == 51 and reads.count(51) == 2 and field != "job":
                    rows[0][field] = 999 if field == "id" else "sha256:" + "8" * 64
                return rows
            with self.subTest(field=field), mock.patch.object(self.api, "artifacts", side_effect=artifacts), self.assertRaisesRegex(
                    PrGateError, "changed during reselection"):
                self.evaluate()

    def test_owner_revoke_replacement_and_identity_drift_after_evidence_fail(self):
        for change in ("revoke", "replacement", "head", "checkout"):
            self.candidate()
            original = self.api.artifacts
            def artifacts(run_id):
                rows = original(run_id)
                if run_id == 52:
                    if change == "revoke": self.api.comments[0]["body"] = self.api.comments[0]["body"].replace("approve", "revoke")
                    elif change == "replacement": self.api.comments[0]["id"] += 1
                    elif change == "head": self.api.current = replace(self.current, head_sha="f" * 40)
                    else: self.git("checkout", "-qf", self.current.head_sha)
                return rows
            with self.subTest(change=change), mock.patch.object(self.api, "artifacts", side_effect=artifacts), self.assertRaises(PrGateError):
                self.evaluate()


class RestrictedLoaderTransitionTests(unittest.TestCase):
    git = RestrictedTransitionTreeTests.git
    write = RestrictedTransitionTreeTests.write
    merged = RestrictedTransitionTreeTests.merged
    contract_path = "e2e/loader-bootstrap-contract.json"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name)
        self.git("init", "-q", "-b", "master")
        self.git("config", "user.name", "Tests")
        self.git("config", "user.email", "tests@invalid.test")
        document = json.loads((REPO / self.contract_path).read_bytes())
        self.current = document["current"] if document["schema_version"] == 2 else document
        self.current_bytes = {}
        for loader, contract in self.current["loaders"].items():
            build = f"{loader}/build.gradle"
            self.current_bytes[build] = f"// {loader} fixture\n{HARNESS_BINDING}\n"
            contract["build_sha256"] = hashlib.sha256(self.current_bytes[build].encode()).hexdigest()
            for path in contract["files"]:
                self.current_bytes[path] = f"// fixture current bytes: {path}\n"
                contract["files"][path] = hashlib.sha256(self.current_bytes[path].encode()).hexdigest()
        for path, content in self.current_bytes.items():
            self.write(path, content)
        self.write("release/release-matrix.json", MATRIX.read_text())
        self.write(self.contract_path, json.dumps(self.current))
        self.git("add", ".")
        self.git("commit", "-qm", "protected current bootstrap")
        self.base = self.git("rev-parse", "HEAD")

    def proposal(self, loader="fabric"):
        next_contract = copy.deepcopy(self.current)
        paths = (f"{loader}/build.gradle", next(
            path for path in self.current["loaders"][loader]["files"] if path.endswith(".java")))
        changes = {path: "// next generation\n" + self.current_bytes[path] for path in paths}
        next_contract["loaders"][loader]["build_sha256"] = hashlib.sha256(changes[paths[0]].encode()).hexdigest()
        next_contract["loaders"][loader]["files"][paths[1]] = hashlib.sha256(changes[paths[1]].encode()).hexdigest()
        return {"schema_version": 2, "generation": 1, "loader": loader,
                "current": copy.deepcopy(self.current), "next": next_contract}, changes

    def validate(self, current, scope, paths):
        declaration = {"schema_version": 1, "controller_generation": 1, "scope": scope,
                       "paths": sorted(paths), "controller_sha": self.base,
                       "base_sha": self.base, "head_sha": current.head_sha}
        return validate_restricted_loader_transition(
            self.repository, current, declaration=json.dumps(declaration).encode(),
            deployed_controller_sha=self.base, deployed_generation=1)

    def prepare(self, loader="fabric"):
        document, changes = self.proposal(loader)
        prepared = self.merged({self.contract_path: json.dumps(document)})
        self.validate(prepared, f"{loader}-contract", [self.contract_path])
        self.base = prepared.merge_sha
        return document, changes

    def test_each_loader_requires_separate_contract_then_exact_next_collapse(self):
        original = self.base
        for loader in ("fabric", "forge", "neoforge"):
            with self.subTest(loader=loader):
                self.base = original
                document, changes = self.prepare(loader)
                changes[self.contract_path] = json.dumps(document["next"])
                candidate = self.merged(changes)
                result = self.validate(candidate, f"{loader}-next", changes)
                self.assertEqual(f"{loader}-next", result.scope)

    def test_contract_phase_rejects_wrong_loader_stale_current_or_generation(self):
        for case in ("wrong loader", "stale current", "single digest", "unknown generation", "no next change"):
            document, _ = self.proposal()
            scope = "forge-contract" if case == "wrong loader" else "fabric-contract"
            if case == "stale current":
                document["current"]["loaders"]["fabric"]["build_sha256"] = "0" * 64
            elif case == "single digest":
                document = self.current
            elif case == "unknown generation":
                document["generation"] = 2
            elif case == "no next change":
                document["next"] = document["current"]
            candidate = self.merged({self.contract_path: json.dumps(document, indent=2)})
            with self.subTest(case=case), self.assertRaises(PrGateError):
                self.validate(candidate, scope, [self.contract_path])

    def test_contract_phase_cannot_replace_an_already_active_transition(self):
        document, _ = self.prepare()
        document["next"]["loaders"]["fabric"]["build_sha256"] = "0" * 64
        candidate = self.merged({self.contract_path: json.dumps(document)})
        with self.assertRaisesRegex(PrGateError, "preserve the protected current"):
            self.validate(candidate, "fabric-contract", [self.contract_path])

    def test_contract_phase_cannot_change_executables_or_ignore_inactive_loader_bytes(self):
        document, changes = self.proposal()
        changes[self.contract_path] = json.dumps(document)
        candidate = self.merged(changes)
        with self.assertRaises(PrGateError):
            self.validate(candidate, "fabric-contract", [self.contract_path])
        self.git("switch", "--discard-changes", "-qC", "broken-base", self.base)
        target = self.repository / "neoforge/build.gradle"
        target.write_bytes(b"// unbound inactive bytes\n" + target.read_bytes())
        self.git("add", ".")
        self.git("commit", "-qm", "broken inactive bootstrap")
        self.base = self.git("rev-parse", "HEAD")
        document, _ = self.proposal("neoforge")
        candidate = self.merged({self.contract_path: json.dumps(document)})
        with self.assertRaisesRegex(PrGateError, "neoforge build script differs"):
            self.validate(candidate, "neoforge-contract", [self.contract_path])

    def test_next_phase_rejects_current_mixed_wrong_loader_and_uncollapsed_bytes(self):
        document, changes = self.prepare()
        for case in ("current", "mixed", "wrong loader", "uncollapsed", "wrong contract"):
            proposal = dict(changes)
            if case in {"current", "wrong loader"}:
                proposal.clear()
            elif case == "mixed":
                proposal.pop(next(path for path in proposal if path.endswith(".java")))
            next_contract = copy.deepcopy(document["next"])
            if case == "wrong contract":
                next_contract["loaders"]["forge"]["build_sha256"] = "0" * 64
            if case != "uncollapsed":
                proposal[self.contract_path] = json.dumps(next_contract)
            candidate = self.merged(proposal)
            scope = "forge-next" if case == "wrong loader" else "fabric-next"
            with self.subTest(case=case), self.assertRaises(PrGateError):
                self.validate(candidate, scope, proposal)

    def test_self_admitted_next_and_non_loader_scopes_fail(self):
        document, changes = self.proposal()
        changes[self.contract_path] = json.dumps(document["next"])
        candidate = self.merged(changes)
        with self.assertRaisesRegex(PrGateError, "requires its declared loader transition"):
            self.validate(candidate, "fabric-next", changes)
        candidate = self.merged({"gradle/verification-metadata.xml": "new"})
        with self.assertRaisesRegex(PrGateError, "exact loader phase scope"):
            self.validate(candidate, "verification", ["gradle/verification-metadata.xml"])


class ControllerUpgradeTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        self.git("init", "-q", "-b", "master")
        self.git("config", "user.name", "Tests")
        self.git("config", "user.email", "tests@invalid.test")
        files = set(EXACT_BASE_OWNED_PATHS) | CONTROLLER_UPGRADE_REQUIRED | {
            "docs/operations.md"
        }
        for relative in sorted(files):
            target = self.repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            source = MATRIX if relative == "release/release-matrix.json" else REPO / relative
            if source.is_file():
                shutil.copyfile(source, target)
            else:
                target.write_text("base-owned\n", encoding="utf-8")
        matrix_path = self.repository / "release/release-matrix.json"
        matrix = json.loads(matrix_path.read_text("utf-8"))
        canonical = matrix["branch"]["canonical"]
        self.canonical = canonical
        matrix["branch"] = {
            "role": "integration",
            "name": canonical,
            "canonical": canonical,
            "sync": {"enabled": False, "source": canonical},
        }
        matrix_path.write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")
        self.matrix_bytes = matrix_path.read_bytes()
        self.git("add", ".")
        self.git("commit", "-qm", "protected controller baseline")
        self.base = self.git("rev-parse", "HEAD")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(self.repository), *arguments], text=True
        ).strip()

    def controller_merge(
        self, path: str, *, executable: bool = False, symlink: bool = False
    ) -> PullIdentity:
        self.git("switch", "-qC", "controller-upgrade/visual-gate", self.base)
        target = self.repository / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if symlink:
            target.symlink_to("outside")
        elif target.exists():
            target.write_text(target.read_text("utf-8") + "candidate\n", encoding="utf-8")
        else:
            target.write_text("candidate\n", encoding="utf-8")
        if executable:
            target.chmod(0o755)
        self.git("add", "--", path)
        self.git("commit", "-qm", "controller candidate")
        head = self.git("rev-parse", "HEAD")
        self.git("switch", "-qC", "master", self.base)
        self.git("merge", "--no-ff", "--no-edit", "controller-upgrade/visual-gate")
        merge = self.git("rev-parse", "HEAD")
        return identity(
            default_sha=self.base,
            default_branch=self.canonical,
            base_branch=self.canonical,
            base_sha=self.base,
            head_branch="controller-upgrade/visual-gate",
            head_sha=head,
            merge_sha=merge,
            merge_tree=self.git("rev-parse", "HEAD^{tree}"),
        )

    def validate(self, current: PullIdentity) -> bytes:
        with mock.patch("scripts.ci.pr_gate.validate_controller_parity"), mock.patch(
            "scripts.ci.pr_gate.validate_loader_bootstrap_commit"
        ) as bootstrap:
            matrix = validate_controller_upgrade_tree(self.repository, current)
        bootstrap.assert_called_once_with(
            self.repository.resolve(),
            head_sha=current.merge_sha,
            contract_sha=current.base_sha,
        )
        return matrix

    def test_docs_and_controller_roots_use_old_loader_contract(self) -> None:
        current = self.controller_merge("docs/operations.md")
        self.assertEqual(self.matrix_bytes, self.validate(current))
        matrix = json.loads(self.matrix_bytes)
        loader = sorted({row["loader"] for row in matrix["artifacts"]})[0]
        loader_paths = frozenset({f"{loader}/build.gradle", f"{loader}/src/e2e"})
        self.assertTrue(_upgrade_path_allowed(f"{loader}/src/e2e/NewProbe.java", loader_paths))
        self.assertFalse(_upgrade_path_allowed(f"{loader}/src/main/Product.java", loader_paths))
        self.assertFalse(_upgrade_path_allowed(f"{loader}/build.gradle/nested", loader_paths))
        self.assertFalse(_upgrade_path_allowed(".github/CODEOWNERS/nested", loader_paths))

    def test_product_matrix_verification_shim_and_forbidden_paths_fail_closed(self) -> None:
        rejected = (
            "common/src/main/java/Product.java",
            "release/release-matrix.json",
            "gradle/verification-metadata.xml",
            "common/src/e2e/java/com/theplumteam/e2e/VanillaShim.java",
            ".gradle/injected.txt",
        )
        for path in rejected:
            with self.subTest(path=path):
                current = self.controller_merge(path)
                with mock.patch("scripts.ci.pr_gate.validate_controller_parity"):
                    with self.assertRaises(PrGateError):
                        validate_controller_upgrade_tree(self.repository, current)

    def test_added_symlinks_and_executable_blobs_fail_closed(self) -> None:
        for path, options in (
            ("scripts/ci/unsafe-link", {"symlink": True}),
            ("scripts/ci/unsafe-executable.py", {"executable": True}),
        ):
            with self.subTest(path=path):
                current = self.controller_merge(path, **options)
                with mock.patch("scripts.ci.pr_gate.validate_controller_parity"):
                    with self.assertRaisesRegex(PrGateError, "unsafe"):
                        validate_controller_upgrade_tree(self.repository, current)


class ResultAndWorkflowContractTests(unittest.TestCase):
    def test_contexts_are_fixed_and_result_is_source_head_bound(self) -> None:
        value = _result(
            identity(),
            {
                "build": GateResult("success", "accepted", 1, 2),
                "e2e": GateResult("pending", "waiting", 3, 4),
            },
        )
        self.assertEqual(HEAD, value["head_sha"])
        self.assertEqual("master", value["default_branch"])
        self.assertEqual("master", value["base_branch"])
        self.assertEqual("feature/ui", value["head_branch"])
        self.assertEqual("e" * 40, value["merge_tree"])
        self.assertEqual(CONTEXTS["build"], value["gates"]["build"]["context"])
        self.assertEqual(CONTEXTS["e2e"], value["gates"]["e2e"]["context"])

    def test_workflow_uses_protected_evaluator_and_fresh_status_only_app_writer(self) -> None:
        workflow = (REPO / ".github/workflows/handle-pr-gate-result.yml").read_text("utf-8")
        self.assertIn("workflow_run:", workflow)
        self.assertIn("issue_comment:", workflow)
        self.assertIn("- created\n      - edited\n      - deleted", workflow)
        self.assertIn("github.event.comment.user.login == 'AkaNebur'", workflow)
        self.assertIn("github.event.comment.author_association == 'MEMBER'", workflow)
        self.assertIn("types:\n      - requested\n      - in_progress\n      - completed", workflow)
        self.assertIn("permissions: {}", workflow)
        self.assertIn("validate", (REPO / "scripts/ci/pr_gate.py").read_text("utf-8"))
        publish = workflow.split("  publish:", 1)[1]
        self.assertIn("environment: pr-gate", publish)
        self.assertIn("contents: read", publish)
        self.assertIn("issues: read", publish)
        self.assertIn("pull-requests: read", publish)
        self.assertIn("ref: ${{ github.sha }}", publish)
        self.assertIn("persist-credentials: false", publish)
        self.assertNotIn("path: candidate", publish)
        for argument in (
            "--expected-default-branch",
            "--expected-base-branch",
            "--expected-head-branch",
            "--expected-merge-tree",
        ):
            self.assertIn(argument, publish)
        self.assertLess(publish.index("pr_gate.py reauthorize"), publish.index("Mint one status-only"))
        self.assertIn(
            "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
            publish,
        )
        self.assertIn("client-id: ${{ vars.PR_GATE_APP_CLIENT_ID }}", publish)
        self.assertIn("private-key: ${{ secrets.PR_GATE_APP_PRIVATE_KEY }}", publish)
        self.assertIn("permission-statuses: write", publish)
        self.assertEqual(4, publish.count('publish_status "Trusted PR /'))
        status_step = publish.split("Publish only the two fixed exact-head contexts", 1)[1]
        self.assertNotIn("github.token", status_step)
        self.assertIn("authorization_current", publish)
        self.assertIn(
            "github.event.workflow_run.event == 'pull_request_target'", workflow
        )
        self.assertNotIn("github.event.workflow_run.event == 'pull_request'", workflow)
        self.assertNotIn("\n  pull_request_target:", workflow)

    def test_codeowners_is_additional_control_plane_review_not_check_provenance(self) -> None:
        codeowners = (REPO / ".github/CODEOWNERS").read_text("utf-8")
        self.assertIn("/.github/ @AkaNebur", codeowners)
        self.assertIn("/scripts/ci/ @AkaNebur", codeowners)
        self.assertIn("/tests/ @AkaNebur", codeowners)
        for loader in ("fabric", "forge", "neoforge"):
            self.assertIn(f"/{loader}/src/e2e/ @AkaNebur", codeowners)


if __name__ == "__main__":
    unittest.main()
