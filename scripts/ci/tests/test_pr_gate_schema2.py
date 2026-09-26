"""The trusted PR gate evaluates a preparing schema-2 master as its schema-1 legacy gate.

Every case runs the protected tree policy against real Git commits, once on the frozen
pre-enrollment schema-1 matrix and once on each preparing schema-2 matrix. The loader
bootstrap check is unchanged by the schema-2 projection and keeps its own tests.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from scripts.ci.e2e_fanin import aggregate_artifact_name
from scripts.ci.e2e_job_graph import expected_jobs
from scripts.ci.gate_controller import GateControllerError, PROTECTED_PATHS, validate_controller_parity
from scripts.ci.pr_gate import (
    CONTEXTS,
    CONTROLLER_ANCHOR_WORKFLOW,
    CONTROLLER_UPGRADE_DIRECTORY_ROOTS,
    CONTROLLER_UPGRADE_REQUIRED,
    EXACT_BASE_OWNED_PATHS,
    WORKFLOWS,
    PrGateError,
    PullIdentity,
    UpgradeAuthorization,
    evaluate,
    validate_controller_upgrade_tree,
    validate_pr_tree,
)
from scripts.ci.tests.matrix_fixtures import SCHEMA1_MATRIX_PATH, schema2_configuration
from scripts.release.matrix import (
    LEGACY_TARGET_NODES,
    MAX_MATRIX_BYTES,
    MatrixError,
    load_matrix_bytes,
    load_trusted_gate_matrix_bytes,
    normalize_matrix_inventory,
)

REPO = Path(__file__).resolve().parents[3]
SCHEMA1 = SCHEMA1_MATRIX_PATH.read_bytes()
PREPARING = {
    "master": (REPO / "release/release-matrix.json").read_bytes(),
    "fixture": json.dumps(schema2_configuration(), indent=2).encode(),
}
REPOSITORY_NAME = "The-Plum-Team/Block-Pops-Minecraft-Mod"
BOOTSTRAPS = ("scripts.ci.gate_controller.validate_loader_bootstrap_commit",
              "scripts.ci.pr_gate.validate_loader_bootstrap_commit")
# The loader controllers the schema-1 gate protected: exactly the two 1.20.1 lanes' loaders.
LOADER_CONTROLLERS = ("fabric/build.gradle", "fabric/src/e2e", "forge/build.gradle", "forge/src/e2e")


def lane_identities(matrix: dict[str, Any]) -> list[tuple[str, str, str]]:
    return sorted((row["artifact_node"], row["loader"], row["minecraft"]) for row in matrix["artifacts"])


class GateRepository:
    """A protected controller tree whose only variable is the committed release matrix."""

    def __init__(self, root: Path, matrix: bytes) -> None:
        self.root = root
        self.git("init", "-q", "-b", "master")
        self.git("config", "user.name", "Tests")
        self.git("config", "user.email", "tests@invalid.test")
        files = {f"{path}/placeholder.txt" if path in CONTROLLER_UPGRADE_DIRECTORY_ROOTS else path
                 for path in PROTECTED_PATHS}
        files |= set(EXACT_BASE_OWNED_PATHS) | set(CONTROLLER_UPGRADE_REQUIRED) | {"docs/operations.md"}
        files |= {f"{loader}/{path}" for loader in ("fabric", "forge", "neoforge")
                  for path in ("build.gradle", "src/e2e/Bootstrap.java", "src/main/Product.java")}
        for relative in sorted(files):
            self.write(relative, f"protected {relative}\n")
        (root / "release/release-matrix.json").write_bytes(matrix)
        self.git("add", ".")
        self.git("commit", "-qm", "protected default branch")
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(["git", "-C", str(self.root), *arguments], text=True).strip()

    def write(self, relative: str, content: str) -> None:
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def pull(self, changes: dict[str, str], *, branch: str = "feature/ui") -> PullIdentity:
        self.git("switch", "-qC", branch, self.base)
        for relative, content in changes.items():
            self.write(relative, content)
        self.git("add", "-A")
        self.git("commit", "-qm", "candidate")
        head = self.git("rev-parse", "HEAD")
        tree = self.git("rev-parse", "HEAD^{tree}")
        merge = self.git("commit-tree", tree, "-p", self.base, "-p", head, "-m", "synthetic merge")
        self.git("checkout", "-qf", merge)
        return PullIdentity(10, "master", self.base, "master", self.base, branch, head, merge, tree)


class FakeGitHub:
    """Successful newest exact runs whose job records follow the schema-1 legacy graph."""

    repository = REPOSITORY_NAME

    def __init__(self, identity: PullIdentity, graphs: dict[str, tuple[Any, ...]], labels: list[str]) -> None:
        self.identity, self.graphs, self.labels = identity, graphs, labels
        self.run_ids = {"build": 51, "e2e": 52}

    def pull(self, number: int) -> dict[str, Any]:
        return {"number": number, "labels": [{"name": label} for label in self.labels]}

    def workflow_runs(self, workflow: str) -> list[dict[str, Any]]:
        kind = next(key for key, value in WORKFLOWS.items() if value == workflow)
        return [{
            "id": self.run_ids[kind], "run_attempt": 1, "status": "completed", "conclusion": "success",
            "created_at": "2026-09-26T10:00:00Z", "event": "pull_request_target",
            "path": f".github/workflows/{workflow}", "head_branch": self.identity.head_branch,
            "head_sha": self.identity.head_sha, "repository": {"full_name": REPOSITORY_NAME},
            "head_repository": {"full_name": REPOSITORY_NAME}, "pull_requests": [{"number": 10}],
            "referenced_workflows": [{
                "path": f"{REPOSITORY_NAME}/{CONTROLLER_ANCHOR_WORKFLOW}@{self.identity.default_sha}",
                "ref": f"refs/heads/{self.identity.default_branch}", "sha": self.identity.default_sha,
            }],
        }]

    def jobs(self, run_id: int) -> list[dict[str, Any]]:
        kind = next(key for key, value in self.run_ids.items() if value == run_id)
        return [{"id": run_id * 100 + index, "name": job.name, "run_attempt": 1, "status": "completed",
                 "conclusion": job.conclusion} for index, job in enumerate(self.graphs[kind])]

    def artifacts(self, run_id: int) -> list[dict[str, Any]]:
        merge = self.identity.merge_sha
        name = (f"staged-release-bundle-{merge}-1" if run_id == self.run_ids["build"]
                else aggregate_artifact_name(merge, 1))
        return [{"id": run_id + 1000, "name": name, "workflow_run": {"id": run_id}, "size_in_bytes": 4096,
                 "digest": "sha256:" + "9" * 64, "expired": False}]


class TrustedGateSchema2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.count = 0

    def repository(self, matrix: bytes) -> GateRepository:
        self.count += 1
        root = Path(self.temporary.name) / f"repository-{self.count}"
        root.mkdir()
        return GateRepository(root, matrix)

    def graphs(self, matrix: bytes) -> dict[str, tuple[Any, ...]]:
        self.count += 1
        path = Path(self.temporary.name) / f"matrix-{self.count}.json"
        path.write_bytes(matrix)
        return {kind: expected_jobs(path, workflow, event="pull_request_target", source_branch="master")
                for kind, workflow in WORKFLOWS.items()}

    def test_preparing_projection_is_exactly_the_schema1_legacy_gate(self) -> None:
        schema1 = load_trusted_gate_matrix_bytes(SCHEMA1)
        self.assertEqual(load_matrix_bytes(SCHEMA1)["artifacts"], schema1["artifacts"])
        self.assertEqual(sorted(LEGACY_TARGET_NODES), [node for node, _, _ in lane_identities(schema1)])
        graphs = self.graphs(SCHEMA1)
        self.assertEqual(2, sum(job.name.endswith(" - contract scenarios") for job in graphs["e2e"]))
        for label, raw in PREPARING.items():
            with self.subTest(matrix=label):
                view = load_trusted_gate_matrix_bytes(raw)
                self.assertEqual(schema1["branch"], view["branch"])
                self.assertEqual(lane_identities(schema1), lane_identities(view))
                self.assertEqual(sorted(LEGACY_TARGET_NODES), sorted(row["artifact_node"] for row in view["runtimes"]))
                self.assertEqual(graphs, self.graphs(raw))
                # The projection activates nothing else: schema 2 stays inventory only.
                self.assertFalse(normalize_matrix_inventory(json.loads(raw)).execution_supported)
                with self.assertRaisesRegex(MatrixError, "inventory only"):
                    load_matrix_bytes(raw)

    def test_shared_unknown_mode_release_role_and_malformed_matrices_fail_closed(self) -> None:
        def mutated(mutate) -> bytes:
            matrix = schema2_configuration()
            mutate(matrix)
            return json.dumps(matrix).encode()

        cases = {
            "shared mode": json.dumps(schema2_configuration(shared=True)).encode(),
            "unknown mode": mutated(lambda matrix: matrix["migration"].update(mode="ready")),
            "missing migration": mutated(lambda matrix: matrix.pop("migration")),
            "one legacy node": mutated(lambda matrix: matrix["migration"]["legacy_nodes"].pop()),
            "unknown schema": mutated(lambda matrix: matrix.update(schema_version=3)),
            "release branch": mutated(lambda matrix: matrix.update(branch={
                "role": "release", "name": "1.20.1", "canonical": "master",
                "sync": {"enabled": True, "source": "master"}})),
            "artifact rows object": mutated(lambda matrix: matrix.update(artifacts={})),
            "not JSON": b"{",
            "empty": b"",
            "array": b"[]",
            "duplicate key": b'{"schema_version":2,"schema_version":2}',
            "non-finite": b'{"schema_version":NaN}',
            "oversized": b" " * (MAX_MATRIX_BYTES + 1),
        }
        for label, raw in cases.items():
            with self.subTest(matrix=label), self.assertRaises(MatrixError):
                load_trusted_gate_matrix_bytes(raw)
        with self.assertRaisesRegex(MatrixError, "'shared' mode"):
            load_trusted_gate_matrix_bytes(cases["shared mode"])

    def assert_ordinary_pr_matches_schema1(self, matrix: bytes) -> None:
        repository = self.repository(matrix)
        current = repository.pull({"product.txt": "candidate\n", "neoforge/src/main/Product.java": "x\n"})
        protected: list[tuple[str, ...]] = []

        def parity(*arguments: Any, **keywords: Any) -> tuple[str, ...]:
            protected.append(validate_controller_parity(*arguments, **keywords))
            return protected[-1]

        with mock.patch(BOOTSTRAPS[0]) as bootstrap, mock.patch(
                "scripts.ci.pr_gate.validate_controller_parity", side_effect=parity):
            self.assertEqual(matrix, validate_pr_tree(repository.root, current))
        self.assertEqual(2, bootstrap.call_count)
        self.assertEqual([(*PROTECTED_PATHS, *LOADER_CONTROLLERS)] * 2, protected)
        self.assertEqual(self.graphs(SCHEMA1), self.graphs(matrix))
        refused = repository.pull({"forge/src/e2e/Bootstrap.java": "candidate\n"}, branch="feature/e2e")
        with mock.patch(BOOTSTRAPS[0]), self.assertRaisesRegex(GateControllerError, "forge/src/e2e/Bootstrap.java"):
            validate_pr_tree(repository.root, refused)

    def test_ordinary_pr_on_the_schema1_master(self) -> None:
        self.assert_ordinary_pr_matches_schema1(SCHEMA1)

    def test_ordinary_pr_on_the_preparing_master(self) -> None:
        self.assert_ordinary_pr_matches_schema1(PREPARING["master"])

    def test_ordinary_pr_on_a_preparing_fixture(self) -> None:
        self.assert_ordinary_pr_matches_schema1(PREPARING["fixture"])

    def assert_controller_upgrade_matches_schema1(self, matrix: bytes) -> None:
        repository = self.repository(matrix)
        current = repository.pull({"docs/operations.md": "upgraded\n", "scripts/ci/new_probe.py": "probe\n",
                                   "forge/src/e2e/Bootstrap.java": "upgraded\n", "fabric/build.gradle": "upgraded\n"},
                                  branch="controller-upgrade/schema2-gate")
        with mock.patch(BOOTSTRAPS[0]), mock.patch(BOOTSTRAPS[1]) as bootstrap:
            self.assertEqual(matrix, validate_controller_upgrade_tree(repository.root, current))
        bootstrap.assert_called_once_with(repository.root.resolve(), head_sha=current.merge_sha,
                                          contract_sha=current.base_sha)
        for path, reason in (("neoforge/src/e2e/Bootstrap.java", "non-controller path"),
                             ("release/release-matrix.json", "base-owned")):
            refused = repository.pull({path: "upgraded\n"}, branch="controller-upgrade/refused")
            with self.subTest(path=path), mock.patch(BOOTSTRAPS[0]), mock.patch(BOOTSTRAPS[1]), \
                    self.assertRaisesRegex(PrGateError, reason):
                validate_controller_upgrade_tree(repository.root, refused)

    def test_controller_upgrade_on_the_schema1_master(self) -> None:
        self.assert_controller_upgrade_matches_schema1(SCHEMA1)

    def test_controller_upgrade_on_the_preparing_master(self) -> None:
        self.assert_controller_upgrade_matches_schema1(PREPARING["master"])

    def test_controller_upgrade_on_a_preparing_fixture(self) -> None:
        self.assert_controller_upgrade_matches_schema1(PREPARING["fixture"])

    def evaluate(self, matrix: bytes, branch: str) -> dict[str, Any]:
        repository = self.repository(matrix)
        current = repository.pull({"docs/operations.md": "changed\n"}, branch=branch)
        labels = ["controller-upgrade"] if branch.startswith("controller-upgrade/") else []
        api = FakeGitHub(current, self.graphs(SCHEMA1), labels)
        authorization = UpgradeAuthorization(91, "2026-09-26T10:00:00Z", current.head_sha, "7" * 64)
        with mock.patch("scripts.ci.pr_gate.resolve_pull_identity", return_value=current), \
                mock.patch("scripts.ci.pr_gate.controller_upgrade_authorization", return_value=authorization), \
                mock.patch(BOOTSTRAPS[0]), mock.patch(BOOTSTRAPS[1]):
            result = evaluate(api, repository=repository.root, implementation_sha=current.default_sha,
                              expected_pr_number=10, expected_merge_sha=current.merge_sha, pr_number=10)
        self.assertEqual("controller-upgrade" if labels else "ordinary", result["policy_mode"])
        self.assertEqual(CONTEXTS, {kind: gate["context"] for kind, gate in result["gates"].items()})
        return result

    def assert_complete_evaluation_accepts_schema1_evidence(self, matrix: bytes) -> None:
        for branch in ("feature/ui", "controller-upgrade/schema2-gate"):
            with self.subTest(branch=branch):
                result = self.evaluate(matrix, branch)
                self.assertEqual({"build": "success", "e2e": "success"},
                                 {kind: gate["state"] for kind, gate in result["gates"].items()})

    def test_complete_evaluation_of_the_preparing_master(self) -> None:
        self.assert_complete_evaluation_accepts_schema1_evidence(PREPARING["master"])

    def test_complete_evaluation_of_a_preparing_fixture(self) -> None:
        self.assert_complete_evaluation_accepts_schema1_evidence(PREPARING["fixture"])

    def test_complete_evaluation_refuses_shared_mode_as_policy(self) -> None:
        result = self.evaluate(json.dumps(schema2_configuration(shared=True)).encode(), "feature/ui")
        for gate in result["gates"].values():
            self.assertEqual(("failure", "Ordinary PR changed protected branch policy", 0),
                             (gate["state"], gate["description"], gate["run_id"]))


if __name__ == "__main__":
    unittest.main()
