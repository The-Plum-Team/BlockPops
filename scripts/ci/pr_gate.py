#!/usr/bin/env python3
"""Evaluate protected ``pull_request_target`` gates from default-branch policy.

Candidate Build/E2E workflows are deliberately treated only as evidence producers.  This
controller runs from the protected default branch, authenticates the current pull request and its
synthetic merge, requires branch-portable controller parity, and selects the newest exact run and
attempt for both deterministic gates.  It never writes to GitHub; a separate App-only job consumes
its bounded outputs and publishes the two trusted commit-status contexts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from scripts.ci.e2e_fanin import aggregate_artifact_name  # noqa: E402
from scripts.ci.e2e_job_graph import (  # noqa: E402
    JobGraphError,
    expected_jobs,
    validate_jobs,
)
from scripts.ci.gate_controller import (  # noqa: E402
    FORBIDDEN_PATHS,
    GateControllerError,
    PROTECTED_PATHS,
    VERSION_SPECIFIC_PATHS,
    validate_controller_parity,
)
from scripts.ci.loader_bootstrap import (  # noqa: E402
    CONTRACT_PATH as BOOTSTRAP_CONTRACT_PATH,
    MAX_CONTRACT_BYTES,
    LoaderBootstrapError,
    load_contract_bytes as load_loader_bootstrap_contract,
    validate_commit as validate_loader_bootstrap_commit,
    validate_transition as validate_loader_bootstrap_transition,
)
from scripts.release.matrix import (  # noqa: E402
    MatrixError,
    load_matrix_bytes,
    load_trusted_gate_matrix_bytes,
    valid_branch_name,
)

SCHEMA_VERSION = 1
WORKFLOWS = {
    "build": "build-gate.yml",
    "e2e": "on-demand-e2e.yml",
}
CONTEXTS = {
    "build": "Trusted PR / Build and verify",
    "e2e": "Trusted PR / Packaged E2E gate",
}
# GitHub records a ``pull_request_target`` run under the pull request's head branch and head
# commit, never the controller that ran it. GitHub runs that workflow from the default branch at
# event time, whatever the PR's base, and resolves its repository-local ``uses:`` there. Both
# gates call this reusable workflow that way, so each run's ``referenced_workflows`` records the
# exact default commit (path suffix, ``ref`` and ``sha``). That entry is how a gate run names its
# controller; a remote reference such as ``…@master`` names a branch, not a commit, and never
# matches.
CONTROLLER_ANCHOR_WORKFLOW = ".github/workflows/verify-gate-attestation.yml"
MATRIX_PATH = "release/release-matrix.json"
VERIFICATION_PATH = "gradle/verification-metadata.xml"
EXACT_BASE_OWNED_PATHS = (
    MATRIX_PATH,
    VERIFICATION_PATH,
    *sorted(VERSION_SPECIFIC_PATHS),
)
CONTROLLER_UPGRADE_LABEL = "controller-upgrade"
CONTROLLER_UPGRADE_BRANCH_PREFIX = "controller-upgrade/"
CONTROLLER_UPGRADE_OWNER = "AkaNebur"
# The repository moved from AkaNebur's account to the The-Plum-Team organization.
# The owner of record is now the organization, while the person whose decisions
# authorize an upgrade is still AkaNebur, an administrator of it, whom GitHub
# reports on their comments as a MEMBER of the organization rather than an OWNER.
REPOSITORY_OWNER = {"login": "The-Plum-Team", "type": "Organization"}
CONTROLLER_UPGRADE_ASSOCIATION = "MEMBER"
CONTROLLER_UPGRADE_COMMAND = re.compile(
    r"^/controller-upgrade (?P<decision>approve|revoke) (?P<head>[0-9a-f]{40})$"
)
CONTROLLER_UPGRADE_DIRECTORY_ROOTS = frozenset(
    {
        ".github/actions",
        ".github/workflows",
        "e2e",
        "gradle/wrapper",
        "scripts/ci",
        "scripts/lib",
        "scripts/pages",
        "scripts/release",
        "scripts/visual",
        "site",
        "tests",
        "common/src/e2e",
    }
)
CONTROLLER_UPGRADE_FILE_ROOTS = frozenset(PROTECTED_PATHS) - CONTROLLER_UPGRADE_DIRECTORY_ROOTS
CONTROLLER_UPGRADE_DOCS = frozenset({"README.md", "CONTRIBUTING.md"})
CONTROLLER_UPGRADE_REQUIRED = frozenset(
    {
        ".github/workflows/build-gate.yml",
        ".github/workflows/handle-pr-gate-result.yml",
        ".github/workflows/on-demand-e2e.yml",
        "scripts/ci/e2e_job_graph.py",
        "scripts/ci/gate_controller.py",
        "scripts/ci/pr_gate.py",
        "scripts/release/matrix.py",
    }
)
MAX_CONTROLLER_UPGRADE_PATHS = 300
# Inert until a separately deployed evaluator authenticates deployment and runtime decisions.
# These are exact files, never directory grants or paths supplied by a candidate controller.
RESTRICTED_TRANSITION_GENERATION = 1
RESTRICTED_TRANSITION_SCOPES = {
    "matrix": ("release/release-matrix.json",),
    "verification": ("gradle/verification-metadata.xml",),
    "vanilla-shim": ("common/src/e2e/java/com/theplumteam/e2e/VanillaShim.java",),
    "datapack-metadata": ("e2e/server-template/datapack/pack.mcmeta",),
    "stonecutter-bootstrap": (
        "settings.gradle", "build.gradle", "gradle/build-conventions.gradle",
        "gradle/stonecutter-branch.gradle", "stonecutter.gradle", "gradle/repository-policy.gradle",
    ),
    "fabric-contract": ("e2e/loader-bootstrap-contract.json",),
    "forge-contract": ("e2e/loader-bootstrap-contract.json",),
    "neoforge-contract": ("e2e/loader-bootstrap-contract.json",),
    "fabric-next": (
        "e2e/loader-bootstrap-contract.json", "fabric/build.gradle",
        "fabric/src/e2e/java/com/theplumteam/e2e/fabric/BlockPopsE2EFabric.java",
        "fabric/src/e2e/resources/fabric.mod.json",
    ),
    "forge-next": (
        "e2e/loader-bootstrap-contract.json", "forge/build.gradle",
        "forge/src/e2e/java/com/theplumteam/e2e/forge/BlockPopsE2EForge.java",
        "forge/src/e2e/resources/META-INF/mods.toml",
    ),
    "neoforge-next": (
        "e2e/loader-bootstrap-contract.json", "neoforge/build.gradle",
        "neoforge/src/e2e/java/com/theplumteam/e2e/neoforge/BlockPopsE2ENeoForge.java",
        "neoforge/src/e2e/resources/META-INF/neoforge.mods.toml",
    ),
}
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA256_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
MAX_API_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 1000
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
RUN_STATUSES = frozenset(
    {"queued", "in_progress", "completed", "pending", "waiting", "requested"}
)
RUN_CONCLUSIONS = frozenset(
    {
        "success",
        "failure",
        "cancelled",
        "timed_out",
        "action_required",
        "neutral",
        "skipped",
        "stale",
        "startup_failure",
    }
)


class PrGateError(ValueError):
    """Trusted PR evidence is malformed, stale, mixed, or incomplete."""


class NotEligible(PrGateError):
    """The wake belongs to no still-current ordinary same-repository PR."""


def _fail(message: str) -> None:
    raise PrGateError(message)


def _positive(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _fail(f"{label} must be a positive integer")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA1.fullmatch(value) is None:
        _fail(f"{label} must be one lowercase SHA-1")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(f"{label} must be a UTC RFC3339 timestamp")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PrGateError(f"{label} is invalid") from exc


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, request: Any, fp: Any, code: int, message: str, headers: Any, newurl: str
    ) -> None:
        return None


class GitHubApi:
    """Small read-only GitHub API surface used by the secretless evaluator."""

    def __init__(self, *, repository: str, token: str, api_url: str) -> None:
        if not isinstance(repository, str) or REPOSITORY.fullmatch(repository) is None:
            _fail("repository must use safe owner/name form")
        if not token or len(token) > 4096:
            _fail("GITHUB_TOKEN is absent or invalid")
        parsed = urllib.parse.urlsplit(api_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            _fail("GitHub API URL must be an HTTPS origin")
        self.repository = repository
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def _route(self, suffix: str) -> str:
        owner, name = self.repository.split("/", 1)
        return (
            f"/repos/{urllib.parse.quote(owner, safe='')}/"
            f"{urllib.parse.quote(name, safe='')}{suffix}"
        )

    def json(self, suffix: str, *, label: str) -> Any:
        request = urllib.request.Request(
            self.api_url + self._route(suffix),
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "BlockPops-protected-pr-gate/1",
            },
        )
        try:
            with self.opener.open(request, timeout=60) as response:
                if response.status != 200:
                    _fail(f"{label} API returned HTTP {response.status}")
                payload = response.read(MAX_API_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise PrGateError(f"{label} API returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise PrGateError(f"{label} API transport failed: {exc.reason}") from exc
        if not 1 <= len(payload) <= MAX_API_BYTES:
            _fail(f"{label} API response is empty or oversized")
        try:
            return json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_reject_duplicates,
                parse_constant=_reject_nonfinite,
            )
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise PrGateError(f"{label} API response is not strict JSON: {exc}") from exc

    def pages(self, suffix: str, *, key: str, label: str) -> list[dict[str, Any]]:
        separator = "&" if "?" in suffix else "?"
        records: list[dict[str, Any]] = []
        for page in range(1, 11):
            value = self.json(
                f"{suffix}{separator}per_page=100&page={page}", label=f"{label} page {page}"
            )
            if not isinstance(value, dict) or not isinstance(value.get(key), list):
                _fail(f"{label} API page has an invalid shape")
            batch = value[key]
            if any(not isinstance(item, dict) for item in batch):
                _fail(f"{label} API page contains a non-object record")
            records.extend(batch)
            if len(records) > MAX_RECORDS:
                _fail(f"{label} API response exceeds {MAX_RECORDS} records")
            if len(batch) < 100:
                return records
        _fail(f"{label} API pagination exceeds ten pages")

    def array_pages(self, suffix: str, *, label: str) -> list[dict[str, Any]]:
        separator = "&" if "?" in suffix else "?"
        records: list[dict[str, Any]] = []
        for page in range(1, 11):
            value = self.json(
                f"{suffix}{separator}per_page=100&page={page}", label=f"{label} page {page}"
            )
            if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
                _fail(f"{label} API page has an invalid shape")
            records.extend(value)
            if len(records) > MAX_RECORDS:
                _fail(f"{label} API response exceeds {MAX_RECORDS} records")
            if len(value) < 100:
                return records
        _fail(f"{label} API pagination exceeds ten pages")

    def repository_record(self) -> dict[str, Any]:
        value = self.json("", label="repository")
        if not isinstance(value, dict):
            _fail("repository API record is not an object")
        return value

    def run(self, run_id: int) -> dict[str, Any]:
        value = self.json(f"/actions/runs/{_positive(run_id, 'run id')}", label="run")
        if not isinstance(value, dict):
            _fail("workflow run API record is not an object")
        return value

    def pull(self, number: int) -> dict[str, Any]:
        value = self.json(f"/pulls/{_positive(number, 'pull request number')}", label="pull")
        if not isinstance(value, dict):
            _fail("pull request API record is not an object")
        return value

    def issue_comments(self, number: int) -> list[dict[str, Any]]:
        return self.array_pages(
            f"/issues/{_positive(number, 'pull request number')}/comments",
            label="pull request issue comments",
        )

    def issue_comment(self, comment_id: int) -> dict[str, Any]:
        value = self.json(f"/issues/comments/{_positive(comment_id, 'issue comment id')}",
                          label="pull request issue comment")
        if not isinstance(value, dict):
            _fail("issue comment API record is not an object")
        return value

    def branch_sha(self, branch: str) -> str:
        if not valid_branch_name(branch):
            _fail("branch identity is unsafe")
        value = self.json(
            f"/branches/{urllib.parse.quote(branch, safe='')}", label="branch"
        )
        try:
            return _sha(value["commit"]["sha"], "branch SHA")
        except (KeyError, TypeError) as exc:
            raise PrGateError("branch API record is malformed") from exc

    def commit_identity(self, commit: str) -> tuple[str, tuple[str, ...]]:
        value = self.json(f"/git/commits/{_sha(commit, 'commit')}", label="commit")
        try:
            if value["sha"] != commit:
                _fail("commit API returned a different object")
            parents = value["parents"]
            if not isinstance(parents, list) or len(parents) > 16:
                _fail("commit parent inventory is invalid")
            parent_shas = tuple(
                _sha(item["sha"], "commit parent") for item in parents if isinstance(item, dict)
            )
            if len(parent_shas) != len(parents) or len(set(parent_shas)) != len(parent_shas):
                _fail("commit parent inventory is malformed or duplicated")
            return _sha(value["tree"]["sha"], "commit tree"), parent_shas
        except (KeyError, TypeError) as exc:
            raise PrGateError("commit API record is malformed") from exc

    def workflow_runs(self, workflow: str) -> list[dict[str, Any]]:
        encoded = urllib.parse.quote(workflow, safe="")
        return self.pages(
            f"/actions/workflows/{encoded}/runs?event=pull_request_target",
            key="workflow_runs",
            label=f"{workflow} runs",
        )

    def jobs(self, run_id: int) -> list[dict[str, Any]]:
        return self.pages(
            f"/actions/runs/{_positive(run_id, 'run id')}/jobs?filter=all",
            key="jobs",
            label="workflow jobs",
        )

    def artifacts(self, run_id: int) -> list[dict[str, Any]]:
        return self.pages(
            f"/actions/runs/{_positive(run_id, 'run id')}/artifacts",
            key="artifacts",
            label="workflow artifacts",
        )


@dataclass(frozen=True)
class PullIdentity:
    number: int
    default_branch: str
    default_sha: str
    base_branch: str
    base_sha: str
    head_branch: str
    head_sha: str
    merge_sha: str
    merge_tree: str


@dataclass(frozen=True)
class RestrictedTransition:
    schema_version: int
    controller_generation: int
    controller_sha: str
    base_sha: str
    head_sha: str
    scope: str
    paths: tuple[str, ...]

    @property
    def digest(self) -> str:
        canonical = json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()


def parse_restricted_transition(
    raw: bytes, *, identity: PullIdentity, deployed_controller_sha: str, deployed_generation: int
) -> RestrictedTransition:
    """Validate an inert proposal against independently authenticated deployment/PR state.

    The caller must obtain deployment, generation and identity from protected repository state,
    never this declaration or candidate code. This does not authenticate an owner, inspect a
    tree, validate bootstrap phases/evidence, admit a candidate, or authorize initial deployment.
    """
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 8192:
        _fail("restricted transition declaration must be bounded JSON bytes")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except (ValueError, RecursionError) as exc:
        raise PrGateError("restricted transition declaration is malformed") from exc
    fields = {
        "schema_version", "controller_generation", "controller_sha", "base_sha",
        "head_sha", "scope", "paths",
    }
    if not isinstance(value, dict) or set(value) != fields:
        _fail("restricted transition declaration has missing or extra fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        _fail("unsupported restricted transition schema")
    if (
        type(deployed_generation) is not int
        or deployed_generation != RESTRICTED_TRANSITION_GENERATION
        or type(value["controller_generation"]) is not int
        or value["controller_generation"] != deployed_generation
    ):
        _fail("unsupported or undeployed restricted transition controller generation")
    controller = _sha(deployed_controller_sha, "deployed controller SHA")
    if (
        identity.default_branch != identity.base_branch
        or controller != identity.default_sha or controller != identity.base_sha
    ):
        _fail("restricted transition requires the exact deployed default branch base")
    for field, expected in (
        ("controller_sha", controller), ("base_sha", identity.base_sha), ("head_sha", identity.head_sha),
    ):
        if _sha(value[field], field) != _sha(expected, f"authenticated {field}"):
            _fail(f"restricted transition {field} disagrees with authenticated state")
    if value["head_sha"] == controller:
        _fail("restricted transition requires a distinct candidate head")
    scope, paths = value["scope"], value["paths"]
    if not isinstance(scope, str) or scope not in RESTRICTED_TRANSITION_SCOPES:
        _fail("unknown restricted transition scope")
    if (
        not isinstance(paths, list) or not paths
        or any(not isinstance(path, str) for path in paths)
        or len(set(paths)) != len(paths) or paths != sorted(paths)
        or any(path not in RESTRICTED_TRANSITION_SCOPES[scope] for path in paths)
    ):
        _fail("restricted transition paths must be sorted unique exact files in the static scope")
    return RestrictedTransition(**{**value, "paths": tuple(paths)})


def bind_restricted_transition_decision(
    transition: RestrictedTransition, *, repository: str, pull_number: int,
    authenticated_owner_decision: dict[str, Any],
) -> str:
    """Return an audit digest, not admission, for a separately authenticated current decision.

    The caller supplies the parsed transition, fetches/authenticates the latest existing owner
    decision, and rechecks it after evidence selection. Candidate documents and ordinary
    controller-upgrade comments are not this authority. This pure binder cannot detect deleted,
    edited, stale or spoofed API records.
    """
    if not isinstance(repository, str) or REPOSITORY.fullmatch(repository) is None:
        _fail("restricted transition repository is invalid")
    expected = {
        "schema_version": 1, "purpose": "restricted-transition-owner-authorization",
        "repository": repository, "pull_request": _positive(pull_number, "pull request number"),
        "owner": CONTROLLER_UPGRADE_OWNER, "decision": "approve",
        "controller_generation": transition.controller_generation,
        "controller_sha": transition.controller_sha, "base_sha": transition.base_sha,
        "head_sha": transition.head_sha, "declaration_sha256": transition.digest,
        "comment_body": (f"/restricted-transition approve {transition.controller_generation} "
                         f"{transition.head_sha} {transition.digest}"),
    }
    decision = authenticated_owner_decision
    if (
        not isinstance(decision, dict)
        or set(decision) != set(expected) | {"comment_id", "comment_created_at", "comment_updated_at"}
        or any(
            type(decision[key]) is not type(value) or decision[key] != value
            for key, value in expected.items()
        )
    ):
        _fail("restricted transition owner decision disagrees with its exact declaration and identity")
    _positive(decision["comment_id"], "owner decision comment id")
    _timestamp(decision["comment_created_at"], "owner decision created_at")
    _timestamp(decision["comment_updated_at"], "owner decision updated_at")
    if decision["comment_created_at"] != decision["comment_updated_at"]:
        _fail("restricted transition owner decision was edited")
    canonical = json.dumps(decision, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class UpgradeAuthorization:
    comment_id: int
    comment_updated_at: str
    head_sha: str
    digest: str


@dataclass(frozen=True)
class SelectedRun:
    run_id: int
    run_attempt: int
    status: str
    conclusion: str | None
    created_at: str


@dataclass(frozen=True)
class GateResult:
    state: str
    description: str
    run_id: int
    run_attempt: int


def _run_pull_number(value: Any, label: str) -> int:
    pulls = value.get("pull_requests") if isinstance(value, dict) else None
    if not isinstance(pulls, list) or len(pulls) != 1 or not isinstance(pulls[0], dict):
        _fail(f"{label} must identify exactly one pull request")
    return _positive(pulls[0].get("number"), f"{label} pull request number")


def _authenticate_trigger(api: GitHubApi, trigger_run_id: int) -> tuple[dict[str, Any], int]:
    run = api.run(trigger_run_id)
    if _positive(run.get("id"), "trigger API run id") != trigger_run_id:
        _fail("trigger run id disagrees with the API record")
    if run.get("event") != "pull_request_target":
        raise NotEligible("source run is not a pull_request_target gate")
    if run.get("path") not in {f".github/workflows/{item}" for item in WORKFLOWS.values()}:
        raise NotEligible("source run is not a deterministic PR gate")
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    if (
        not isinstance(repository, dict)
        or repository.get("full_name") != api.repository
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != api.repository
    ):
        raise NotEligible("source run is not a same-repository PR gate")
    _sha(run.get("head_sha"), "trigger controller head")
    if not valid_branch_name(run.get("head_branch")):
        _fail("trigger controller branch is unsafe")
    _positive(run.get("run_attempt"), "trigger run attempt")
    status = run.get("status")
    conclusion = run.get("conclusion")
    if status not in RUN_STATUSES:
        _fail("trigger run has an invalid status")
    if status == "completed":
        if conclusion not in RUN_CONCLUSIONS:
            _fail("completed trigger run has an invalid conclusion")
    elif conclusion is not None:
        _fail("incomplete trigger run unexpectedly has a conclusion")
    _timestamp(run.get("created_at"), "trigger run created_at")
    return run, _run_pull_number(run, "trigger run")


def runs_default_controller(
    run: dict[str, Any], *, repository: str, default_branch: str, default_sha: str
) -> bool:
    """Whether GitHub records ``run`` as executing the exact default-branch controller."""

    references = run.get("referenced_workflows")
    if not isinstance(references, list):
        return False
    path = f"{repository}/{CONTROLLER_ANCHOR_WORKFLOW}@"
    anchors = [
        value for value in references
        if isinstance(value, dict)
        and isinstance(value.get("path"), str)
        and value["path"].startswith(path)
    ]
    return (
        len(anchors) == 1
        and anchors[0].get("path") == path + default_sha
        and anchors[0].get("ref") == f"refs/heads/{default_branch}"
        and anchors[0].get("sha") == default_sha
    )


def resolve_pull_identity(
    api: GitHubApi,
    *,
    implementation_sha: str,
    trigger_run_id: int | None = None,
    pr_number: int | None = None,
) -> PullIdentity:
    implementation_sha = _sha(implementation_sha, "protected implementation SHA")
    if (trigger_run_id is None) == (pr_number is None):
        _fail("exactly one trusted run or pull request locator is required")
    trigger: dict[str, Any] | None = None
    if trigger_run_id is not None:
        trigger, number = _authenticate_trigger(api, _positive(trigger_run_id, "trigger run id"))
    else:
        number = _positive(pr_number, "pull request number")
    repository = api.repository_record()
    if repository.get("full_name") != api.repository:
        _fail("repository API identity changed")
    default_branch = repository.get("default_branch")
    if not valid_branch_name(default_branch):
        _fail("repository default branch is unsafe")
    default_sha = api.branch_sha(default_branch)
    if default_sha != implementation_sha:
        raise NotEligible("protected default branch advanced during PR evaluation")
    if trigger is not None and not runs_default_controller(
        trigger, repository=api.repository, default_branch=default_branch, default_sha=default_sha
    ):
        raise NotEligible("trigger run is not from the exact current default controller")

    pull = api.pull(number)
    try:
        if _positive(pull["number"], "pull request API number") != number:
            _fail("pull request API number changed")
        if pull["state"] != "open":
            raise NotEligible("pull request is no longer open")
        if (
            pull["head"]["repo"]["full_name"] != api.repository
            or pull["base"]["repo"]["full_name"] != api.repository
        ):
            raise NotEligible("pull request is not wholly same-repository")
        head_branch = pull["head"]["ref"]
        head_sha = _sha(pull["head"]["sha"], "pull request head SHA")
        base_branch = pull["base"]["ref"]
        base_sha = _sha(pull["base"]["sha"], "pull request base SHA")
        merge_sha = _sha(pull["merge_commit_sha"], "pull request merge SHA")
    except (KeyError, TypeError) as exc:
        raise PrGateError("pull request API record is malformed") from exc
    if not valid_branch_name(head_branch) or not valid_branch_name(base_branch):
        _fail("pull request branch identity is unsafe")
    if head_branch.startswith("automation/release-sync/"):
        raise NotEligible("release synchronization head is not an ordinary PR")
    # A wake from an older head of this pull request still re-evaluates its current head, whose
    # newest exact runs are selected below; a run of another branch is not this PR's evidence.
    if trigger is not None and trigger["head_branch"] != head_branch:
        raise NotEligible("trigger run is not from this pull request's head branch")
    if api.branch_sha(head_branch) != head_sha or api.branch_sha(base_branch) != base_sha:
        raise NotEligible("pull request branch heads changed during evaluation")
    merge_tree, parents = api.commit_identity(merge_sha)
    if parents != (base_sha, head_sha):
        _fail("synthetic pull request merge lacks exact current base/head parents")
    return PullIdentity(
        number=number,
        default_branch=default_branch,
        default_sha=default_sha,
        base_branch=base_branch,
        base_sha=base_sha,
        head_branch=head_branch,
        head_sha=head_sha,
        merge_sha=merge_sha,
        merge_tree=merge_tree,
    )


def resolve_dispatch_source(
    api: GitHubApi,
    *,
    implementation_sha: str,
    expected_source_sha: str,
    target_branch: str,
    expected_target_sha: str,
    candidate_branch: str,
    expected_candidate_sha: str,
    expected_candidate_tree: str,
) -> PullIdentity:
    """Authenticate one release-sync candidate tested by a default-controller dispatch."""

    implementation_sha = _sha(implementation_sha, "protected implementation SHA")
    expected_source_sha = _sha(expected_source_sha, "expected source SHA")
    target_sha = _sha(expected_target_sha, "expected target SHA")
    candidate_sha = _sha(expected_candidate_sha, "expected candidate SHA")
    candidate_tree = _sha(expected_candidate_tree, "expected candidate tree")
    if not valid_branch_name(target_branch) or not valid_branch_name(candidate_branch):
        _fail("release-sync dispatch has an unsafe branch identity")
    if not candidate_branch.startswith("automation/release-sync/"):
        _fail("release-sync candidate branch lacks its protected prefix")

    repository = api.repository_record()
    if repository.get("full_name") != api.repository:
        _fail("repository API identity changed")
    default_branch = repository.get("default_branch")
    if not valid_branch_name(default_branch):
        _fail("repository default branch is unsafe")
    if target_branch == default_branch or candidate_branch in {default_branch, target_branch}:
        _fail("release-sync source, target, and candidate branches must be distinct")
    default_sha = api.branch_sha(default_branch)
    if default_sha != implementation_sha or expected_source_sha != implementation_sha:
        raise NotEligible("protected default branch advanced during dispatch resolution")
    if api.branch_sha(target_branch) != target_sha:
        raise NotEligible("release-sync target branch advanced before dispatch")
    if api.branch_sha(candidate_branch) != candidate_sha:
        raise NotEligible("release-sync candidate branch advanced before dispatch")
    actual_tree, parents = api.commit_identity(candidate_sha)
    if actual_tree != candidate_tree:
        raise NotEligible("release-sync candidate tree differs from the expected tree")
    if parents != (target_sha, default_sha):
        _fail("release-sync candidate lacks exact ordered target/default parents")
    return PullIdentity(
        number=0,
        default_branch=default_branch,
        default_sha=default_sha,
        base_branch=target_branch,
        base_sha=target_sha,
        head_branch=candidate_branch,
        head_sha=candidate_sha,
        merge_sha=candidate_sha,
        merge_tree=actual_tree,
    )


def _upgrade_requested(api: GitHubApi, identity: PullIdentity) -> bool:
    pull = api.pull(identity.number)
    try:
        labels = pull["labels"]
        if not isinstance(labels, list) or len(labels) > 100:
            _fail("pull request label inventory is malformed or excessive")
        names = []
        for label in labels:
            if (
                not isinstance(label, dict)
                or not isinstance(label.get("name"), str)
                or not 1 <= len(label["name"]) <= 100
            ):
                _fail("pull request label inventory contains an invalid label")
            names.append(label["name"])
    except (KeyError, TypeError) as exc:
        raise PrGateError("pull request label inventory is malformed") from exc
    if len(names) != len(set(names)):
        _fail("pull request label inventory repeats a label")
    labelled = CONTROLLER_UPGRADE_LABEL in names
    prefixed = identity.head_branch.startswith(CONTROLLER_UPGRADE_BRANCH_PREFIX)
    if labelled != prefixed:
        _fail("controller-upgrade label and branch prefix must be present together")
    if not labelled:
        return False
    if (
        identity.base_branch != identity.default_branch
        or identity.base_sha != identity.default_sha
    ):
        _fail("controller upgrades may target only the exact default branch")
    return True


def controller_upgrade_authorization(
    api: GitHubApi, identity: PullIdentity
) -> UpgradeAuthorization:
    """Authenticate the latest exact owner command for this controller-upgrade head."""

    if not _upgrade_requested(api, identity):
        _fail("pull request does not request a controller upgrade")
    repository = api.repository_record()
    owner = repository.get("owner") if isinstance(repository, dict) else None
    if (
        repository.get("full_name") != api.repository
        or not isinstance(owner, dict)
        or owner.get("login") != REPOSITORY_OWNER["login"]
        or owner.get("type") != REPOSITORY_OWNER["type"]
    ):
        _fail("repository owner does not match protected controller-upgrade policy")

    commands: list[tuple[datetime, int, str, str]] = []
    seen_ids: set[int] = set()
    for comment in api.issue_comments(identity.number):
        comment_id = _positive(comment.get("id"), "issue comment id")
        if comment_id in seen_ids:
            _fail("issue comment inventory repeats an id")
        seen_ids.add(comment_id)
        user = comment.get("user")
        body = comment.get("body")
        updated_at = comment.get("updated_at")
        if not isinstance(user, dict) or not isinstance(body, str):
            _fail("issue comment inventory contains a malformed comment")
        updated = _timestamp(updated_at, "issue comment updated_at")
        match = CONTROLLER_UPGRADE_COMMAND.fullmatch(body)
        if match is None:
            continue
        if (
            user.get("login") != CONTROLLER_UPGRADE_OWNER
            or user.get("type") != "User"
            or comment.get("author_association") != CONTROLLER_UPGRADE_ASSOCIATION
        ):
            continue
        if match.group("head") == identity.head_sha:
            commands.append((updated, comment_id, match.group("decision"), updated_at))
    if not commands:
        _fail("controller upgrade lacks an exact current-head owner command")
    _updated, comment_id, decision, updated_at = max(commands, key=lambda item: (item[0], item[1]))
    if decision != "approve":
        _fail("latest exact current-head owner command revokes controller upgrade")
    bound = {
        "schema_version": 1,
        "purpose": "controller-upgrade-owner-authorization",
        "repository": api.repository,
        "pull_request": identity.number,
        "head_sha": identity.head_sha,
        "comment_id": comment_id,
        "comment_updated_at": updated_at,
    }
    digest = hashlib.sha256(
        (json.dumps(bound, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    ).hexdigest()
    return UpgradeAuthorization(comment_id, updated_at, identity.head_sha, digest)


def read_restricted_transition_owner_decision(
    api: GitHubApi, identity: PullIdentity, *, declaration: bytes,
    deployed_controller_sha: str, deployed_generation: int,
) -> dict[str, Any]:
    """Read authenticated decision data only; this never admits a transition.

    Deployment identity/generation must come from independently observed trusted deployment.
    Grammar: /restricted-transition approve|revoke <generation> <head> <declaration-sha256>.
    The newest owner command must be exact and have matching created/updated timestamps; stale,
    malformed and revoked commands cannot fall back to an older approval. Any newer edited
    owner comment also blocks, because editing can erase its original command purpose.
    The caller must retain its bound digest and re-read/compare after selecting gate evidence.
    API reads are not atomic and cannot reconstruct comments deleted before the first observation.
    """
    transition = parse_restricted_transition(
        declaration, identity=identity, deployed_controller_sha=deployed_controller_sha,
        deployed_generation=deployed_generation)

    def check_identity() -> None:
        if resolve_pull_identity(api, implementation_sha=deployed_controller_sha,
                                 pr_number=identity.number) != identity:
            _fail("restricted transition pull identity changed")

    check_identity()
    repository = api.repository_record()
    owner = repository.get("owner")
    if (repository.get("full_name") != api.repository or not isinstance(owner, dict)
            or owner.get("login") != REPOSITORY_OWNER["login"]
            or owner.get("type") != REPOSITORY_OWNER["type"]):
        _fail("repository owner does not match restricted transition policy")
    issue_url = f"{api.api_url}/repos/{api.repository}/issues/{identity.number}"

    def snapshot(comment: dict[str, Any]) -> dict[str, Any]:
        keys = ("id", "body", "created_at", "updated_at", "issue_url",
                "author_association", "performed_via_github_app")
        return {**{key: comment.get(key) for key in keys},
                "user": {key: comment.get("user", {}).get(key) for key in ("login", "type")}}

    def latest() -> dict[str, Any]:
        comments = api.issue_comments(identity.number)
        if not isinstance(comments, list) or len(comments) > MAX_RECORDS:
            _fail("restricted transition comment inventory exceeds its bound")
        commands, seen = [], set()
        for comment in comments:
            if not isinstance(comment, dict):
                _fail("restricted transition comment inventory contains a non-object")
            comment_id = _positive(comment.get("id"), "issue comment id")
            if comment_id in seen:
                _fail("restricted transition comment inventory repeats an id")
            seen.add(comment_id)
            user, body = comment.get("user"), comment.get("body")
            if not isinstance(user, dict) or not isinstance(body, str):
                _fail("restricted transition comment inventory contains a malformed comment")
            if user.get("login") == CONTROLLER_UPGRADE_OWNER:
                updated = _timestamp(comment.get("updated_at"), "issue comment updated_at")
                _timestamp(comment.get("created_at"), "issue comment created_at")
                if (body.startswith("/restricted-transition")
                        or comment["created_at"] != comment["updated_at"]):
                    commands.append((updated, comment["created_at"] != comment["updated_at"],
                                     comment_id, snapshot(comment)))
        if not commands:
            _fail("restricted transition lacks an exact current-head owner command")
        # An edit tied to an approval's timestamp cannot be ordered by creation id safely.
        return max(commands, key=lambda item: item[:3])[3]

    selected = latest()
    fresh = api.issue_comment(selected["id"])
    if (not isinstance(fresh.get("user"), dict) or snapshot(fresh) != selected
            or latest() != selected):
        _fail("restricted transition owner comment changed or disappeared")
    if (selected["issue_url"] != issue_url
            or selected["user"] != {"login": CONTROLLER_UPGRADE_OWNER, "type": "User"}
            or selected["author_association"] != CONTROLLER_UPGRADE_ASSOCIATION
            or selected["performed_via_github_app"] is not None):
        _fail("restricted transition comment is not a direct repository-owner decision")
    decision = {
        "schema_version": 1, "purpose": "restricted-transition-owner-authorization",
        "repository": api.repository, "pull_request": identity.number,
        "owner": CONTROLLER_UPGRADE_OWNER, "decision": "approve",
        "controller_generation": transition.controller_generation,
        "controller_sha": transition.controller_sha, "base_sha": transition.base_sha,
        "head_sha": transition.head_sha, "declaration_sha256": transition.digest,
        "comment_id": selected["id"], "comment_body": selected["body"],
        "comment_created_at": selected["created_at"], "comment_updated_at": selected["updated_at"],
    }
    bind_restricted_transition_decision(
        transition, repository=api.repository, pull_number=identity.number,
        authenticated_owner_decision=decision)
    check_identity()
    return decision


def _git(repository: Path, *arguments: str, accepted: Iterable[int] = (0,)) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_GRAFT_FILE": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "LC_ALL": "C",
        },
    )
    if result.returncode not in set(accepted):
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise PrGateError(detail or f"git {' '.join(arguments)} failed")
    return result.stdout


def _exact_commit(repository: Path, commit: str, label: str) -> str:
    commit = _sha(commit, label)
    resolved = _git(repository, "rev-parse", "--verify", f"{commit}^{{commit}}").decode().strip()
    if resolved != commit:
        _fail(f"{label} did not resolve to itself")
    return commit


def _tree_entry(repository: Path, commit: str, path: str) -> tuple[str, str, str] | None:
    raw = _git(repository, "ls-tree", "-z", commit, "--", path)
    if not raw:
        return None
    metadata, separator, raw_path = raw.rstrip(b"\0").partition(b"\t")
    fields = metadata.split()
    if separator != b"\t" or raw_path != path.encode() or len(fields) != 3:
        _fail(f"{commit} has a malformed tree entry for {path}")
    try:
        return tuple(item.decode("ascii") for item in fields)  # type: ignore[return-value]
    except UnicodeDecodeError as exc:
        raise PrGateError(f"{commit} has a non-ASCII tree entry for {path}") from exc


def _blob(repository: Path, commit: str, path: str, *, maximum: int) -> bytes:
    entry = _tree_entry(repository, commit, path)
    if entry is None or entry[:2] != ("100644", "blob"):
        _fail(f"{commit} has no regular non-executable {path} blob")
    size_raw = _git(repository, "cat-file", "-s", entry[2]).decode().strip()
    try:
        size = int(size_raw)
    except ValueError as exc:
        raise PrGateError(f"{path} has invalid Git blob size") from exc
    if not 1 <= size <= maximum:
        _fail(f"{path} size is outside 1..{maximum}")
    value = _git(repository, "cat-file", "blob", entry[2])
    if len(value) != size:
        _fail(f"{path} changed while reading its immutable Git blob")
    return value


def _validate_local_pull_tree(repository: Path, identity: PullIdentity) -> Path:
    repository = repository.resolve()
    for value, label in (
        (identity.default_sha, "default SHA"),
        (identity.base_sha, "base SHA"),
        (identity.head_sha, "head SHA"),
        (identity.merge_sha, "merge SHA"),
    ):
        _exact_commit(repository, value, label)
    if _git(repository, "rev-parse", "HEAD").decode().strip() != identity.merge_sha:
        _fail("candidate checkout is not the exact current synthetic merge")
    parents = tuple(_git(repository, "show", "-s", "--format=%P", identity.merge_sha).decode().split())
    if parents != (identity.base_sha, identity.head_sha):
        _fail("local synthetic merge has stale or reordered parents")
    tree = _git(repository, "rev-parse", f"{identity.merge_sha}^{{tree}}").decode().strip()
    if tree != identity.merge_tree:
        _fail("local synthetic merge tree disagrees with GitHub API")
    return repository


def validate_restricted_transition_tree(
    repository: Path, identity: PullIdentity, *, declaration: bytes,
    deployed_controller_sha: str, deployed_generation: int,
) -> RestrictedTransition:
    """Check exact proposal/tree boundaries; return no admission or authorization.

    Deployment and PR state must be authenticated externally, as required by the parser.
    Scope-specific semantics (including both loader phases), owner decisions and required
    gate evidence remain separate checks. No existing gate calls this opt-in helper.
    """
    transition = parse_restricted_transition(
        declaration, identity=identity, deployed_controller_sha=deployed_controller_sha,
        deployed_generation=deployed_generation,
    )
    repository = _validate_local_pull_tree(repository, identity)
    _git(repository, "merge-base", "--is-ancestor", identity.base_sha, identity.head_sha)
    head_tree = _git(repository, "rev-parse", f"{identity.head_sha}^{{tree}}").decode().strip()
    if head_tree != identity.merge_tree:
        _fail("restricted transition head and synthetic merge have different trees")
    raw = _git(
        repository, "diff", "--no-ext-diff", "--no-renames", "--ignore-submodules=none",
        "--name-status", "-z", identity.base_sha, identity.merge_sha, "--",
    )
    fields = raw.rstrip(b"\0").split(b"\0") if raw else []
    if not fields or len(fields) % 2 or len(fields) // 2 > len(transition.paths):
        _fail("restricted transition diff is empty, malformed or exceeds its declaration")
    seen: set[str] = set()
    for index in range(0, len(fields), 2):
        status = fields[index]
        path = _canonical_upgrade_path(fields[index + 1])
        if status not in {b"A", b"M", b"D"} or path in seen or path not in transition.paths:
            _fail("restricted transition diff has an undeclared path, status or duplicate")
        seen.add(path)
        base = _tree_entry(repository, identity.base_sha, path)
        candidate = _tree_entry(repository, identity.merge_sha, path)
        if any(entry is not None and entry[:2] != ("100644", "blob") for entry in (base, candidate)):
            _fail(f"restricted transition requires regular non-executable blobs: {path!r}")
        if (status == b"A" and (base is not None or candidate is None)
                or status == b"D" and (base is None or candidate is not None)
                or status == b"M" and (base is None or candidate is None)):
            _fail("restricted transition status disagrees with immutable tree entries")
    if seen != set(transition.paths):
        _fail("restricted transition changed paths differ from its exact declaration")
    return transition


def validate_restricted_loader_transition(
    repository: Path, identity: PullIdentity, *, declaration: bytes,
    deployed_controller_sha: str, deployed_generation: int,
) -> RestrictedTransition:
    """Verify a contract-first or exact-next proposal, without admitting it.

    Deployment and identity remain externally authenticated inputs. Owner authorization and
    required gate evidence are still separate; no existing evaluator calls this helper.
    """
    transition = validate_restricted_transition_tree(
        repository, identity, declaration=declaration,
        deployed_controller_sha=deployed_controller_sha, deployed_generation=deployed_generation,
    )
    loader, _, phase = transition.scope.rpartition("-")
    if loader not in {"fabric", "forge", "neoforge"} or phase not in {"contract", "next"}:
        _fail("restricted loader validation requires one exact loader phase scope")
    try:
        base = load_loader_bootstrap_contract(_blob(
            repository, identity.base_sha, BOOTSTRAP_CONTRACT_PATH, maximum=MAX_CONTRACT_BYTES,
        ))
        if phase == "contract":
            candidate = load_loader_bootstrap_contract(_blob(
                repository, identity.head_sha, BOOTSTRAP_CONTRACT_PATH, maximum=MAX_CONTRACT_BYTES,
            ))
            if (base.schema_version != 1 or candidate.transition is None
                    or candidate.transition.loader != loader or candidate.loaders != base.loaders):
                _fail("contract-first proposal must preserve the protected current contract for its exact loader")
            validate_loader_bootstrap_commit(repository, head_sha=identity.base_sha, contract_sha=identity.base_sha)
            validate_loader_bootstrap_commit(repository, head_sha=identity.head_sha, contract_sha=identity.head_sha)
        else:
            if base.transition is None or base.transition.loader != loader:
                _fail("exact-next proposal requires its declared loader transition in the protected base")
            validate_loader_bootstrap_transition(repository, head_sha=identity.head_sha, base_sha=identity.base_sha)
    except LoaderBootstrapError as exc:
        raise PrGateError(f"restricted loader bootstrap proposal is invalid: {exc}") from exc
    return transition


def _require_exact_base_owned(repository: Path, identity: PullIdentity) -> None:
    for path in EXACT_BASE_OWNED_PATHS:
        base = _tree_entry(repository, identity.base_sha, path)
        merge = _tree_entry(repository, identity.merge_sha, path)
        if base is None or base[:2] != ("100644", "blob") or merge != base:
            _fail(f"pull request changed exact base-owned path {path!r}")


def _matrix_for_identity(repository: Path, identity: PullIdentity) -> tuple[bytes, dict[str, Any]]:
    matrix_bytes = _blob(
        repository, identity.merge_sha, MATRIX_PATH, maximum=256 * 1024
    )
    matrix = load_trusted_gate_matrix_bytes(matrix_bytes)
    branch = matrix["branch"]
    if branch["name"] != identity.base_branch or branch["canonical"] != identity.default_branch:
        _fail("base branch release matrix does not authenticate this PR topology")
    if identity.base_branch == identity.default_branch:
        if branch["role"] != "integration":
            _fail("default branch matrix is not integration policy")
    elif (
        branch["role"] != "release"
        or branch["sync"] != {"enabled": True, "source": identity.default_branch}
    ):
        _fail("release base matrix is not enrolled in protected synchronization")
    return matrix_bytes, matrix


def validate_pr_tree(repository: Path, identity: PullIdentity) -> bytes:
    """Authenticate default->base portability and exact base->merge control-plane parity."""

    repository = _validate_local_pull_tree(repository, identity)

    # A release branch is accepted as policy only after proving its controllers are a valid,
    # branch-portable projection of the current protected default branch.
    validate_controller_parity(
        repository,
        protected_sha=identity.default_sha,
        candidate_sha=identity.base_sha,
    )
    validate_controller_parity(
        repository,
        protected_sha=identity.base_sha,
        candidate_sha=identity.merge_sha,
    )
    _require_exact_base_owned(repository, identity)
    matrix_bytes, _matrix = _matrix_for_identity(repository, identity)
    return matrix_bytes


def _canonical_upgrade_path(raw: bytes) -> str:
    try:
        value = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise PrGateError("controller-upgrade diff contains a non-UTF-8 path") from exc
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        _fail("controller-upgrade diff contains an unsafe path")
    return value


def _upgrade_path_allowed(path: str, loader_paths: frozenset[str]) -> bool:
    if path in CONTROLLER_UPGRADE_DOCS:
        return True
    if path.startswith("docs/") and path.endswith(".md"):
        return True
    loader_files = {root for root in loader_paths if root.endswith("/build.gradle")}
    loader_directories = loader_paths - loader_files
    if path in loader_files or any(
        path == root or path.startswith(f"{root}/") for root in loader_directories
    ):
        return True
    if path in CONTROLLER_UPGRADE_FILE_ROOTS:
        return True
    return any(
        path == root or path.startswith(f"{root}/")
        for root in CONTROLLER_UPGRADE_DIRECTORY_ROOTS
    )


def validate_controller_upgrade_tree(repository: Path, identity: PullIdentity) -> bytes:
    """Admit an owner-authorized, controller-only change under the old protected policy."""

    repository = _validate_local_pull_tree(repository, identity)
    if (
        identity.base_branch != identity.default_branch
        or identity.base_sha != identity.default_sha
    ):
        _fail("controller upgrades may target only the exact default branch")
    validate_controller_parity(
        repository,
        protected_sha=identity.default_sha,
        candidate_sha=identity.base_sha,
    )
    _require_exact_base_owned(repository, identity)
    matrix_bytes, matrix = _matrix_for_identity(repository, identity)
    loader_paths = frozenset(
        path
        for loader in {row["loader"] for row in matrix["artifacts"]}
        for path in (f"{loader}/build.gradle", f"{loader}/src/e2e")
    )
    raw = _git(
        repository,
        "diff",
        "--no-ext-diff",
        "--no-renames",
        "--name-status",
        "-z",
        identity.base_sha,
        identity.merge_sha,
        "--",
    )
    fields = raw.rstrip(b"\0").split(b"\0") if raw else []
    if not fields or len(fields) % 2:
        _fail("controller-upgrade diff inventory is empty or malformed")
    if len(fields) // 2 > MAX_CONTROLLER_UPGRADE_PATHS:
        _fail("controller-upgrade diff exceeds its bounded path inventory")
    seen: set[str] = set()
    for index in range(0, len(fields), 2):
        try:
            status = fields[index].decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise PrGateError("controller-upgrade diff status is not ASCII") from exc
        path = _canonical_upgrade_path(fields[index + 1])
        if status not in {"A", "M", "D"} or path in seen:
            _fail("controller-upgrade diff has an unknown status or duplicate path")
        seen.add(path)
        if path in EXACT_BASE_OWNED_PATHS:
            _fail(f"controller upgrade changed exact base-owned path {path!r}")
        if not _upgrade_path_allowed(path, loader_paths):
            _fail(f"controller upgrade changed non-controller path {path!r}")
        base_entry = _tree_entry(repository, identity.base_sha, path)
        merge_entry = _tree_entry(repository, identity.merge_sha, path)
        if status == "A":
            if base_entry is not None or merge_entry is None or merge_entry[:2] != ("100644", "blob"):
                _fail(f"controller upgrade added unsafe tree entry {path!r}")
        elif status == "D":
            if (
                merge_entry is not None
                or base_entry is None
                or base_entry[0] not in {"100644", "100755"}
                or base_entry[1] != "blob"
            ):
                _fail(f"controller upgrade removed an unsafe tree entry {path!r}")
        elif (
            base_entry is None
            or merge_entry is None
            or base_entry[:2] != merge_entry[:2]
            or base_entry[0] not in {"100644", "100755"}
            or base_entry[1] != "blob"
        ):
            _fail(f"controller upgrade changed mode or kind for {path!r}")
    for path in CONTROLLER_UPGRADE_REQUIRED:
        entry = _tree_entry(repository, identity.merge_sha, path)
        if entry is None or entry[:2] != ("100644", "blob"):
            _fail(f"controller upgrade removed required protected file {path!r}")
    for path in FORBIDDEN_PATHS:
        if _tree_entry(repository, identity.merge_sha, path) is not None:
            _fail(f"controller upgrade introduced forbidden path {path!r}")
    try:
        validate_loader_bootstrap_commit(
            repository,
            head_sha=identity.merge_sha,
            contract_sha=identity.base_sha,
        )
    except LoaderBootstrapError as exc:
        raise PrGateError(
            f"controller upgrade changed loader bootstrap outside old policy: {exc}"
        ) from exc
    return matrix_bytes


def select_newest_pull_run(
    records: Iterable[Any],
    *,
    workflow: str,
    repository: str,
    identity: PullIdentity,
) -> SelectedRun | None:
    if workflow not in WORKFLOWS.values():
        _fail("unsupported PR gate workflow")
    path = f".github/workflows/{workflow}"
    candidates: list[tuple[datetime, int, SelectedRun]] = []
    seen: set[int] = set()
    for value in records:
        if not isinstance(value, dict):
            _fail("workflow runs response contains a non-object")
        run_repository = value.get("repository")
        head_repository = value.get("head_repository")
        if (
            value.get("event") != "pull_request_target"
            or value.get("path") != path
            or value.get("head_branch") != identity.head_branch
            or value.get("head_sha") != identity.head_sha
            or not runs_default_controller(
                value,
                repository=repository,
                default_branch=identity.default_branch,
                default_sha=identity.default_sha,
            )
            or not isinstance(run_repository, dict)
            or run_repository.get("full_name") != repository
            or not isinstance(head_repository, dict)
            or head_repository.get("full_name") != repository
        ):
            continue
        if _run_pull_number(value, f"{workflow} run") != identity.number:
            continue
        run_id = _positive(value.get("id"), "workflow run id")
        attempt = _positive(value.get("run_attempt"), "workflow run attempt")
        if run_id in seen:
            _fail("workflow runs response repeats a run id")
        seen.add(run_id)
        status = value.get("status")
        conclusion = value.get("conclusion")
        if status not in RUN_STATUSES:
            _fail("matching workflow run has an invalid status")
        if status == "completed":
            if conclusion not in RUN_CONCLUSIONS:
                _fail("completed workflow run has an invalid conclusion")
        elif conclusion is not None:
            _fail("incomplete workflow run unexpectedly has a conclusion")
        created_at = value.get("created_at")
        selected = SelectedRun(run_id, attempt, status, conclusion, created_at)
        candidates.append((_timestamp(created_at, "workflow run created_at"), run_id, selected))
    if not candidates:
        return None
    # One PR event can start two runs of a gate in the same second (``opened`` with ``labeled``),
    # and the gate's ``cancel-in-progress`` concurrency cancels whichever entered its group first,
    # which neither the timestamp nor the run id reveals. Every candidate here is the same exact
    # head under the same controller, so a cancelled run never shadows a sibling that ran: a newer
    # failed or in-progress run still overrides an older success.
    ran = [item for item in candidates if item[2].conclusion != "cancelled"]
    return max(ran or candidates, key=lambda item: (item[0], item[1]))[2]


def _expected_artifact_name(kind: str, identity: PullIdentity, attempt: int) -> str:
    if kind == "build":
        return f"staged-release-bundle-{identity.merge_sha}-{attempt}"
    if kind == "e2e":
        return aggregate_artifact_name(identity.merge_sha, attempt)
    _fail("unsupported gate artifact kind")


def validate_exact_artifact(
    records: Iterable[Any], *, expected_name: str, run_id: int
) -> dict[str, Any]:
    ids: set[int] = set()
    names: set[str] = set()
    matched: list[dict[str, Any]] = []
    for value in records:
        if not isinstance(value, dict):
            _fail("artifact API response contains a non-object")
        artifact_id = _positive(value.get("id"), "artifact id")
        name = value.get("name")
        if not isinstance(name, str) or not name or len(name) > 256:
            _fail("artifact has an invalid name")
        if artifact_id in ids or name in names:
            _fail("artifact API response repeats an id or name")
        ids.add(artifact_id)
        names.add(name)
        if name != expected_name:
            continue
        owner = value.get("workflow_run")
        size = value.get("size_in_bytes")
        digest = value.get("digest")
        if (
            value.get("expired") is not False
            or not isinstance(owner, dict)
            or _positive(owner.get("id"), "artifact workflow run id") != run_id
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 1 <= size <= MAX_ARTIFACT_BYTES
            or not isinstance(digest, str)
            or SHA256_DIGEST.fullmatch(digest) is None
        ):
            _fail("exact gate artifact metadata is stale or unsafe")
        matched.append(value)
    if len(matched) != 1:
        _fail(f"expected exactly one immutable artifact named {expected_name!r}")
    return matched[0]


def _gate_result(
    api: GitHubApi,
    *,
    kind: str,
    identity: PullIdentity,
    matrix_path: Path,
    selected: SelectedRun | None,
    evidence: dict[str, Any] | None = None,
) -> GateResult:
    label = "Build" if kind == "build" else "Packaged E2E"
    if selected is None:
        return GateResult("pending", f"No exact current-head {label} run exists", 0, 0)
    if selected.status != "completed":
        return GateResult(
            "pending",
            f"Newest exact {label} run attempt is still in progress",
            selected.run_id,
            selected.run_attempt,
        )
    if selected.conclusion != "success":
        return GateResult(
            "failure",
            f"Newest exact {label} run attempt did not succeed",
            selected.run_id,
            selected.run_attempt,
        )
    try:
        graph = expected_jobs(
            matrix_path,
            WORKFLOWS[kind],
            event="pull_request_target",
            source_branch=identity.base_branch,
        )
        jobs = validate_jobs(
            api.jobs(selected.run_id),
            expected=graph,
            run_attempt=selected.run_attempt,
        )
        artifact = validate_exact_artifact(
            api.artifacts(selected.run_id),
            expected_name=_expected_artifact_name(kind, identity, selected.run_attempt),
            run_id=selected.run_id,
        )
    except (JobGraphError, MatrixError, PrGateError):
        return GateResult(
            "failure",
            f"Newest exact {label} evidence failed protected validation",
            selected.run_id,
            selected.run_attempt,
        )
    if evidence is not None:
        evidence[kind] = {
            "run_id": selected.run_id, "run_attempt": selected.run_attempt, "jobs": jobs,
            "artifact": {key: artifact[key] for key in ("id", "name", "size_in_bytes", "digest", "expired")},
        }
    return GateResult(
        "success",
        f"Protected evaluator accepted newest exact {label} attempt",
        selected.run_id,
        selected.run_attempt,
    )


def _snapshot(
    api: GitHubApi, *, identity: PullIdentity, matrix_path: Path,
    evidence: dict[str, Any] | None = None,
) -> tuple[dict[str, GateResult], dict[str, SelectedRun | None]]:
    selected = {
        kind: select_newest_pull_run(
            api.workflow_runs(workflow),
            workflow=workflow,
            repository=api.repository,
            identity=identity,
        )
        for kind, workflow in WORKFLOWS.items()
    }
    results = {
        kind: _gate_result(
            api,
            kind=kind,
            identity=identity,
            matrix_path=matrix_path,
            selected=selected[kind],
            evidence=evidence,
        )
        for kind in WORKFLOWS
    }
    return results, selected


def evaluate_restricted_transition(
    api: GitHubApi, *, repository: Path, identity: PullIdentity, declaration: bytes,
    deployed_controller_sha: str, deployed_generation: int,
) -> dict[str, Any]:
    """Compose a bounded evidence proposal; no existing admission or publication route calls this.

    The implementation and generation must come from an independently authenticated deployed
    controller, never the candidate. Only unchanged schema-1 base matrices currently define
    protected expected graphs. Matrix transitions and schema 2 remain unsupported here.
    The result is not a status-writer credential: final publication reauthorization is unwired.
    """
    def current_identity() -> None:
        if resolve_pull_identity(api, implementation_sha=deployed_controller_sha,
                                 pr_number=identity.number) != identity:
            raise NotEligible("restricted transition identity changed during evaluation")

    current_identity()
    arguments = dict(declaration=declaration, deployed_controller_sha=deployed_controller_sha,
                     deployed_generation=deployed_generation)
    transition = parse_restricted_transition(declaration, identity=identity,
        deployed_controller_sha=deployed_controller_sha, deployed_generation=deployed_generation)
    if transition.scope == "matrix":
        _fail("restricted matrix transition has no independently authorized evidence graph")
    if transition.scope.rpartition("-")[0] in {"fabric", "forge", "neoforge"}:
        validate_restricted_loader_transition(repository, identity, **arguments)
    else:
        validate_restricted_transition_tree(repository, identity, **arguments)
    base_matrix = _blob(repository, identity.base_sha, MATRIX_PATH, maximum=256 * 1024)
    # Restricted evidence graphs stay schema-1 only; the gate's preparing projection is not one.
    load_matrix_bytes(base_matrix)
    matrix_bytes, _ = _matrix_for_identity(repository, identity)
    if matrix_bytes != base_matrix:
        _fail("restricted transition cannot select candidate-owned evidence policy")

    def owner() -> tuple[dict[str, Any], str]:
        decision = read_restricted_transition_owner_decision(api, identity, **arguments)
        digest = bind_restricted_transition_decision(transition, repository=api.repository,
            pull_number=identity.number, authenticated_owner_decision=decision)
        return decision, digest

    decision, owner_digest = owner()
    with tempfile.TemporaryDirectory(prefix="blockpops-restricted-evidence-") as temporary:
        matrix_path = Path(temporary) / "release-matrix.json"
        matrix_path.write_bytes(base_matrix)
        snapshots = []
        for _ in range(2):
            evidence: dict[str, Any] = {}
            results, selected = _snapshot(api, identity=identity, matrix_path=matrix_path, evidence=evidence)
            if set(evidence) != set(WORKFLOWS) or any(gate.state != "success" for gate in results.values()):
                _fail("restricted transition lacks successful newest exact Build and E2E evidence")
            snapshots.append((results, selected, evidence))
            if owner() != (decision, owner_digest):
                raise NotEligible("restricted transition owner decision changed during evaluation")
        if snapshots[0] != snapshots[1]:
            _fail("restricted transition newest exact evidence changed during reselection")
    current_identity()
    # Recheck local immutable-object/checkout bindings after all external observations.
    validate_restricted_transition_tree(repository, identity, **arguments)
    return {
        "schema_version": 1, "kind": "restricted-transition-evidence", "status": "evidence-validated",
        "admission": False, "repository": api.repository, "identity": asdict(identity),
        "transition": asdict(transition), "declaration_sha256": transition.digest,
        "owner_decision": decision, "owner_decision_sha256": owner_digest,
        "matrix": {"commit": identity.base_sha, "sha256": hashlib.sha256(base_matrix).hexdigest()},
        "gates": {kind: {**asdict(snapshots[1][0][kind]), "context": CONTEXTS[kind],
                         "evidence": snapshots[1][2][kind]} for kind in WORKFLOWS},
    }


def evaluate(
    api: GitHubApi,
    *,
    repository: Path,
    implementation_sha: str,
    expected_pr_number: int,
    expected_merge_sha: str,
    trigger_run_id: int | None = None,
    pr_number: int | None = None,
) -> dict[str, Any]:
    identity = resolve_pull_identity(
        api,
        trigger_run_id=trigger_run_id,
        pr_number=pr_number,
        implementation_sha=implementation_sha,
    )
    if identity.number != expected_pr_number or identity.merge_sha != expected_merge_sha:
        raise NotEligible("pull request identity changed after candidate checkout")
    policy_mode = "ordinary"
    authorization: UpgradeAuthorization | None = None
    try:
        if _upgrade_requested(api, identity):
            policy_mode = "controller-upgrade"
            authorization = controller_upgrade_authorization(api, identity)
            matrix_bytes = validate_controller_upgrade_tree(repository, identity)
        else:
            matrix_bytes = validate_pr_tree(repository, identity)
    except (GateControllerError, LoaderBootstrapError, MatrixError, PrGateError) as exc:
        # The target head/base were authenticated before policy evaluation, so a protected-policy
        # mismatch is safe to report as failure on that exact current head.
        current = resolve_pull_identity(
            api,
            trigger_run_id=trigger_run_id,
            pr_number=pr_number,
            implementation_sha=implementation_sha,
        )
        if current != identity:
            raise NotEligible("pull request changed while reporting a policy failure") from exc
        description = (
            "Controller upgrade authorization or protected policy failed"
            if policy_mode == "controller-upgrade"
            else "Ordinary PR changed protected branch policy"
        )
        failure = GateResult("failure", description, 0, 0)
        return _result(
            identity,
            {"build": failure, "e2e": failure},
            policy_mode=policy_mode,
            authorization=authorization,
        )

    def current_identity_and_authorization() -> None:
        current = resolve_pull_identity(
            api,
            trigger_run_id=trigger_run_id,
            pr_number=pr_number,
            implementation_sha=implementation_sha,
        )
        if current != identity:
            raise NotEligible("pull request identity changed during protected gate evaluation")
        if policy_mode == "controller-upgrade":
            if authorization is None or controller_upgrade_authorization(api, current) != authorization:
                raise NotEligible("controller-upgrade authorization changed during evaluation")

    with tempfile.TemporaryDirectory(prefix="blockpops-pr-gate-") as temporary:
        matrix_path = Path(temporary) / "release-matrix.json"
        matrix_path.write_bytes(matrix_bytes)
        try:
            first_results, first_selected = _snapshot(
                api, identity=identity, matrix_path=matrix_path
            )
        except (JobGraphError, MatrixError, PrGateError) as exc:
            current = resolve_pull_identity(
                api,
                trigger_run_id=trigger_run_id,
                pr_number=pr_number,
                implementation_sha=implementation_sha,
            )
            if current != identity:
                raise NotEligible(
                    "pull request changed while gate evidence was unavailable"
                ) from exc
            failure = GateResult(
                "failure",
                "Protected evaluator could not authenticate newest exact gate evidence",
                0,
                0,
            )
            return _result(
                identity,
                {"build": failure, "e2e": failure},
                policy_mode=policy_mode,
                authorization=authorization,
            )
        current_identity_and_authorization()
        try:
            second_results, second_selected = _snapshot(
                api, identity=identity, matrix_path=matrix_path
            )
        except (JobGraphError, MatrixError, PrGateError) as exc:
            current = resolve_pull_identity(
                api,
                trigger_run_id=trigger_run_id,
                pr_number=pr_number,
                implementation_sha=implementation_sha,
            )
            if current != identity:
                raise NotEligible(
                    "pull request changed during exact gate reselection"
                ) from exc
            failure = GateResult(
                "failure",
                "Protected evaluator could not reselect newest exact gate evidence",
                0,
                0,
            )
            return _result(
                identity,
                {"build": failure, "e2e": failure},
                policy_mode=policy_mode,
                authorization=authorization,
            )
        current_identity_and_authorization()
        if first_selected != second_selected or first_results != second_results:
            pending = {
                kind: GateResult(
                    "pending",
                    "Exact gate evidence changed during protected reselection",
                    0 if second_selected[kind] is None else second_selected[kind].run_id,
                    0 if second_selected[kind] is None else second_selected[kind].run_attempt,
                )
                for kind in WORKFLOWS
            }
            return _result(
                identity,
                pending,
                policy_mode=policy_mode,
                authorization=authorization,
            )
        return _result(
            identity,
            second_results,
            policy_mode=policy_mode,
            authorization=authorization,
        )


def _result(
    identity: PullIdentity,
    gates: dict[str, GateResult],
    *,
    policy_mode: str = "ordinary",
    authorization: UpgradeAuthorization | None = None,
) -> dict[str, Any]:
    if policy_mode not in {"ordinary", "controller-upgrade"}:
        _fail("trusted PR policy mode is invalid")
    return {
        "schema_version": SCHEMA_VERSION,
        "eligible": True,
        "pull_request": identity.number,
        "default_branch": identity.default_branch,
        "base_branch": identity.base_branch,
        "head_branch": identity.head_branch,
        "head_sha": identity.head_sha,
        "merge_sha": identity.merge_sha,
        "merge_tree": identity.merge_tree,
        "base_sha": identity.base_sha,
        "default_sha": identity.default_sha,
        "policy_mode": policy_mode,
        "authorization_digest": "0" * 64 if authorization is None else authorization.digest,
        "authorization_comment_id": 0 if authorization is None else authorization.comment_id,
        "gates": {
            kind: {**asdict(gates[kind]), "context": CONTEXTS[kind]}
            for kind in ("build", "e2e")
        },
    }


def reauthorize(
    api: GitHubApi,
    *,
    implementation_sha: str,
    expected_pr_number: int,
    expected_default_branch: str,
    expected_default_sha: str,
    expected_base_branch: str,
    expected_base_sha: str,
    expected_head_branch: str,
    expected_head_sha: str,
    expected_merge_sha: str,
    expected_merge_tree: str,
    expected_policy_mode: str,
    expected_authorization_digest: str,
    expected_authorization_comment_id: int,
) -> dict[str, Any]:
    """Reauthenticate the exact evaluator result immediately before status-token minting.

    A changed or revoked controller-upgrade authorization is still eligible for a restrictive
    failure status on the same immutable head.  A changed PR, branch name, commit, merge, or merge
    tree identity is ineligible, because publishing to the old head would be stale and publishing
    to the new topology would bless evidence that was never evaluated.
    """

    expected_pr_number = _positive(expected_pr_number, "expected pull request number")
    for branch, label in (
        (expected_default_branch, "expected default branch"),
        (expected_base_branch, "expected base branch"),
        (expected_head_branch, "expected head branch"),
    ):
        if not valid_branch_name(branch):
            _fail(f"{label} is unsafe")
    expected_default_sha = _sha(expected_default_sha, "expected default SHA")
    expected_base_sha = _sha(expected_base_sha, "expected base SHA")
    expected_head_sha = _sha(expected_head_sha, "expected head SHA")
    expected_merge_sha = _sha(expected_merge_sha, "expected merge SHA")
    expected_merge_tree = _sha(expected_merge_tree, "expected merge tree")
    if expected_policy_mode not in {"ordinary", "controller-upgrade"}:
        _fail("expected policy mode is invalid")
    if (
        not isinstance(expected_authorization_digest, str)
        or SHA256.fullmatch(expected_authorization_digest) is None
    ):
        _fail("expected authorization digest must be one lowercase SHA-256")
    if (
        isinstance(expected_authorization_comment_id, bool)
        or not isinstance(expected_authorization_comment_id, int)
        or expected_authorization_comment_id < 0
    ):
        _fail("expected authorization comment id must be a non-negative integer")
    empty_authorization = expected_authorization_digest == "0" * 64
    if expected_policy_mode == "ordinary":
        if not empty_authorization or expected_authorization_comment_id != 0:
            _fail("ordinary policy unexpectedly carries controller-upgrade authorization")
    elif empty_authorization != (expected_authorization_comment_id == 0):
        _fail("controller-upgrade authorization expectation is partially empty")

    identity = resolve_pull_identity(
        api,
        pr_number=expected_pr_number,
        implementation_sha=implementation_sha,
    )
    expected_identity = PullIdentity(
        number=expected_pr_number,
        default_branch=expected_default_branch,
        default_sha=expected_default_sha,
        base_branch=expected_base_branch,
        base_sha=expected_base_sha,
        head_branch=expected_head_branch,
        head_sha=expected_head_sha,
        merge_sha=expected_merge_sha,
        merge_tree=expected_merge_tree,
    )
    if identity != expected_identity:
        raise NotEligible("pull request identity changed before trusted status publication")

    authorization_current = False
    if expected_policy_mode == "ordinary":
        try:
            authorization_current = not _upgrade_requested(api, identity)
        except PrGateError:
            authorization_current = False
    else:
        try:
            current = controller_upgrade_authorization(api, identity)
        except PrGateError:
            authorization_current = False
        else:
            authorization_current = (
                not empty_authorization
                and current.digest == expected_authorization_digest
                and current.comment_id == expected_authorization_comment_id
            )

    return {
        "schema_version": SCHEMA_VERSION,
        "eligible": True,
        "authorization_current": authorization_current,
        "pull_request": identity.number,
        "head_sha": identity.head_sha,
        "policy_mode": expected_policy_mode,
    }


def _append_outputs(path: Path, values: dict[str, Any]) -> None:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            _fail("GITHUB_OUTPUT must be a regular non-symlink file")
    except FileNotFoundError:
        path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for key, raw in values.items():
        value = str(raw).lower() if isinstance(raw, bool) else str(raw)
        if not re.fullmatch(r"[A-Za-z0-9._:/ -]{0,200}", value) or "\n" in value:
            _fail(f"unsafe workflow output {key}")
        lines.append(f"{key}={value}\n")
    with path.open("a", encoding="utf-8") as stream:
        stream.writelines(lines)


def _locate_outputs(identity: PullIdentity) -> dict[str, Any]:
    return {
        "eligible": True,
        "pr_number": identity.number,
        "merge_sha": identity.merge_sha,
        "head_sha": identity.head_sha,
    }


def _source_outputs(identity: PullIdentity) -> dict[str, Any]:
    """Bounded identity exported to a protected PRT gate before candidate checkout."""

    return {
        "eligible": True,
        "pr_number": identity.number,
        "default_branch": identity.default_branch,
        "default_sha": identity.default_sha,
        "base_branch": identity.base_branch,
        "base_sha": identity.base_sha,
        "head_branch": identity.head_branch,
        "head_sha": identity.head_sha,
        "merge_sha": identity.merge_sha,
        "merge_tree": identity.merge_tree,
    }


def _evaluation_outputs(value: dict[str, Any]) -> dict[str, Any]:
    outputs: dict[str, Any] = {
        "eligible": value["eligible"],
        "pr_number": value["pull_request"],
        "default_branch": value["default_branch"],
        "head_sha": value["head_sha"],
        "head_branch": value["head_branch"],
        "merge_sha": value["merge_sha"],
        "merge_tree": value["merge_tree"],
        "base_branch": value["base_branch"],
        "base_sha": value["base_sha"],
        "default_sha": value["default_sha"],
        "policy_mode": value["policy_mode"],
        "authorization_digest": value["authorization_digest"],
        "authorization_comment_id": value["authorization_comment_id"],
    }
    for kind in ("build", "e2e"):
        gate = value["gates"][kind]
        for field in ("state", "description", "run_id", "run_attempt"):
            outputs[f"{kind}_{field}"] = gate[field]
    return outputs


def _reauthorization_outputs(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "eligible": value["eligible"],
        "authorization_current": value["authorization_current"],
        "pr_number": value["pull_request"],
        "head_sha": value["head_sha"],
        "policy_mode": value["policy_mode"],
    }


def _add_locator_arguments(parser: argparse.ArgumentParser) -> None:
    locator = parser.add_mutually_exclusive_group(required=True)
    locator.add_argument("--trigger-run-id", type=int)
    locator.add_argument("--pr-number", type=int)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    locate = commands.add_parser("locate")
    locate.add_argument("--repository-name", required=True)
    _add_locator_arguments(locate)
    locate.add_argument("--implementation-sha", required=True)
    locate.add_argument("--github-output", type=Path)
    source = commands.add_parser("resolve-source")
    source.add_argument("--repository-name", required=True)
    source.add_argument("--implementation-sha", required=True)
    source.add_argument("--pr-number", type=int, required=True)
    source.add_argument("--github-output", type=Path)
    dispatch_source = commands.add_parser("resolve-dispatch-source")
    dispatch_source.add_argument("--repository-name", required=True)
    dispatch_source.add_argument("--implementation-sha", required=True)
    dispatch_source.add_argument("--expected-source-sha", required=True)
    dispatch_source.add_argument("--target-branch", required=True)
    dispatch_source.add_argument("--expected-target-sha", required=True)
    dispatch_source.add_argument("--candidate-branch", required=True)
    dispatch_source.add_argument("--expected-candidate-sha", required=True)
    dispatch_source.add_argument("--expected-candidate-tree", required=True)
    dispatch_source.add_argument("--github-output", type=Path)
    assess = commands.add_parser("evaluate")
    assess.add_argument("--repository-name", required=True)
    assess.add_argument("--repository", type=Path, required=True)
    _add_locator_arguments(assess)
    assess.add_argument("--implementation-sha", required=True)
    assess.add_argument("--expected-pr-number", type=int, required=True)
    assess.add_argument("--expected-merge-sha", required=True)
    assess.add_argument("--github-output", type=Path)
    final = commands.add_parser("reauthorize")
    final.add_argument("--repository-name", required=True)
    final.add_argument("--implementation-sha", required=True)
    final.add_argument("--expected-pr-number", type=int, required=True)
    final.add_argument("--expected-default-branch", required=True)
    final.add_argument("--expected-default-sha", required=True)
    final.add_argument("--expected-base-branch", required=True)
    final.add_argument("--expected-base-sha", required=True)
    final.add_argument("--expected-head-branch", required=True)
    final.add_argument("--expected-head-sha", required=True)
    final.add_argument("--expected-merge-sha", required=True)
    final.add_argument("--expected-merge-tree", required=True)
    final.add_argument("--expected-policy-mode", required=True)
    final.add_argument("--expected-authorization-digest", required=True)
    final.add_argument("--expected-authorization-comment-id", type=int, required=True)
    final.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    try:
        api = GitHubApi(
            repository=args.repository_name,
            token=os.environ.get("GITHUB_TOKEN", ""),
            api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        )
        if args.command == "locate":
            identity = resolve_pull_identity(
                api,
                trigger_run_id=args.trigger_run_id,
                pr_number=args.pr_number,
                implementation_sha=args.implementation_sha,
            )
            value: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION,
                **_locate_outputs(identity),
            }
            outputs = _locate_outputs(identity)
        elif args.command == "resolve-source":
            identity = resolve_pull_identity(
                api,
                pr_number=args.pr_number,
                implementation_sha=args.implementation_sha,
            )
            outputs = _source_outputs(identity)
            value = {
                "schema_version": SCHEMA_VERSION,
                **outputs,
            }
        elif args.command == "resolve-dispatch-source":
            identity = resolve_dispatch_source(
                api,
                implementation_sha=args.implementation_sha,
                expected_source_sha=args.expected_source_sha,
                target_branch=args.target_branch,
                expected_target_sha=args.expected_target_sha,
                candidate_branch=args.candidate_branch,
                expected_candidate_sha=args.expected_candidate_sha,
                expected_candidate_tree=args.expected_candidate_tree,
            )
            outputs = _source_outputs(identity)
            value = {
                "schema_version": SCHEMA_VERSION,
                **outputs,
            }
        elif args.command == "evaluate":
            value = evaluate(
                api,
                repository=args.repository,
                trigger_run_id=args.trigger_run_id,
                pr_number=args.pr_number,
                implementation_sha=args.implementation_sha,
                expected_pr_number=args.expected_pr_number,
                expected_merge_sha=args.expected_merge_sha,
            )
            outputs = _evaluation_outputs(value)
        else:
            value = reauthorize(
                api,
                implementation_sha=args.implementation_sha,
                expected_pr_number=args.expected_pr_number,
                expected_default_branch=args.expected_default_branch,
                expected_default_sha=args.expected_default_sha,
                expected_base_branch=args.expected_base_branch,
                expected_base_sha=args.expected_base_sha,
                expected_head_branch=args.expected_head_branch,
                expected_head_sha=args.expected_head_sha,
                expected_merge_sha=args.expected_merge_sha,
                expected_merge_tree=args.expected_merge_tree,
                expected_policy_mode=args.expected_policy_mode,
                expected_authorization_digest=args.expected_authorization_digest,
                expected_authorization_comment_id=args.expected_authorization_comment_id,
            )
            outputs = _reauthorization_outputs(value)
        if args.github_output is not None:
            _append_outputs(args.github_output, outputs)
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    except NotEligible as exc:
        if args.command in {"resolve-source", "resolve-dispatch-source"}:
            print(f"trusted gate source is ineligible: {exc}", file=sys.stderr)
            return 2
        if args.github_output is not None:
            _append_outputs(args.github_output, {"eligible": False})
        print(f"trusted PR gate is ineligible: {exc}", file=sys.stderr)
        return 0
    except (GateControllerError, JobGraphError, MatrixError, OSError, PrGateError) as exc:
        print(f"trusted PR gate error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
