"""Relationship registry: which entity pairs each edge kind may connect.

One :class:`RelationshipSpec` per :class:`RelationshipType`. The registry is
the single source for the published ``/v1/graph/schema`` edge metadata and for
the write-time contract check in :mod:`agent_bom.graph.relationship_contract`.

``allowed_pairs`` is explicit: the cartesian product of the documented source
and target kinds plus ``extra`` pairs that real producers emit outside that
product. A pair that is not listed is a contract violation, never a silently
accepted edge.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from itertools import product

from agent_bom.graph.types import EntityType, RelationshipType

E = EntityType
R = RelationshipType


class TraversalClass(str, Enum):
    """What kind of claim an edge makes; decides how path analysis may use it."""

    STRUCTURAL = "structural"
    DEPENDENCY = "dependency"
    AUTHORITY = "authority"
    EXPOSURE = "exposure"
    FINDING = "finding"
    RUNTIME = "runtime"
    CORRELATION = "correlation"
    DERIVED = "derived"
    GOVERNANCE = "governance"


DEFAULT_REQUIRED_EVIDENCE: tuple[str, ...] = ("source", "tier")


@dataclass(frozen=True, slots=True)
class RelationshipSpec:
    rel: RelationshipType
    traversal_class: TraversalClass
    allowed_pairs: frozenset[tuple[EntityType, EntityType]]
    direction: str
    default_traversable: bool
    symmetric: bool
    required_evidence: tuple[str, ...]
    category: str
    source_types: tuple[EntityType, ...]
    target_types: tuple[EntityType, ...]

    def allows(self, source: EntityType, target: EntityType) -> bool:
        if (source, target) in self.allowed_pairs:
            return True
        return self.symmetric and (target, source) in self.allowed_pairs


def _ordered(values: list[EntityType]) -> tuple[EntityType, ...]:
    return tuple(dict.fromkeys(values))


def _spec(
    rel: RelationshipType,
    traversal_class: TraversalClass,
    category: str,
    sources: tuple[EntityType, ...],
    targets: tuple[EntityType, ...],
    *,
    extra: tuple[tuple[EntityType, EntityType], ...] = (),
    direction: str = "directed",
    traversable: bool = True,
    required: tuple[str, ...] = DEFAULT_REQUIRED_EVIDENCE,
) -> RelationshipSpec:
    pairs = frozenset(product(sources, targets)) | frozenset(extra)
    return RelationshipSpec(
        rel=rel,
        traversal_class=traversal_class,
        allowed_pairs=pairs,
        direction=direction,
        default_traversable=traversable,
        symmetric=direction == "bidirectional",
        required_evidence=required,
        category=category,
        source_types=_ordered([*sources, *(pair[0] for pair in extra)]),
        target_types=_ordered([*targets, *(pair[1] for pair in extra)]),
    )


T = TraversalClass
_HUMAN_AND_WORKLOAD = (E.USER, E.SERVICE_ACCOUNT, E.SERVICE_PRINCIPAL, E.FEDERATED_IDENTITY)
_PRINCIPALS = (E.USER, E.GROUP, E.ROLE, E.SERVICE_ACCOUNT, E.SERVICE_PRINCIPAL)
_CLOUD_ASSETS = (E.CLOUD_RESOURCE, E.DATA_STORE, E.API_GATEWAY)
_FINDINGS = (E.VULNERABILITY, E.MISCONFIGURATION)
_WORKLOADS = (E.AGENT, E.SERVER, E.CONTAINER, E.CLUSTER, E.MODEL, E.CLOUD_RESOURCE)
_WORKLOAD_IDENTITIES = (E.ROLE, E.SERVICE_ACCOUNT, E.SERVICE_PRINCIPAL)
# Inventory kinds a scope (environment) holds and a posture finding can name.
_ASSETS = (
    *_WORKLOADS,
    *_WORKLOAD_IDENTITIES,
    E.DATA_STORE,
    E.DATASET,
    E.API_GATEWAY,
    E.APPLICATION,
    E.TOOL,
    E.PACKAGE,
    E.FRAMEWORK,
    E.CONFIG_FILE,
    E.CI_JOB,
    E.ACCESS_POLICY,
)
_TRACE_ASSETS = (*_ASSETS, E.USER)
_ACCESSIBLE = (
    E.DATA_STORE,
    E.DATASET,
    E.CLUSTER,
    E.CONTAINER,
    E.MODEL,
    E.SERVER,
    E.AGENT,
    E.CONFIG_FILE,
    E.CLOUD_RESOURCE,
    E.RESOURCE,
    E.API_GATEWAY,
)

_SPECS: tuple[RelationshipSpec, ...] = (
    _spec(
        R.HOSTS,
        T.STRUCTURAL,
        "inventory",
        (E.PROVIDER, E.ENVIRONMENT, E.FLEET, E.ACCOUNT, E.CLOUD_RESOURCE),
        (E.ACCOUNT, E.ORG, E.AGENT, E.SERVER, E.CLOUD_RESOURCE),
    ),
    # A workload runs on its host: an agent or server in a container or on a
    # VM, a container (pod) on a node VM, a cluster or a managed fleet. The
    # structural rollup stays HOSTS; this is the runtime dependency paths walk.
    _spec(
        R.HOSTED_ON,
        T.DEPENDENCY,
        "inventory",
        (E.AGENT, E.SERVER, E.CONTAINER),
        (E.CONTAINER, E.CLUSTER, E.CLOUD_RESOURCE, E.FLEET),
    ),
    _spec(R.USES, T.DEPENDENCY, "inventory", (E.AGENT,), (E.SERVER,)),
    _spec(R.USES_FRAMEWORK, T.DEPENDENCY, "inventory", (E.AGENT,), (E.FRAMEWORK,)),
    _spec(
        R.DEPENDS_ON,
        T.DEPENDENCY,
        "inventory",
        (E.SERVER, E.CONTAINER, E.CONFIG_FILE, E.SOURCE_FILE, E.FRAMEWORK),
        (E.PACKAGE,),
        # Image layering, a manifest directory's packages, and service/data lineage
        # (an external table reads the bucket behind it).
        extra=(
            # A recorded parent package pulls in its child (one edge per pair; no closure).
            (E.PACKAGE, E.PACKAGE),
            (E.CONTAINER, E.CONTAINER),
            (E.DIRECTORY, E.PACKAGE),
            (E.CLOUD_RESOURCE, E.CLOUD_RESOURCE),
            (E.DATA_STORE, E.DATA_STORE),
            (E.DATA_STORE, E.CLOUD_RESOURCE),
        ),
    ),
    _spec(R.PROVIDES_TOOL, T.STRUCTURAL, "inventory", (E.SERVER,), (E.TOOL,)),
    _spec(R.EXPOSES_CRED, T.AUTHORITY, "inventory", (E.SERVER, E.AGENT), (E.CREDENTIAL,)),
    _spec(R.REACHES_TOOL, T.AUTHORITY, "inventory", (E.CREDENTIAL, E.AGENT), (E.TOOL,)),
    _spec(R.SERVES_MODEL, T.DEPENDENCY, "inventory", (E.SERVER, E.AGENT, E.FRAMEWORK, E.CONTAINER), (E.MODEL,)),
    _spec(R.OBSERVES, T.STRUCTURAL, "inventory", (E.FRAMEWORK,), (E.AGENT, E.SERVER)),
    _spec(
        R.CONTAINS,
        T.STRUCTURAL,
        "inventory",
        (E.CONTAINER, E.CLUSTER, E.FLEET, E.DIRECTORY),
        (E.PACKAGE, E.SERVER, E.CONTAINER, E.DIRECTORY, E.SOURCE_FILE, E.CONFIG_FILE),
        extra=(
            # An agent workload runs inside its container, as a server does.
            (E.CONTAINER, E.AGENT),
            # Kubernetes: a cluster holds namespaces; a namespace holds its workloads and service accounts.
            (E.CLUSTER, E.RESOURCE),
            (E.RESOURCE, E.CONTAINER),
            (E.RESOURCE, E.SERVICE_ACCOUNT),
            # A project agent contains the framework graphs its source declares.
            (E.AGENT, E.AGENT),
            # Organization hierarchy: a parent organization nests sub-organizations.
            (E.ORG, E.ORG),
            # Warehouse hierarchy (database -> schema) and a directory's code modules.
            (E.DATA_STORE, E.DATA_STORE),
            (E.DIRECTORY, E.CODE_MODULE),
            (E.ORG, E.ACCOUNT),
            (E.ACCOUNT, E.ENVIRONMENT),
            (E.ACCOUNT, E.APPLICATION),
            (E.CLOUD_RESOURCE, E.CLOUD_RESOURCE),
            (E.SOURCE_FILE, E.PACKAGE),
            # A side-scanned VM disk or machine image holds the OS packages read from it.
            (E.CLOUD_RESOURCE, E.PACKAGE),
            *((E.ACCOUNT, target) for target in _CLOUD_ASSETS),
            *((E.ENVIRONMENT, target) for target in _ASSETS),
            # Roll-up containment: a posture finding sits under the asset it names.
            *((asset, finding) for asset in _ASSETS for finding in _FINDINGS),
        ),
    ),
    _spec(R.IMPORTS, T.DEPENDENCY, "code_topology", (E.SOURCE_FILE, E.CODE_MODULE), (E.EXTERNAL_IMPORT, E.CODE_MODULE, E.PACKAGE)),
    _spec(R.DEFINES, T.STRUCTURAL, "code_topology", (E.SOURCE_FILE,), (E.CODE_MODULE, E.TOOL, E.CI_JOB)),
    _spec(R.RUNS, T.STRUCTURAL, "code_topology", (E.CI_JOB,), (E.TOOL, E.SERVER, E.AGENT)),
    _spec(R.CONFIGURES, T.STRUCTURAL, "code_topology", (E.CONFIG_FILE,), (E.AGENT, E.SERVER, E.CI_JOB, E.TOOL)),
    _spec(
        R.AFFECTS,
        T.FINDING,
        "vulnerability",
        _FINDINGS,
        (E.PACKAGE, E.SERVER, E.CONTAINER, E.SOURCE_FILE, E.CONFIG_FILE),
        # Posture findings also name account- and organization-scope settings, and a
        # hardware advisory names the firmware / accelerator resource it affects.
        extra=(
            *((E.MISCONFIGURATION, target) for target in (*_ASSETS, E.CLOUD_RESOURCE, E.ACCOUNT, E.ORG)),
            (E.VULNERABILITY, E.RESOURCE),
        ),
    ),
    _spec(
        R.VULNERABLE_TO,
        T.FINDING,
        "vulnerability",
        (E.PACKAGE, E.SERVER, E.CONTAINER, E.AGENT, E.CREDENTIAL, E.CREDENTIAL_REF, E.TOOL, E.CLOUD_RESOURCE, E.ROLE, E.DIRECTORY),
        _FINDINGS,
    ),
    _spec(R.EXPLOITABLE_VIA, T.FINDING, "vulnerability", _FINDINGS, (E.TOOL, E.CREDENTIAL)),
    _spec(R.REMEDIATES, T.FINDING, "vulnerability", (E.PACKAGE,), _FINDINGS, traversable=False),
    _spec(R.TRIGGERS, T.FINDING, "vulnerability", (E.VULNERABILITY,), (E.MISCONFIGURATION,)),
    _spec(R.SHARES_SERVER, T.CORRELATION, "lateral_movement", (E.AGENT,), (E.AGENT,), direction="bidirectional", traversable=False),
    _spec(R.SHARES_CRED, T.CORRELATION, "lateral_movement", (E.AGENT,), (E.AGENT,), direction="bidirectional", traversable=False),
    _spec(R.LATERAL_PATH, T.DERIVED, "lateral_movement", (E.AGENT,), (E.AGENT,)),
    _spec(
        R.MANAGES,
        T.GOVERNANCE,
        "governance",
        (*_PRINCIPALS, E.FEDERATED_IDENTITY),
        (E.AGENT, E.FLEET, E.ENVIRONMENT, E.CLOUD_RESOURCE),
    ),
    _spec(
        R.OWNS,
        T.GOVERNANCE,
        "governance",
        (E.ORG, E.ACCOUNT, *_PRINCIPALS),
        (E.ENVIRONMENT, E.CLOUD_RESOURCE, E.AGENT),
        extra=(
            (E.ACCOUNT, E.DATA_STORE),
            (E.ACCOUNT, E.API_GATEWAY),
            *((E.ACCOUNT, principal) for principal in _PRINCIPALS),
            # Organization / account guardrail policies (SCPs, management-group policy).
            (E.ORG, E.POLICY),
            (E.ACCOUNT, E.POLICY),
        ),
    ),
    _spec(
        R.PART_OF,
        T.STRUCTURAL,
        "governance",
        (E.ACCOUNT, E.AGENT, E.SERVER, E.CONTAINER),
        (E.ORG, E.FLEET, E.CLUSTER, E.ENVIRONMENT),
        # A hardware component (firmware, accelerator) is part of its host.
        extra=((E.CLOUD_RESOURCE, E.CLOUD_RESOURCE), (E.CI_JOB, E.APPLICATION), (E.TOOL, E.SERVER), (E.RESOURCE, E.RESOURCE)),
    ),
    _spec(
        R.MEMBER_OF,
        T.AUTHORITY,
        "governance",
        (*_PRINCIPALS, E.FEDERATED_IDENTITY, E.AGENT),
        (E.ACCOUNT, E.GROUP, E.AGENT, E.FLEET),
        # RBAC role grants (a user granted a role) and identities homed in an account.
        extra=((E.USER, E.ROLE), (E.ROLE, E.ROLE), (E.MANAGED_IDENTITY, E.ACCOUNT)),
    ),
    _spec(
        R.ASSUMES,
        T.AUTHORITY,
        "identity",
        _HUMAN_AND_WORKLOAD,
        (E.ROLE,),
        extra=(*product(_WORKLOADS, (*_WORKLOAD_IDENTITIES, E.MANAGED_IDENTITY)), (E.ROLE, E.ROLE)),
    ),
    _spec(
        R.TRUSTS,
        T.AUTHORITY,
        "identity",
        (E.ROLE, E.ACCOUNT),
        (E.ACCOUNT, *_PRINCIPALS, E.FEDERATED_IDENTITY),
    ),
    _spec(
        R.ATTACHED,
        T.AUTHORITY,
        "identity",
        (*_PRINCIPALS, E.MANAGED_IDENTITY),
        (E.POLICY, E.ACCESS_GRANT),
    ),
    _spec(R.INHERITS, T.AUTHORITY, "identity", _PRINCIPALS, (E.POLICY, E.ROLE)),
    _spec(
        R.CAN_ACCESS,
        T.AUTHORITY,
        "identity",
        (E.ACCOUNT, *_PRINCIPALS, E.FEDERATED_IDENTITY),
        (E.CLOUD_RESOURCE, E.DATASET, E.CREDENTIAL, E.RESOURCE),
        extra=(
            *product((*_PRINCIPALS, *_WORKLOADS, E.APPLICATION, E.TOOL, E.MANAGED_IDENTITY), _ACCESSIBLE),
            # A Kubernetes workload mounts or references a named Secret.
            (E.CONTAINER, E.CREDENTIAL),
            # Principal-to-principal reach (impersonation, pass-role, managed-identity attach).
            *product((*_WORKLOAD_IDENTITIES, E.MANAGED_IDENTITY), (*_WORKLOAD_IDENTITIES, E.MANAGED_IDENTITY)),
        ),
    ),
    _spec(
        R.CROSS_ACCOUNT_TRUST,
        T.AUTHORITY,
        "identity",
        (E.ACCOUNT, E.ROLE, E.SERVICE_PRINCIPAL, E.FEDERATED_IDENTITY),
        (E.ACCOUNT, E.ROLE, E.SERVICE_PRINCIPAL, E.FEDERATED_IDENTITY),
    ),
    _spec(R.ACTED_AS, T.RUNTIME, "runtime", _HUMAN_AND_WORKLOAD, (E.AGENT,)),
    _spec(
        R.INVOKED,
        T.RUNTIME,
        "runtime",
        (E.AGENT, E.USER),
        (E.TOOL, E.TOOL_CALL),
        # Cloud audit trails record principals invoking provider APIs on resources.
        extra=tuple((principal, E.CLOUD_RESOURCE) for principal in (*_HUMAN_AND_WORKLOAD, E.ROLE)),
    ),
    _spec(R.CALLED, T.RUNTIME, "runtime", (E.TOOL_CALL, E.AGENT), (E.TOOL, E.SERVER)),
    _spec(R.USED_CREDENTIAL, T.RUNTIME, "runtime", (E.TOOL_CALL, E.AGENT, E.TOOL), (E.CREDENTIAL_REF, E.CREDENTIAL)),
    _spec(
        R.ACCESSED,
        T.RUNTIME,
        "runtime",
        (E.TOOL, E.TOOL_CALL),
        (E.CLOUD_RESOURCE, E.DATASET, E.CREDENTIAL, E.CREDENTIAL_REF, E.RESOURCE),
        # Audit trails and warehouse access history record principals touching data.
        extra=tuple(product((*_HUMAN_AND_WORKLOAD, E.ROLE, E.AGENT), (E.CLOUD_RESOURCE, E.DATA_STORE, E.DATASET, E.RESOURCE))),
    ),
    _spec(R.DELEGATED_TO, T.RUNTIME, "runtime", (E.AGENT,), (E.AGENT,)),
    # Consecutive assets one correlated trace touched, across vendors' audit logs.
    _spec(R.TRACE_STEP, T.RUNTIME, "runtime", _TRACE_ASSETS, _TRACE_ASSETS),
    _spec(
        R.RECORDED_ACTIVITY,
        T.CORRELATION,
        "runtime",
        (*_HUMAN_AND_WORKLOAD, E.AGENT, E.SERVER, E.TOOL_CALL, E.RESOURCE, E.MANAGED_IDENTITY, E.ROLE),
        (*_TRACE_ASSETS, E.RESOURCE, E.CREDENTIAL, E.CREDENTIAL_REF, E.TOOL_CALL, E.POLICY),
        traversable=False,
    ),
    _spec(
        R.CORRELATES_WITH,
        T.CORRELATION,
        "correlation",
        (E.AGENT, E.SERVER),
        (E.AGENT, E.SERVER),
        direction="bidirectional",
        traversable=False,
    ),
    # A candidate is never a merge: weak identity signals (host name, address,
    # name within an account) propose that two workloads, identities or data
    # stores may be one asset. Pairs stay within one asset family.
    _spec(
        R.POSSIBLY_CORRELATES_WITH,
        T.CORRELATION,
        "correlation",
        (E.AGENT, E.SERVER),
        (E.AGENT, E.SERVER),
        extra=(
            *product((E.CLOUD_RESOURCE, E.CLUSTER, E.CONTAINER), (E.CLOUD_RESOURCE, E.CLUSTER, E.CONTAINER)),
            *product(_WORKLOAD_IDENTITIES + (E.USER, E.MANAGED_IDENTITY), _WORKLOAD_IDENTITIES + (E.USER, E.MANAGED_IDENTITY)),
            (E.DATA_STORE, E.DATA_STORE),
        ),
        direction="bidirectional",
        traversable=False,
    ),
    # An agent runs as a workload identity; a credential is that identity's auth material.
    _spec(
        R.AUTHENTICATES_AS,
        T.AUTHORITY,
        "governance",
        (E.AGENT, E.CREDENTIAL),
        (E.MANAGED_IDENTITY, E.SERVICE_ACCOUNT, E.SERVICE_PRINCIPAL),
        extra=((E.CREDENTIAL, E.ROLE),),
    ),
    _spec(R.SCOPED_TO, T.GOVERNANCE, "governance", (E.MANAGED_IDENTITY, E.ACCESS_GRANT, E.DRIFT_INCIDENT), (E.TOOL,)),
    _spec(
        R.GOVERNS,
        T.GOVERNANCE,
        "governance",
        # Access policies, guardrail policies (SCPs on an org root / OU / account) and
        # approved AI-system blueprints govern their targets and what drifts from them.
        (E.ACCESS_POLICY, E.BLUEPRINT),
        (E.AGENT, E.MANAGED_IDENTITY, E.TOOL, E.DRIFT_INCIDENT),
        extra=((E.POLICY, E.ORG), (E.POLICY, E.ACCOUNT)),
        traversable=False,
    ),
    _spec(R.EXHIBITS_DRIFT, T.GOVERNANCE, "governance", (E.AGENT,), (E.DRIFT_INCIDENT,), direction="bidirectional"),
    _spec(
        R.EXPOSED_TO,
        T.EXPOSURE,
        "exposure",
        (E.CLOUD_RESOURCE, E.SERVER, E.AGENT, E.DATA_STORE, E.CONTAINER, E.API_GATEWAY),
        (E.CLOUD_RESOURCE, E.RESOURCE, E.DATA_STORE),
        # A front door (firewall, Kubernetes Service) exposing the workload behind
        # it, and a data share exposing data to an external account.
        extra=((E.SERVER, E.AGENT), (E.DATA_STORE, E.ACCOUNT)),
    ),
    _spec(R.STORES, T.STRUCTURAL, "exposure", (E.CLOUD_RESOURCE, E.RESOURCE, E.DATA_STORE, E.SERVER), (E.DATASET, E.DATA_STORE)),
    _spec(
        R.HAS_PERMISSION,
        T.AUTHORITY,
        "identity",
        (E.USER, E.GROUP, E.ROLE, E.SERVICE_ACCOUNT, E.SERVICE_PRINCIPAL, E.MANAGED_IDENTITY),
        # Grants scoped to a whole subscription / project / organization (or a Kubernetes cluster) land on it.
        (E.CLOUD_RESOURCE, E.DATA_STORE, E.RESOURCE, E.TOOL, E.ACCOUNT, E.ORG, E.CLUSTER),
    ),
    _spec(
        R.PROTECTS,
        T.GOVERNANCE,
        "exposure",
        (E.API_GATEWAY, E.CLOUD_RESOURCE),
        (E.CLOUD_RESOURCE, E.DATA_STORE, E.RESOURCE),
        traversable=False,
    ),
    _spec(
        R.BELONGS_TO,
        T.STRUCTURAL,
        "aspm",
        (*_FINDINGS, E.PACKAGE, E.CONTAINER, E.CLOUD_RESOURCE, E.SERVER, E.CREDENTIAL),
        (E.APPLICATION,),
    ),
)

RELATIONSHIP_SPECS: dict[RelationshipType, RelationshipSpec] = {spec.rel: spec for spec in _SPECS}


def relationship_spec(rel: RelationshipType | str) -> RelationshipSpec | None:
    try:
        return RELATIONSHIP_SPECS.get(RelationshipType(rel))
    except ValueError:
        return None
