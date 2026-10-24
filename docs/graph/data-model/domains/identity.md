# Identity and access: entity relationships

> Generated from the code by `scripts/generate_graph_data_model.py`. Do not edit by hand: re-run the
> generator and commit the result. CI runs it with `--check` and fails on drift.

Entity types in the identity and access domain and the relationships allowed between them. A line means the relationship is allowed between the two types; cardinality is not modelled. Back to the [data model](../../DATA_MODEL.md) · [all relationship pairs](../relationships.md).

## Inside the domain

### Structure: what contains, depends on or governs what

```mermaid
erDiagram
  access_policy }o--o{ managed_identity : "governs"
  account }o--o{ account : "hosts"
  account }o--o{ group : "owns"
  account }o--o{ org : "contains, hosts, part_of"
  account }o--o{ policy : "governs, owns"
  account }o--o{ role : "owns"
  account }o--o{ service_account : "owns"
  account }o--o{ service_principal : "owns"
  account }o--o{ user : "owns"
  org }o--o{ org : "contains"
  org }o--o{ policy : "governs, owns"
```

### Authority: who can act on what

54 type pairs, too many to draw legibly. Read a row as *source → relationship → target*.

| Source ↓ / target → | `access_grant` | `account` | `credential` | `federated_identity` | `group` | `managed_identity` | `org` | `policy` | `role` | `service_account` | `service_principal` | `user` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `account` |  | cross_account_trust<br/>trusts | can_access | cross_account_trust<br/>trusts | trusts |  |  |  | cross_account_trust<br/>trusts | trusts | cross_account_trust<br/>trusts | trusts |
| `credential` |  |  |  |  |  | authenticates_as |  |  | authenticates_as | authenticates_as | authenticates_as |  |
| `federated_identity` |  | cross_account_trust<br/>member_of | can_access | cross_account_trust | member_of |  |  |  | assumes<br/>cross_account_trust |  | cross_account_trust |  |
| `group` | attached | has_permission<br/>member_of | can_access |  | member_of |  | has_permission | attached<br/>inherits | inherits |  |  |  |
| `managed_identity` | attached | has_permission<br/>member_of |  |  |  | can_access | has_permission | attached | can_access | can_access | can_access |  |
| `role` | attached | cross_account_trust<br/>has_permission<br/>member_of<br/>trusts | can_access | cross_account_trust<br/>trusts | member_of<br/>trusts | can_access | has_permission | attached<br/>inherits | assumes<br/>can_access<br/>cross_account_trust<br/>inherits<br/>member_of<br/>trusts | can_access<br/>trusts | can_access<br/>cross_account_trust<br/>trusts | trusts |
| `service_account` | attached | has_permission<br/>member_of | can_access |  | member_of | can_access | has_permission | attached<br/>inherits | assumes<br/>can_access<br/>inherits | can_access | can_access |  |
| `service_principal` | attached | cross_account_trust<br/>has_permission<br/>member_of | can_access | cross_account_trust | member_of | can_access | has_permission | attached<br/>inherits | assumes<br/>can_access<br/>cross_account_trust<br/>inherits | can_access | can_access<br/>cross_account_trust |  |
| `user` | attached | has_permission<br/>member_of | can_access |  | member_of |  | has_permission | attached<br/>inherits | assumes<br/>inherits<br/>member_of |  |  |  |

Not drawn, because they can connect almost any two types: `possibly_correlates_with`, `trace_step`. They are listed in the tables below.

## Relationship reference

### Inside the domain

| Relationship | Class | Traversable | From | To |
|---|---|---|---|---|
| `assumes` | `authority` | yes | `federated_identity`, `role`, `service_account`, `service_principal`, `user` | `role` |
| `attached` | `authority` | yes | `group`, `managed_identity`, `role`, `service_account`, `service_principal`, `user` | `access_grant`, `policy` |
| `authenticates_as` | `authority` | yes | `credential` | `managed_identity`, `role`, `service_account`, `service_principal` |
| `can_access` | `authority` | yes | `account`, `federated_identity`, `group`, `managed_identity`, `role`, `service_account`, `service_principal`, `user` | `credential`, `managed_identity`, `role`, `service_account`, `service_principal` |
| `contains` | `structural` | yes | `org` | `account`, `org` |
| `cross_account_trust` | `authority` | yes | `account`, `federated_identity`, `role`, `service_principal` | `account`, `federated_identity`, `role`, `service_principal` |
| `governs` | `governance` | no | `access_policy`, `policy` | `account`, `managed_identity`, `org` |
| `has_permission` | `authority` | yes | `group`, `managed_identity`, `role`, `service_account`, `service_principal`, `user` | `account`, `org` |
| `hosts` | `structural` | yes | `account` | `account`, `org` |
| `inherits` | `authority` | yes | `group`, `role`, `service_account`, `service_principal`, `user` | `policy`, `role` |
| `member_of` | `authority` | yes | `federated_identity`, `group`, `managed_identity`, `role`, `service_account`, `service_principal`, `user` | `account`, `group`, `role` |
| `owns` | `governance` | yes | `account`, `org` | `group`, `policy`, `role`, `service_account`, `service_principal`, `user` |
| `part_of` | `structural` | yes | `account` | `org` |
| `possibly_correlates_with` | `correlation` | no | `managed_identity`, `role`, `service_account`, `service_principal`, `user` | `managed_identity`, `role`, `service_account`, `service_principal`, `user` |
| `trace_step` | `runtime` | yes | `access_policy`, `role`, `service_account`, `service_principal`, `user` | `access_policy`, `role`, `service_account`, `service_principal`, `user` |
| `trusts` | `authority` | yes | `account`, `role` | `account`, `federated_identity`, `group`, `role`, `service_account`, `service_principal`, `user` |

### Across domains

| Relationship | Class | Traversable | From | To |
|---|---|---|---|---|
| `accessed` | `runtime` | yes | `federated_identity`, `role`, `service_account`, `service_principal`, `user`<br/>AI and agents: `tool`, `tool_call` | `credential`, `credential_ref`<br/>Cloud, infrastructure and data: `cloud_resource`, `data_store`, `dataset`, `resource` |
| `acted_as` | `runtime` | yes | `federated_identity`, `service_account`, `service_principal`, `user` | AI and agents: `agent` |
| `affects` | `finding` | yes | Findings: `misconfiguration` | `access_policy`, `account`, `org`, `role`, `service_account`, `service_principal` |
| `assumes` | `authority` | yes | AI and agents: `agent`, `server`<br/>Cloud, infrastructure and data: `cloud_resource`, `cluster`, `container`, `model` | `managed_identity`, `role`, `service_account`, `service_principal` |
| `authenticates_as` | `authority` | yes | AI and agents: `agent` | `managed_identity`, `service_account`, `service_principal` |
| `belongs_to` | `structural` | yes | `credential` | AI and agents: `application` |
| `can_access` | `authority` | yes | `account`, `federated_identity`, `group`, `managed_identity`, `role`, `service_account`, `service_principal`, `user` | AI and agents: `agent`, `server`<br/>Cloud, infrastructure and data: `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `model`, `resource`<br/>Code and supply chain: `config_file` |
| `contains` | `structural` | yes | `access_policy`, `account`, `role`, `service_account`, `service_principal`<br/>Cloud, infrastructure and data: `environment` | `access_policy`, `role`, `service_account`, `service_principal`<br/>Cloud, infrastructure and data: `api_gateway`, `cloud_resource`, `data_store`, `environment`<br/>AI and agents: `application`<br/>Findings: `misconfiguration`, `vulnerability` |
| `exploitable_via` | `finding` | yes | Findings: `misconfiguration`, `vulnerability` | `credential` |
| `exposed_to` | `exposure` | yes | Cloud, infrastructure and data: `data_store` | `account` |
| `exposes_cred` | `authority` | yes | AI and agents: `agent`, `server` | `credential` |
| `governs` | `governance` | no | `access_policy`<br/>AI and agents: `blueprint` | `managed_identity`<br/>AI and agents: `agent`, `tool`<br/>Findings: `drift_incident` |
| `has_permission` | `authority` | yes | `group`, `managed_identity`, `role`, `service_account`, `service_principal`, `user` | Cloud, infrastructure and data: `cloud_resource`, `data_store`, `resource`<br/>AI and agents: `tool` |
| `hosts` | `structural` | yes | `account`<br/>Cloud, infrastructure and data: `cloud_resource`, `environment`, `fleet`, `provider` | `account`, `org`<br/>AI and agents: `agent`, `server`<br/>Cloud, infrastructure and data: `cloud_resource` |
| `invoked` | `runtime` | yes | `federated_identity`, `role`, `service_account`, `service_principal`, `user` | Cloud, infrastructure and data: `cloud_resource`<br/>AI and agents: `tool`, `tool_call` |
| `manages` | `governance` | yes | `federated_identity`, `group`, `role`, `service_account`, `service_principal`, `user` | AI and agents: `agent`<br/>Cloud, infrastructure and data: `cloud_resource`, `environment`, `fleet` |
| `member_of` | `authority` | yes | `federated_identity`, `group`, `role`, `service_account`, `service_principal`, `user`<br/>AI and agents: `agent` | `account`, `group`<br/>AI and agents: `agent`<br/>Cloud, infrastructure and data: `fleet` |
| `owns` | `governance` | yes | `account`, `group`, `org`, `role`, `service_account`, `service_principal`, `user` | AI and agents: `agent`<br/>Cloud, infrastructure and data: `api_gateway`, `cloud_resource`, `data_store`, `environment` |
| `part_of` | `structural` | yes | `account`<br/>AI and agents: `agent`, `server`<br/>Cloud, infrastructure and data: `container` | `org`<br/>Cloud, infrastructure and data: `cluster`, `environment`, `fleet` |
| `reaches_tool` | `authority` | yes | `credential` | AI and agents: `tool` |
| `scoped_to` | `governance` | yes | `access_grant`, `managed_identity` | AI and agents: `tool` |
| `trace_step` | `runtime` | yes | `access_policy`, `role`, `service_account`, `service_principal`, `user`<br/>AI and agents: `agent`, `application`, `framework`, `server`, `tool`<br/>Cloud, infrastructure and data: `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `model`<br/>Code and supply chain: `ci_job`, `config_file`, `package` | `access_policy`, `role`, `service_account`, `service_principal`, `user`<br/>AI and agents: `agent`, `application`, `framework`, `server`, `tool`<br/>Cloud, infrastructure and data: `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `model`<br/>Code and supply chain: `ci_job`, `config_file`, `package` |
| `used_credential` | `runtime` | yes | AI and agents: `agent`, `tool`, `tool_call` | `credential`, `credential_ref` |
| `vulnerable_to` | `finding` | yes | `credential`, `credential_ref`, `role` | Findings: `misconfiguration`, `vulnerability` |
