# Cloud, infrastructure and data: entity relationships

> Generated from the code by `scripts/generate_graph_data_model.py`. Do not edit by hand: re-run the
> generator and commit the result. CI runs it with `--check` and fails on drift.

Entity types in the cloud, infrastructure and data domain and the relationships allowed between them. A line means the relationship is allowed between the two types; cardinality is not modelled. Back to the [data model](../../DATA_MODEL.md) · [all relationship pairs](../relationships.md).

## Inside the domain

### Structure: what contains, depends on or governs what

43 type pairs, too many to draw legibly. Read a row as *source → relationship → target*.

| Source ↓ / target → | `account` | `api_gateway` | `cloud_resource` | `cluster` | `container` | `data_store` | `dataset` | `environment` | `fleet` | `model` | `org` | `resource` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `account` | hosts | contains<br/>owns | contains<br/>hosts<br/>owns | part_of |  | contains<br/>owns |  | contains<br/>owns<br/>part_of | part_of |  | hosts<br/>part_of |  |
| `api_gateway` |  |  | protects |  |  | protects |  |  |  |  |  | protects |
| `cloud_resource` | hosts |  | contains<br/>depends_on<br/>hosts<br/>part_of<br/>protects |  |  | protects<br/>stores | stores |  |  |  | hosts | protects |
| `cluster` |  |  |  |  | contains |  |  |  |  |  |  | contains |
| `container` |  |  | hosted_on | hosted_on<br/>part_of | contains<br/>depends_on<br/>hosted_on<br/>runs |  |  | part_of | hosted_on<br/>part_of | serves_model | part_of |  |
| `data_store` |  |  | depends_on |  |  | contains<br/>depends_on<br/>stores | stores |  |  |  |  |  |
| `environment` | hosts | contains | contains<br/>hosts | contains | contains | contains | contains |  |  | contains | hosts |  |
| `fleet` | hosts |  | hosts |  | contains |  |  |  |  |  | hosts |  |
| `org` | contains |  | owns |  |  |  |  | owns |  |  | contains |  |
| `provider` | hosts |  | hosts |  |  |  |  |  |  |  | hosts |  |
| `resource` |  |  |  |  | contains | stores | stores |  |  |  |  | part_of |

### Exposure and runtime: what is exposed to, observed or affected

```mermaid
erDiagram
  account }o--o{ data_store : "exposed_to"
  api_gateway }o--o{ cloud_resource : "exposed_to"
  api_gateway }o--o{ data_store : "exposed_to"
  api_gateway }o--o{ resource : "exposed_to"
  cloud_resource }o--o{ cloud_resource : "exposed_to"
  cloud_resource }o--o{ container : "exposed_to"
  cloud_resource }o--o{ data_store : "exposed_to"
  cloud_resource }o--o{ resource : "exposed_to"
  container }o--o{ data_store : "exposed_to"
  container }o--o{ resource : "exposed_to"
  data_store }o--o{ data_store : "exposed_to"
  data_store }o--o{ resource : "exposed_to"
```

### Authority: who can act on what

30 type pairs, too many to draw legibly. Read a row as *source → relationship → target*.

| Source ↓ / target → | `account` | `api_gateway` | `cloud_resource` | `cluster` | `container` | `data_store` | `dataset` | `model` | `resource` |
|---|---|---|---|---|---|---|---|---|---|
| `account` | cross_account_trust<br/>trusts |  | can_access |  |  |  | can_access |  | can_access |
| `cloud_resource` |  | can_access | can_access | can_access | can_access | can_access | can_access | can_access | can_access |
| `cluster` |  | can_access | can_access | can_access | can_access | can_access | can_access | can_access | can_access |
| `container` |  | can_access | can_access | can_access | can_access | can_access | can_access | can_access | can_access |
| `model` |  | can_access | can_access | can_access | can_access | can_access | can_access | can_access | can_access |

Not drawn, because they can connect almost any two types: `correlates_with`, `possibly_correlates_with`, `recorded_activity`, `trace_step`. They are listed in the tables below.

## Relationship reference

### Inside the domain

| Relationship | Class | Traversable | From | To |
|---|---|---|---|---|
| `can_access` | `authority` | yes | `account`, `cloud_resource`, `cluster`, `container`, `model` | `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `model`, `resource` |
| `contains` | `structural` | yes | `account`, `cloud_resource`, `cluster`, `container`, `data_store`, `environment`, `fleet`, `org`, `resource` | `account`, `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `environment`, `model`, `org`, `resource` |
| `cross_account_trust` | `authority` | yes | `account` | `account` |
| `depends_on` | `dependency` | yes | `cloud_resource`, `container`, `data_store` | `cloud_resource`, `container`, `data_store` |
| `exposed_to` | `exposure` | yes | `api_gateway`, `cloud_resource`, `container`, `data_store` | `account`, `cloud_resource`, `container`, `data_store`, `resource` |
| `hosted_on` | `dependency` | yes | `container` | `cloud_resource`, `cluster`, `container`, `fleet` |
| `hosts` | `structural` | yes | `account`, `cloud_resource`, `environment`, `fleet`, `provider` | `account`, `cloud_resource`, `org` |
| `owns` | `governance` | yes | `account`, `org` | `api_gateway`, `cloud_resource`, `data_store`, `environment` |
| `part_of` | `structural` | yes | `account`, `cloud_resource`, `container`, `resource` | `cloud_resource`, `cluster`, `environment`, `fleet`, `org`, `resource` |
| `possibly_correlates_with` | `correlation` | no | `cloud_resource`, `cluster`, `container`, `data_store` | `cloud_resource`, `cluster`, `container`, `data_store` |
| `protects` | `governance` | no | `api_gateway`, `cloud_resource` | `cloud_resource`, `data_store`, `resource` |
| `recorded_activity` | `correlation` | no | `resource` | `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `model`, `resource` |
| `runs` | `structural` | yes | `container` | `container` |
| `serves_model` | `dependency` | yes | `container` | `model` |
| `stores` | `structural` | yes | `cloud_resource`, `data_store`, `resource` | `data_store`, `dataset` |
| `trace_step` | `runtime` | yes | `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `model` | `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `model` |
| `trusts` | `authority` | yes | `account` | `account` |

### Across domains

| Relationship | Class | Traversable | From | To |
|---|---|---|---|---|
| `accessed` | `runtime` | yes | AI and agents: `agent`, `tool`, `tool_call`<br/>Identity and access: `federated_identity`, `role`, `service_account`, `service_principal`, `user` | `cloud_resource`, `data_store`, `dataset`, `resource` |
| `affects` | `finding` | yes | Findings: `misconfiguration`, `vulnerability` | `account`, `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `model`, `org`, `resource` |
| `assumes` | `authority` | yes | `cloud_resource`, `cluster`, `container`, `model` | Identity and access: `managed_identity`, `role`, `service_account`, `service_principal` |
| `belongs_to` | `structural` | yes | `cloud_resource`, `container` | AI and agents: `application` |
| `can_access` | `authority` | yes | `account`, `cloud_resource`, `cluster`, `container`, `model`<br/>AI and agents: `agent`, `application`, `server`, `tool`<br/>Identity and access: `federated_identity`, `group`, `managed_identity`, `role`, `service_account`, `service_principal`, `user` | `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `model`, `resource`<br/>AI and agents: `agent`, `server`<br/>Code and supply chain: `config_file`<br/>Identity and access: `credential` |
| `contains` | `structural` | yes | `account`, `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `environment`, `fleet`, `model`, `resource`<br/>Code and supply chain: `directory` | `container`<br/>Identity and access: `access_policy`, `role`, `service_account`, `service_principal`<br/>AI and agents: `agent`, `application`, `framework`, `server`, `tool`<br/>Code and supply chain: `ci_job`, `config_file`, `directory`, `package`, `source_file`<br/>Findings: `misconfiguration`, `vulnerability` |
| `correlates_with` | `correlation` | no | Code and supply chain: `code_module` | `data_store` |
| `cross_account_trust` | `authority` | yes | `account`<br/>Identity and access: `federated_identity`, `role`, `service_principal` | `account`<br/>Identity and access: `federated_identity`, `role`, `service_principal` |
| `depends_on` | `dependency` | yes | `container`, `resource` | Code and supply chain: `package` |
| `evaluates` | `governance` | no | AI and agents: `eval_suite` | `model` |
| `exposed_to` | `exposure` | yes | AI and agents: `agent`, `server` | `cloud_resource`, `data_store`, `resource` |
| `exposes_cred` | `authority` | yes | `resource` | Identity and access: `credential` |
| `governs` | `governance` | no | Identity and access: `policy` | `account`, `org` |
| `has_permission` | `authority` | yes | Identity and access: `group`, `managed_identity`, `role`, `service_account`, `service_principal`, `user` | `account`, `cloud_resource`, `cluster`, `data_store`, `org`, `resource` |
| `hosted_on` | `dependency` | yes | AI and agents: `agent`, `server` | `cloud_resource`, `cluster`, `container`, `fleet` |
| `hosts` | `structural` | yes | `account`, `cloud_resource`, `environment`, `fleet`, `provider` | AI and agents: `agent`, `server` |
| `invoked` | `runtime` | yes | Identity and access: `federated_identity`, `role`, `service_account`, `service_principal`, `user` | `cloud_resource` |
| `manages` | `governance` | yes | Identity and access: `federated_identity`, `group`, `role`, `service_account`, `service_principal`, `user` | `cloud_resource`, `environment`, `fleet` |
| `member_of` | `authority` | yes | AI and agents: `agent`<br/>Identity and access: `federated_identity`, `group`, `managed_identity`, `role`, `service_account`, `service_principal`, `user` | `account`, `fleet` |
| `owns` | `governance` | yes | `account`, `org`<br/>Identity and access: `group`, `role`, `service_account`, `service_principal`, `user` | `cloud_resource`, `environment`<br/>AI and agents: `agent`<br/>Identity and access: `group`, `policy`, `role`, `service_account`, `service_principal`, `user` |
| `part_of` | `structural` | yes | AI and agents: `agent`, `server` | `cluster`, `environment`, `fleet`, `org` |
| `platform_for` | `structural` | no | `provider` | AI and agents: `agent` |
| `recorded_activity` | `correlation` | no | `resource`<br/>AI and agents: `agent`, `server`, `tool_call`<br/>Identity and access: `federated_identity`, `managed_identity`, `role`, `service_account`, `service_principal`, `user` | `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `model`, `resource`<br/>Identity and access: `access_policy`, `credential`, `credential_ref`, `policy`, `role`, `service_account`, `service_principal`, `user`<br/>AI and agents: `agent`, `application`, `framework`, `server`, `tool`, `tool_call`<br/>Code and supply chain: `ci_job`, `config_file`, `package` |
| `serves_model` | `dependency` | yes | AI and agents: `agent`, `framework`, `server` | `model` |
| `stores` | `structural` | yes | AI and agents: `server` | `data_store`, `dataset` |
| `trace_step` | `runtime` | yes | `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `model`<br/>Identity and access: `access_policy`, `role`, `service_account`, `service_principal`, `user`<br/>AI and agents: `agent`, `application`, `framework`, `server`, `tool`<br/>Code and supply chain: `ci_job`, `config_file`, `package` | `api_gateway`, `cloud_resource`, `cluster`, `container`, `data_store`, `dataset`, `model`<br/>Identity and access: `access_policy`, `role`, `service_account`, `service_principal`, `user`<br/>AI and agents: `agent`, `application`, `framework`, `server`, `tool`<br/>Code and supply chain: `ci_job`, `config_file`, `package` |
| `trusts` | `authority` | yes | `account`<br/>Identity and access: `role` | `account`<br/>Identity and access: `federated_identity`, `group`, `role`, `service_account`, `service_principal`, `user` |
| `uses` | `dependency` | yes | AI and agents: `agent` | `resource` |
| `vulnerable_to` | `finding` | yes | `cloud_resource`, `container` | Findings: `misconfiguration`, `vulnerability` |
