# Terms of service

Last updated: 2026-11-12.

These terms cover the agent-bom software, its directory plugins, and the public lookup
service at `https://agent-bom-lookup.up.railway.app` (the "lookup service"), which is
operated by Mohamed Wagdy Saad, operating as Koda AI ("we"). Apart from the lookup service, the
agent-bom project offers no public hosted service. Anyone else who runs agent-bom as a
service for others is its operator and sets their own terms for that service.

## Software and service scope

agent-bom provides security inventory, vulnerability analysis and related
read-only investigation tools. The open-source software is licensed under
[Apache License 2.0](https://github.com/koda-ai-studio/agent-bom/blob/main/LICENSE).
That license governs use, modification and distribution of the software;
this page does not replace it, including its warranty and liability terms, or
grant access to a hosted service.

Access to a deployment run by an operator depends on that operator's approved accounts, tenant
assignments and supported tool profile. OAuth authorization grants access only
to the configured tenant and available read-only tools. It does not authorize
access to another tenant, changes to infrastructure or collection outside the
scope selected by the user. Self-hosted operators control their deployment,
credentials, storage and access policy.

## Authorized use and results

Use the tools only on systems, files, packages and accounts you are authorized
to inspect. Provide only data needed for the requested operation. Do not use
service access to bypass authorization, obtain other tenants' information or
disrupt the service.

Results depend on available evidence, permissions and third-party advisory
sources. Missing evidence, outdated versions, unavailable services and incomplete
scans can affect results. A finding, grade or absence of findings is not a
promise of security, a certification or professional legal advice. Review the
reported scope and limitations before acting on a result.

## External services and availability

Package registries, vulnerability databases, identity providers, hosting
providers and the selected AI client have their own terms and policies.
See the [privacy notice](privacy.md) for the data boundaries and retention
limitations. The software does not itself establish a service-level agreement
or a guaranteed response time. Any separately agreed service commitments must
be documented by the operator.

## Public lookup service

The lookup service is free and needs no account. It is provided "as is" and "as
available", without warranties of any kind, express or implied, to the extent the law
allows. We may change, rate-limit, suspend or end it at any time without notice. Do
not exceed or work around its rate limits, use it to disrupt the service or others,
or send it personal information. To the extent the law allows, we are not liable for
any indirect, incidental, special or consequential damages, or for any loss arising
from use of, or inability to use, the lookup service or its results.

## Governing law

These terms and any dispute about the lookup service are governed by the laws of the
State of New York, United States, without regard to its conflict-of-laws rules.

## Contact

For the lookup service: wagdy@koda-studio.dev.

## Questions and review

Use [project support](https://github.com/koda-ai-studio/agent-bom/issues) for
non-sensitive software questions and the
[security reporting process](https://github.com/koda-ai-studio/agent-bom/security/policy)
for private security concerns. Account and data requests for a deployment belong
to its operator.
