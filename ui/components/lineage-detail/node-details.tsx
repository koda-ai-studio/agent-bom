import type { LineageNodeData } from "../lineage-nodes";
import { graphRepositoryContext } from "@/lib/graph-repository-context";
import { severityColor } from "@/lib/api";
import { CodeBlock, GenericAssetSection, Row, TagList } from "./fields";
import { VulnerabilityDetails } from "./vulnerability";

function RepositoryDetails({ data }: { data: LineageNodeData }) {
  const repository = graphRepositoryContext(data);
  return (<>
{repository && <div className="space-y-2" aria-label="Repository context">
  <Row label="Repository" value={repository.slug || data.label} />
  <Row label="Host" value={repository.host} />
  <Row label="Remote" value={repository.remote || "Not recorded"} />
  <Row label="Scanned branch" value={repository.branch || "Not recorded"} />
  <Row label="Scanned commit" value={repository.commit || "Not recorded"} />
  {repository.defaultBranch && <Row label="Default branch" value={repository.defaultBranch} />}
</div>}
  </>);
}

function ProviderDetails({ data }: { data: LineageNodeData }) {
  return (<>
{data.nodeType === "provider" && data.agentCount !== undefined && (
  <Row label="Hosted agents" value={data.agentCount} />
)}
  </>);
}

function AgentDetails({ data }: { data: LineageNodeData }) {
  return (<>
{data.nodeType === "agent" && (
  <div className="space-y-3">
    {data.agentType && <Row label="Type" value={data.agentType} />}
    {data.agentStatus && (
      <div
        className={`text-xs px-2 py-1 rounded border font-mono ${
          data.agentStatus === "installed-not-configured"
            ? "border-[color:var(--severity-medium-border)] bg-[color:var(--severity-medium-bg)] text-[color:var(--severity-medium)]"
            : "border-emerald-800 bg-emerald-950 text-emerald-400"
        }`}
      >
        {data.agentStatus === "installed-not-configured"
          ? "Not Configured"
          : "Configured"}
      </div>
    )}
    {data.serverCount !== undefined && (
      <Row label="Servers" value={data.serverCount} />
    )}
    {data.packageCount !== undefined && (
      <Row label="Packages" value={data.packageCount} />
    )}
    {(data.vulnCount ?? 0) > 0 && (
      <Row
        label="Findings"
        value={data.vulnCount ?? 0}
        className="text-red-400"
      />
    )}
  </div>
)}
  </>);
}

function IdentityDetails({ data }: { data: LineageNodeData }) {
  return (<>
{(data.nodeType === "user" ||
  data.nodeType === "group" ||
  data.nodeType === "serviceAccount" ||
  data.nodeType === "environment" ||
  data.nodeType === "fleet" ||
  data.nodeType === "cluster") && (
  <GenericAssetSection
    description={data.description}
    version={data.version}
    attributes={data.attributes}
  />
)}
  </>);
}

function ServerDetails({ data }: { data: LineageNodeData }) {
  return (<>
{data.nodeType === "server" && (
  <div className="space-y-3">
    {data.command && (
      <CodeBlock label="Connection" value={data.command} />
    )}
    {data.toolCount !== undefined && data.toolCount > 0 && (
      <Row label="Tools" value={data.toolCount} />
    )}
    {data.credentialCount !== undefined && data.credentialCount > 0 && (
      <Row
        label="Credentials"
        value={data.credentialCount}
        className="text-amber-400"
      />
    )}
    {data.packageCount !== undefined && data.packageCount > 0 && (
      <Row label="Packages" value={data.packageCount} />
    )}
  </div>
)}
  </>);
}

function SharedServerDetails({ data }: { data: LineageNodeData }) {
  return (<>
{data.nodeType === "sharedServer" && (
  <div className="space-y-3">
    {data.sharedBy && (
      <div className="text-xs px-2 py-1 rounded bg-cyan-500/10 dark:bg-cyan-900/60 text-cyan-700 dark:text-cyan-300 border border-cyan-700 font-mono">
        Shared by {data.sharedBy} agents
      </div>
    )}
    {data.sharedAgents && data.sharedAgents.length > 0 && (
      <TagList label="Connected Agents" tags={data.sharedAgents} />
    )}
    {data.command && (
      <CodeBlock label="Connection" value={data.command} />
    )}
  </div>
)}
  </>);
}

function PackageDetails({ data }: { data: LineageNodeData }) {
  return (<>
{data.nodeType === "package" && (
  <div className="space-y-3">
    {data.ecosystem && <Row label="Ecosystem" value={data.ecosystem} />}
    {data.version && <Row label="Version" value={data.version} />}
    {data.versionSource && (
      <Row label="Version source" value={data.versionSource} />
    )}
    {data.versionConfidence && (
      <Row label="Version confidence" value={data.versionConfidence} />
    )}
    {data.vulnCount == null ? (
      <div className="text-xs text-ink-secondary">Finding count unavailable</div>
    ) : data.vulnCount > 0 ? (
      <Row label="Findings" value={data.vulnCountPartial ? `At least ${data.vulnCount}` : data.vulnCount} className="text-red-400" />
    ) : (
      <div className="text-xs text-ink-secondary">No findings linked in this snapshot</div>
    )}
  </div>
)}
  </>);
}

function MisconfigurationDetails({ data }: { data: LineageNodeData }) {
  return (<>
{data.nodeType === "misconfiguration" && (
  <div className="space-y-3">
    {data.severity && (
      <span
        className={`inline-block text-xs px-2 py-1 rounded border font-mono uppercase ${severityColor(data.severity)}`}
      >
        {data.severity}
      </span>
    )}
    {data.description && (
      <div className="text-xs text-ink-secondary">{data.description}</div>
    )}
  </div>
)}
  </>);
}

function CredentialDetails({ data }: { data: LineageNodeData }) {
  return (<>
{data.nodeType === "credential" && (
  <div className="space-y-3">
    <div className="text-xs text-amber-400">
      Environment variable or credential-like secret exposed in
      configuration.
    </div>
    {data.serverName && (
      <Row label="Linked server" value={data.serverName} />
    )}
  </div>
)}
  </>);
}

function ToolDetails({ data }: { data: LineageNodeData }) {
  return (<>
{data.nodeType === "tool" && data.description && (
  <div className="text-xs text-ink-secondary">{data.description}</div>
)}
  </>);
}

function ModelDetails({ data }: { data: LineageNodeData }) {
  return (<>
{data.nodeType === "model" && (
  <GenericAssetSection
    description={data.description}
    version={data.version}
    attributes={data.attributes}
  />
)}
  </>);
}

function DatasetDetails({ data }: { data: LineageNodeData }) {
  return (<>
{data.nodeType === "dataset" && (
  <GenericAssetSection
    description={data.description}
    version={data.version}
    attributes={data.attributes}
  />
)}
  </>);
}

function ContainerDetails({ data }: { data: LineageNodeData }) {
  return (<>
{data.nodeType === "container" && (
  <GenericAssetSection
    description={data.description}
    attributes={data.attributes}
  />
)}
  </>);
}

function CloudResourceDetails({ data }: { data: LineageNodeData }) {
  return (<>
{data.nodeType === "cloudResource" && (
  <GenericAssetSection
    description={data.description}
    attributes={data.attributes}
  />
)}
  </>);
}

export function PrimaryNodeDetails({ data }: { data: LineageNodeData }) {
  return (<>
    <RepositoryDetails data={data} />
    <ProviderDetails data={data} />
    <AgentDetails data={data} />
    <IdentityDetails data={data} />
    <ServerDetails data={data} />
    <SharedServerDetails data={data} />
    <PackageDetails data={data} />
    <VulnerabilityDetails data={data} />
    <MisconfigurationDetails data={data} />
    <CredentialDetails data={data} />
    <ToolDetails data={data} />
    <ModelDetails data={data} />
    <DatasetDetails data={data} />
    <ContainerDetails data={data} />
    <CloudResourceDetails data={data} />
  </>);
}
