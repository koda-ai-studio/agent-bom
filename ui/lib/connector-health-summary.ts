export interface ConnectorHealthRow {
  connector: string;
  state: string;
}

export interface ConnectorHealthSummary {
  value: string;
  hint: string | undefined;
  allHealthy: boolean;
}

/**
 * Connector probes use the API server's own tokens, so the API answers
 * `disabled` until an operator opts in and an admin asks. Those rows are not
 * failures and must not read as "0 healthy".
 */
export function connectorHealthSummary(rows: readonly ConnectorHealthRow[]): ConnectorHealthSummary {
  if (rows.length === 0) return { value: "Not reported", hint: undefined, allHealthy: false };
  const probed = rows.filter((row) => row.state !== "disabled");
  if (probed.length === 0) return { value: "Not enabled", hint: undefined, allHealthy: false };
  const healthy = probed.filter((row) => row.state === "healthy").length;
  const notEnabled = rows.length - probed.length;
  return {
    value: `${healthy}/${probed.length}`,
    hint: notEnabled > 0 ? `${notEnabled} not enabled` : undefined,
    allHealthy: healthy === probed.length && notEnabled === 0,
  };
}
