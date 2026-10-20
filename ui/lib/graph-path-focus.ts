/** Present on an attack-path page the server focused on one node or finding occurrence. */
export interface GraphPathFocus {
  node_id: string | null;
  finding_id: string | null;
  resolved_from: string | null;
  /** False when a read bound cut the search: a miss is then not proof of absence. */
  covers_all_matches: boolean;
  /** Present when the link carried the occurrence's advisory. */
  advisory_id?: string | undefined;
  /** "node_advisory" when paths record the advisory, not the occurrence id, on the occurrence's node. */
  matched_by?: "occurrence" | "node_advisory" | undefined;
  /** Present when the queue is focused on one compliance control's mapped findings. */
  framework?: string | undefined;
  control?: string | undefined;
  control_findings?: number | undefined;
}
