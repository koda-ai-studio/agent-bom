/** Present on an attack-path page the server focused on one node or finding occurrence. */
export interface GraphPathFocus {
  node_id: string | null;
  finding_id: string | null;
  resolved_from: string | null;
  /** False when a read bound cut the search: a miss is then not proof of absence. */
  covers_all_matches: boolean;
}
