import { Suspense } from "react";

import { GraphSurface } from "./graph-surface";

export default function GraphPage() {
  return <Suspense fallback={null}><GraphSurface /></Suspense>;
}
