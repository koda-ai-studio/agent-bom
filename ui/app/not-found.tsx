import { Suspense } from "react";

import { RouteNotFound } from "@/components/route-not-found";

export default function NotFound() {
  return <Suspense fallback={null}><RouteNotFound /></Suspense>;
}
