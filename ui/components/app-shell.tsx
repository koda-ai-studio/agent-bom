"use client";

import { usePathname } from "next/navigation";

import { AuthGate } from "@/components/auth-gate";
import { DemoSeedNotice } from "@/components/demo-seed-notice";
import { Nav } from "@/components/nav";
import { StaticDemoBanner } from "@/components/static-demo-banner";
import { StaticDemoRouteGate } from "@/components/static-demo-route-gate";
import { isStaticDemo } from "@/lib/static-demo";
import {
  SidebarLayoutProvider,
  mainContentPaddingClass,
  useSidebarLayout,
} from "@/components/sidebar-layout";

function ShellMain({ children }: { children: React.ReactNode }) {
  const { collapsed } = useSidebarLayout();
  const pathname = usePathname();
  return (
    <main
      id="main-content"
      className={`min-h-screen pt-16 transition-[padding-left] duration-200 ${mainContentPaddingClass(collapsed)}`}
    >
      <div className="mx-auto w-full max-w-[2560px] px-4 py-6 sm:px-6 lg:px-8">
        <StaticDemoBanner />
        <DemoSeedNotice />
        <StaticDemoRouteGate pathname={pathname}>{children}</StaticDemoRouteGate>
      </div>
    </main>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isLoginRoute = pathname === "/login";

  if (isLoginRoute) {
    return (
      <div className="min-h-screen bg-background text-foreground">
        {isStaticDemo() ? <div className="mx-auto w-full max-w-3xl px-4 pt-6"><StaticDemoBanner /></div> : null}
        <StaticDemoRouteGate pathname={pathname}>{children}</StaticDemoRouteGate>
      </div>
    );
  }

  return (
    <SidebarLayoutProvider>
      <a
        href="#main-content"
        className="fixed left-4 top-3 z-[100] -translate-y-20 rounded-lg bg-[color:var(--accent)] px-3 py-2 text-sm font-semibold text-white shadow-lg transition-transform focus:translate-y-0"
      >
        Skip to content
      </a>
      <AuthGate>
        <Nav />
        <ShellMain>{children}</ShellMain>
      </AuthGate>
    </SidebarLayoutProvider>
  );
}
