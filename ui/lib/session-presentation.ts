import type { AuthMeResponse } from "@/lib/api";
import { isStaticDemo } from "@/lib/static-demo";

/** Presentation of verified session fields; never interprets a key as a human. */
export function sessionPresentation(session: AuthMeResponse | null) {
  if (isStaticDemo()) {
    return {
      name: "Demo visitor",
      method: "Read-only demo",
      description: "Everything here is labelled sample data. Install agent-bom to sign in and scan your own environment.",
      canSignOut: false,
    };
  }
  const method = session?.auth_method ?? "";
  const anonymous = method === "anonymous" || session?.auth_required === false;
  const local = method === "browser_session_dev_key";
  const sharedKey = ["api_key", "static_api_key", "browser_session", "browser_session_static_api_key"].includes(method);
  return {
    name: anonymous ? "Unauthenticated access" : local ? "Local session" : session?.subject || "Signed-in session",
    method: anonymous ? "Authentication disabled" : local ? "Local development access" : sharedKey ? "API key session" : method.includes("proxy") ? "Trusted proxy" : method.includes("oidc") ? "Single sign-on" : method.includes("saml") ? "SAML single sign-on" : method.replaceAll("_", " ") || "Not signed in",
    description: anonymous ? "This deployment allows access without signing in. Signing out cannot protect an unauthenticated server." : local ? "This local session uses the server's temporary development key." : sharedKey ? "This identity belongs to an API key. It does not identify an individual person." : "Identity and role are provided by your configured authentication service.",
    canSignOut: Boolean(session?.authenticated && !anonymous),
  };
}
