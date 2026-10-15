import type { Metadata } from "next";

import { GcpOAuthCallback } from "@/console/gcp-callback";

// The redirect URI Google returns to (GCP_OAUTH_REDIRECT_URI ends in /gcp/oauth/callback): no referrer leaves it.
export const metadata: Metadata = { title: "Google 연결 · CreMore", referrer: "no-referrer", robots: { index: false, follow: false } };

export default function Page() { return <GcpOAuthCallback />; }
