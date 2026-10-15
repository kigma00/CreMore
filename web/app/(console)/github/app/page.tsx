import type { Metadata } from "next";

import { GitHubAppPage } from "@/console/views/integrations/github-app";

// GitHub sends the admin back here after making the App (with a code) and after installing it.
export const metadata: Metadata = { title: "GitHub App · CreMore", referrer: "no-referrer", robots: { index: false, follow: false } };

export default function Page() {
  return <GitHubAppPage />;
}
