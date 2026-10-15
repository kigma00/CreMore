import type { Metadata } from "next";

import { ResponseLinkPage } from "@/console/views/response-link";

// A responder opens this from CreMore's exposure-response request; the link's token is the URL fragment.
export const metadata: Metadata = { title: "Exposure response · CreMore", referrer: "no-referrer", robots: { index: false, follow: false } };

export default function Page() {
  return <ResponseLinkPage />;
}
