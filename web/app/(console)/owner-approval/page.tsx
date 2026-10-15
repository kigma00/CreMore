import type { Metadata } from "next";

import { OwnerApprovalPage } from "@/console/views/owner-approval";

// A key's owner opens this from CreMore's approval request; the link's token is the URL fragment.
export const metadata: Metadata = { title: "Owner approval · CreMore", referrer: "no-referrer", robots: { index: false, follow: false } };

export default function Page() {
  return <OwnerApprovalPage />;
}
