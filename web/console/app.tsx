"use client";

/* The screens the console has, by route. */

import { Console, type ViewTable } from "@/console/shell";
import { Approvals } from "@/console/views/approvals/page";
import { Assign } from "@/console/views/assign/page";
import { Audit } from "@/console/views/audit";
import { Credentials } from "@/console/views/credentials/list";
import { Dashboard } from "@/console/views/dashboard";
import { Integrations } from "@/console/views/integrations/page";
import { Leavers } from "@/console/views/leavers/page";
import { Logs } from "@/console/views/logs";
import { Metadata } from "@/console/views/metadata";
import { Operations } from "@/console/views/operations";
import { Rules } from "@/console/views/rules/page";
import { Settings } from "@/console/views/settings";
import { Vaults } from "@/console/views/vaults/page";

const VIEWS: ViewTable = {
  approvals: Approvals,
  assign: Assign,
  audit: Audit,
  dashboard: Dashboard,
  exposed: Credentials,
  inventory: Credentials,
  leavers: Leavers,
  sources: Integrations,
  metadata: Metadata,
  operations: Operations,
  rules: Rules,
  scans: Logs,
  settings: Settings,
  vaults: Vaults,
};

export function ConsoleApp() {
  return <Console views={VIEWS} />;
}
