/* Service logos: each brand's own mark, from files under /logos (public/logos/SOURCES.md says where
 * each came from). What is not a brand -- a file, pasted text, a vault product the reader names --
 * shows a line icon instead. An id with neither renders as its initials. */

import type { CSSProperties } from "react";

import { Ic, type IconName } from "@/console/icons";
import { BRANDS } from "@/console/logo-set";

type Mark = { name: string; src?: string; solid?: boolean; glyph?: IconName };

// The mockup's logo files, and the ids that are not brands.
const MARKS: Record<string, Mark> = {
  gitlab: { name: "GitLab", src: "/logos/gitlab.svg" },
  github: { name: "GitHub", src: "/logos/github.svg" },
  aws: { name: "AWS", src: "/logos/aws.png" },
  s3: { name: "Amazon S3", src: "/logos/s3.svg" },
  gcp: { name: "Google Cloud", src: "/logos/gcp.png" },
  gcs: { name: "Cloud Storage", src: "/logos/gcs.png" },
  google_workspace: { name: "Google Workspace", src: "/logos/google_workspace.png" },
  notion: { name: "Notion", src: "/logos/notion.png" },
  confluence: { name: "Confluence", src: "/logos/confluence.svg" },
  bitbucket: { name: "Bitbucket", src: "/logos/bitbucket.svg" },
  awssm: { name: "AWS Secrets Manager", src: "/logos/awssm.svg" },
  external_vault: { name: "Vault", glyph: "vault" },
  website: { name: "Website", glyph: "globe" },
  filesystem: { name: "Files", glyph: "page" },
  inline: { name: "Pasted text", glyph: "comment" },
  generic: { name: "Generic", glyph: "key" },
  database: { name: "Database", glyph: "server" },
};

// Other ids the API uses for the same service.
const ALIASES: Record<string, string> = {
  aws_s3: "s3", aws_iam: "aws", aws_cloudtrail: "aws", aws_ssm: "aws", aws_secrets_manager: "awssm",
  gcp_secret_manager: "gcp", gcp_storage: "gcs", google: "gcp", azure_blob: "azure", azure_entra: "entra_id",
  azure_resource_manager: "azure", azdo: "azure_devops", github_identity: "github",
  "github-org": "github", "notion-admin": "notion", postgresql: "postgres",
};

function brand(key: string): Mark | null {
  const found = Object.prototype.hasOwnProperty.call(BRANDS, key) ? BRANDS[key] : undefined;
  return found ? { name: found[0], src: `/logos/${key}.svg`, solid: Boolean(found[1]) } : null;
}

export function markOf(id: string | undefined | null): Mark | null {
  const key = (id || "").toLowerCase();
  const alias = ALIASES[key] ?? "";
  return MARKS[key] ?? brand(key) ?? MARKS[alias] ?? brand(alias) ?? null;
}

export function serviceName(id: string | undefined | null, fallback?: string): string {
  return markOf(id)?.name ?? fallback ?? titled(id || "");
}

function titled(id: string) {
  return id.split(/[_\-\s]+/).filter(Boolean).map(word => word[0].toUpperCase() + word.slice(1)).join(" ");
}

function initials(label: string) {
  const words = label.split(/[\s_\-.]+/).filter(Boolean);
  const letters = words.length > 1 ? words[0][0] + words[1][0] : (words[0] || "?").slice(0, 2);
  return letters.toUpperCase();
}

export function Logo({ id, size = 22, tip, label }: { id: string | undefined | null; size?: number; tip?: string; label?: string }) {
  const mark = markOf(id);
  const style = { "--s": `${size}px` } as CSSProperties;
  if (!mark || (!mark.src && !mark.glyph)) {  // no file of its own: its initials
    const name = label || mark?.name || titled(id || "");
    return <span className="logo-ph" style={style} data-tip={tip ?? name} aria-hidden="true">{initials(name)}</span>;
  }
  if (mark.glyph) return <span className="logo glyph" style={style} data-tip={tip ?? mark.name}><Ic name={mark.glyph} size={Math.round(size * 0.62)} /></span>;
  return <span className={mark.solid ? "logo solid" : "logo"} style={style} data-tip={tip ?? mark.name}><img src={mark.src} alt="" /></span>;
}
