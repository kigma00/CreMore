/* Content source types the platform scans, in the platform's source order.
 *
 * The console reads this one list instead of each screen keeping its own: the rules'
 * scope offers it, and the logs use it to tell content scans (which can be stopped). It is plain data on purpose, so
 * pure models may import it. Keep it equal to the backend registry's SOURCE_TYPES, so a backend source is added here
 * in the same change.
 */
export const CONTENT_SOURCE_TYPES = ["s3", "github", "notion", "gitlab", "gcp", "confluence", "bitbucket", "azure_blob", "azure_devops",
  "website"] as const;
