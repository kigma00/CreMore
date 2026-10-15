/* Who is signed in, and what that lets them do.
 *
 * The API decides authorization; this is only what the dashboard needs to stop
 * offering a control the server would refuse. Hiding a button is a courtesy,
 * never the check -- every route re-derives the role from the token.
 *
 * The order is Viewer < Analyst < Remediator < Admin, the same order the API
 * uses, so a role satisfies every requirement below it.
 */

export type PlatformRole = "Viewer" | "Analyst" | "Remediator" | "Admin";

/** ``ref``: how tickets name this person (a UUID reference), where the API reports it. */
export type Session = { id: string; name: string; email?: string | null; role: PlatformRole; ref?: string };

export const roleRank: Record<PlatformRole, number> = { Viewer: 0, Analyst: 1, Remediator: 2, Admin: 3 };

export function hasRole(role: PlatformRole | undefined, required: PlatformRole) {
  return role !== undefined && roleRank[role] >= roleRank[required];
}
