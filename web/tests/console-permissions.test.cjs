"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { load } = require("./load-module.cjs");
const { permissionRows, permissionNotes, unreadKeys, conditionalOn } = load("@/console/views/credentials/permissions.tsx");
const { awsPermissionEvidence } = load("@/console/records.ts");
const en = (_ko, text) => text;
const action = (decision, extra = {}) => ({ action: "kms:Decrypt", service: "kms", decision,
  risk: "SECRET_ACCESS", missing_context_values: [], ...extra });

test("denials and missing context stay visible without being asserted as usable permissions", () => {
  for (const decision of ["ALLOWED", "IMPLICIT_DENY", "EXPLICIT_DENY"]) {
    const potential_access = { collection_status: "COMPLETE", assessment_version: 2,
      actions: [action(decision, { missing_context_values: ["aws:SourceIp"] })] };
    const [row] = permissionRows({ potential_access }, en);
    assert.match(row.allows, /Missing context.*aws:SourceIp/);
    assert.equal(row.tag, null);
    assert.equal(awsPermissionEvidence({ aws_permissions: { potential_access } }).actions.length, 0);
    assert.ok(permissionNotes({ potential_access }, en).some(note => /do not establish actual denial or low privilege/.test(note.text)));
  }
});

test("returned layer denial excludes an allow; absent details remain absent rather than false", () => {
  for (const field of ["organizations_allowed", "permissions_boundary_allowed"]) {
    const potential_access = { collection_status: "COMPLETE", assessment_version: 2, actions: [action("ALLOWED", { [field]: false })] };
    assert.equal(awsPermissionEvidence({ aws_permissions: { potential_access } }).actions.length, 0);
  }
  const potential_access = { collection_status: "COMPLETE", assessment_version: 2, actions: [action("ALLOWED")] };
  assert.equal(awsPermissionEvidence({ aws_permissions: { potential_access } }).actions.length, 1);
});

test("an action allowed only on named resources says where, and version 3 needs no recollection", () => {
  const resources = ["arn:aws:kms:us-east-1:123456789012:key/abc"];
  const potential_access = { collection_status: "COMPLETE", assessment_version: 3, named_resources: [], named_resources_complete: true,
    actions: [action("ALLOWED", { resource_scope: "NAMED", resources })] };
  const [row] = permissionRows({ potential_access }, en);
  assert.match(row.allows, /^Allowed on 1 named resource \(potential\)$/);
  assert.equal(row.tag, "secret access");
  assert.equal(awsPermissionEvidence({ aws_permissions: { potential_access } }).actions.length, 1);
  assert.ok(!permissionNotes({ potential_access }, en).some(note => /older simulation/.test(note.text)));
});

test("an action a key policy blocks says so instead of reading as no allow", () => {
  const key = "arn:aws:kms:us-east-1:123456789012:key/closed";
  const named_resources = [{ resource: key, actions: ["kms:Decrypt"], allowed: [], explicit_deny: [], missing_context_values: [],
    resource_policy: "EVALUATED", key_policy_blocks: ["kms:Decrypt"] }];
  const potential_access = { collection_status: "COMPLETE", assessment_version: 3, named_resources, named_resources_complete: true,
    actions: [action("IMPLICIT_DENY")] };
  const [row] = permissionRows({ potential_access }, en);
  assert.match(row.allows, /^The IAM policy allows it; the key policy of 1 KMS key blocks it \(simulation\)$/);
  assert.equal(row.tag, null);
  assert.equal(awsPermissionEvidence({ aws_permissions: { potential_access } }).actions.length, 0);
  const two = { ...potential_access, named_resources: [...named_resources, { ...named_resources[0], resource: key + "-2" }] };
  assert.match(permissionRows({ potential_access: two }, en)[0].allows, /the key policies of 2 KMS keys block it/);
});

test("a key whose policy could not be read and an answer left to request conditions are named under the action", () => {
  const named = (resource, extra) => ({ resource, actions: ["kms:Decrypt"], allowed: [], explicit_deny: [], missing_context_values: [],
    resource_policy: "EVALUATED", ...extra });
  const potential = { named_resources: [
    named("arn:aws:kms:us-east-1:123456789012:key/unread", { allowed: ["kms:Decrypt"], resource_policy: "NOT_READ" }),
    named("arn:aws:kms:us-east-1:123456789012:key/when", { missing_context_values: ["kms:ViaService"], conditional: ["kms:Decrypt"] }),
    // Another action's missing context on the same resource is not this action's.
    named("arn:aws:kms:us-east-1:123456789012:key/other", { missing_context_values: ["aws:SourceIp"], conditional: ["kms:Encrypt"] }),
    named("arn:aws:secretsmanager:us-east-1:123456789012:secret:x", { resource_policy: "NOT_READ" })] };
  assert.deepEqual(unreadKeys(potential, "kms:Decrypt"), ["arn:aws:kms:us-east-1:123456789012:key/unread"]);  // KMS keys only
  assert.deepEqual(conditionalOn(potential, "kms:Decrypt").map(item => item.resource), ["arn:aws:kms:us-east-1:123456789012:key/when"]);
});

test("historical simulations require recollection instead of claiming preserved condition evidence", () => {
  const potential_access = { collection_status: "COMPLETE", actions: [action("IMPLICIT_DENY")] };
  assert.match(permissionRows({ potential_access }, en)[0].allows, /No allow found \(simulation\)/);
  assert.ok(permissionNotes({ potential_access }, en).some(note => /older simulation.*Recollect/.test(note.text)));
});
