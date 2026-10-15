"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { load } = require("./load-module.cjs");

const { ItemDrawer, rotationStage, nextStep } = load("@/console/views/approvals/page.tsx", {
  extraExports: "\nexport { ItemDrawer, rotationStage, nextStep };",
  overrides: {
    "@/console/layer": { Drawer: ({ children }) => React.createElement("div", null, children), useToast: () => () => {} },
    "@/console/data": { useSaved: () => () => {}, send: () => { throw new Error("Legacy rotation must not write"); } },
  },
});
const { LocaleContext } = load("@/components/locale.tsx");
const L = ko => ko;
const job = status => ({ id: "legacy-job", credential_id: "credential", status, phase: "",
  requested_by: "requester", approved_by: null, error: null, secret_arn: "arn:aws:secretsmanager:us-east-1:123456789012:secret:app",
  user_name: "ci", account_id: "123456789012", old_key_id: "AKIA0000000000000000", new_key_id: "",
  created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z" });

test("legacy rotations are read-only even if an older API omits migration flags", () => {
  for (const status of ["REQUESTED", "PREPARED", "PUBLISHED", "FAILED", "UNKNOWN"]) {
    const legacy = job(status), stage = rotationStage(legacy);
    assert.equal(stage, status === "PUBLISHED" ? "done" : "check");
    const item = { kind: "rotation", id: "rotation:legacy-job", stage, job: legacy };
    assert.equal(nextStep(item, L), status === "PUBLISHED" ? "읽기 전용 이력" : "관리자 상태 확인 필요");
    const html = renderToStaticMarkup(React.createElement(LocaleContext.Provider, { value: "ko" },
      React.createElement(ItemDrawer, { item, actor: { id: "other-admin", role: "Admin" },
        policy: { execution_enabled: true, rotation_execution_enabled: true, auth_mode: "oidc" },
        record: { id: "credential:credential", provider: "aws", credential_type: "AWS_ACCESS_KEY", exposed: true },
        onClose: () => {}, onChanged: () => {}, go: () => {} })));
    assert.match(html, /이전 키 교체 이력 · 읽기 전용/);
    assert.match(html, /조치 계획 보기/);
    assert.doesNotMatch(html, /승인하고 준비|>게시<|승인하면 새 키를/);
    if (status !== "PUBLISHED") assert.match(html, /관리자가 현재 IAM 키와 Secret 상태를 대조/);
    else assert.doesNotMatch(html, /관리자가 현재 IAM 키와 Secret 상태를 대조/);
  }
  assert.equal(rotationStage({ ...job("PUBLISHED"), reconciliation_required: true }), "check");
});
