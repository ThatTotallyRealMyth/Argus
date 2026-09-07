import test from "node:test";
import assert from "node:assert/strict";
import { leadPoCExecutionPayload, leadQueueParams, leadStatusLabel, leadTargetURL, leadTriagePayload, leadTypeLabel } from "./leadQueue.js";

test("builds compact lead queue filters", () => {
  assert.equal(leadQueueParams({ page: 2, status: "investigating", severity: "high", type: "management_surface", query: " admin " }), "page=2&page_size=25&status=investigating&severity=high&type=management_surface&q=admin");
  assert.equal(leadQueueParams({}), "page=1&page_size=25&status=open");
});

test("maps lead workflow labels", () => {
  assert.equal(leadStatusLabel("validated"), "已验证");
  assert.equal(leadTypeLabel("subdomain_takeover"), "接管候选");
});

test("opens browser-compatible lead targets", () => {
  assert.equal(leadTargetURL({ type: "management_surface", target: "https://admin.example.com/login" }), "https://admin.example.com/login");
  assert.equal(leadTargetURL({ type: "sensitive_service", target: "10.0.0.1:6379/tcp" }), "");
  assert.equal(leadTargetURL({ asset_kind: "domain", asset_value: "example.com" }), "https://example.com");
});

test("updates every member of a collapsed lead cluster", () => {
  assert.deepEqual(leadTriagePayload({
    id: "finding:site-link",
    asset_id: "site-1",
    related_assets: [
      { asset_id: "domain-1", lead_id: "finding:domain-link" },
      { asset_id: "site-1", lead_id: "finding:site-link" },
    ],
  }, "ignored", "reviewed"), {
    asset_id: "site-1",
    lead_id: "finding:site-link",
    status: "ignored",
    note: "reviewed",
    related_leads: [
      { asset_id: "domain-1", lead_id: "finding:domain-link" },
      { asset_id: "site-1", lead_id: "finding:site-link" },
    ],
  });
});

test("builds task-bound PoC execution input without trusting target or PoC id", () => {
  assert.deepEqual(leadPoCExecutionPayload({
    asset_id: " asset-1 ", id: " poc:trusted ", target: "https://attacker.invalid", poc: { id: "untrusted" },
  }), { asset_id: "asset-1", lead_id: "poc:trusted", confirm: true });
});
