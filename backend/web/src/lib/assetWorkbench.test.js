import assert from "node:assert/strict";
import test from "node:test";
import { assetPivot, assetTargetURL, leadSummary } from "./assetWorkbench.js";

test("assetPivot builds field-aware searches", () => {
  assert.deepEqual(assetPivot({ kind: "domain", display_value: "api.example.com" }), { tab: "domains", search: 'domain:"api.example.com"' });
  assert.deepEqual(assetPivot({ kind: "port", display_value: "203.0.113.8:6379/tcp" }), { tab: "ports", search: 'ip:"203.0.113.8" && port:6379' });
	assert.deepEqual(assetPivot({ kind: "site", display_value: "https://example.com/admin" }), { tab: "sites", search: 'url:"https://example.com/admin"' });
	assert.deepEqual(assetPivot({ kind: "url", display_value: "https://example.com/api?token=redacted" }), { tab: "urls", search: 'url:"https://example.com/api?token=redacted"' });
});

test("assetTargetURL only opens browser-compatible endpoints", () => {
	assert.equal(assetTargetURL({ kind: "domain", display_value: "example.com" }), "https://example.com");
	assert.equal(assetTargetURL({ kind: "url", display_value: "https://example.com/api" }), "https://example.com/api");
  assert.equal(assetTargetURL({ kind: "port", display_value: "203.0.113.8:8443/tcp" }), "https://203.0.113.8:8443");
  assert.equal(assetTargetURL({ kind: "port", display_value: "203.0.113.8:22/tcp" }), "");
});

test("leadSummary counts severity and executable PoCs", () => {
  assert.deepEqual(leadSummary([
    { severity: "critical" }, { severity: "high", poc: { id: "poc-1" } }, { severity: "unknown" },
  ]), { total: 3, critical: 1, high: 1, medium: 0, low: 0, info: 1, poc: 1 });
});
