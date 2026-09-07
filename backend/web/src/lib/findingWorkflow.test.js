import test from "node:test";
import assert from "node:assert/strict";
import { findingStatusLabel, findingStatusTone, verificationResultLabel } from "./findingWorkflow.js";

test("maps finding lifecycle and retest states", () => {
  assert.equal(findingStatusLabel("regressed"), "复发");
  assert.equal(findingStatusTone("resolved"), "muted");
  assert.equal(verificationResultLabel("safe"), "最近未复现");
  assert.equal(verificationResultLabel(""), "尚未复测");
});
