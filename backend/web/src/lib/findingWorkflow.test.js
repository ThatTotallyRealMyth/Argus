import test from "node:test";
import assert from "node:assert/strict";
import { findingStatusLabel, findingStatusTone, verificationResultLabel } from "./findingWorkflow.js";

test("maps finding lifecycle and retest states", () => {
  assert.equal(findingStatusLabel("regressed"), "Relapsing");
  assert.equal(findingStatusTone("resolved"), "muted");
  assert.equal(verificationResultLabel("safe"), "Not recently recreated");
  assert.equal(verificationResultLabel(""), "Not yet recovered");
});
