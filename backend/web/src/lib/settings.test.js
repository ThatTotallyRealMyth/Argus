import assert from "node:assert/strict";
import test from "node:test";

import { hasConfiguredSetting, normalizeSettingState } from "./settings.js";

test("keeps encrypted settings configured without exposing values", () => {
  const state = normalizeSettingState([
    { key: "github_token", value: "", is_encrypted: true, configured: true },
    { key: "fofa_email", value: "hunter@example.com", is_encrypted: false },
    { key: "empty_secret", value: "", is_encrypted: true },
  ]);
  assert.equal(state.values.github_token, "");
  assert.equal(hasConfiguredSetting(state.values, state.configuredKeys, "github_token"), true);
  assert.equal(hasConfiguredSetting(state.values, state.configuredKeys, "fofa_email"), true);
  assert.equal(hasConfiguredSetting(state.values, state.configuredKeys, "empty_secret"), false);
});
