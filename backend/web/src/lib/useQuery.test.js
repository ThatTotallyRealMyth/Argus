import test from "node:test";
import assert from "node:assert/strict";
import { selectQueryState } from "../hooks/useQuery.js";

test("returns loading state immediately when the query key changes", () => {
  const state = { key: "domains", data: { domains: [{ id: "domain" }] }, loading: false, error: "" };
  assert.deepEqual(selectQueryState(state, "risks"), { data: null, loading: true, error: "" });
});

test("returns data only for the matching query key", () => {
  const data = { domains: [{ id: "domain" }] };
  assert.deepEqual(
    selectQueryState({ key: "domains", data, loading: false, error: "" }, "domains"),
    { data, loading: false, error: "" },
  );
});
