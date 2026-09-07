import assert from "node:assert/strict";
import test from "node:test";
import { filtersToExpression, hasFilterRules, normalizeFilterGroup } from "./searchSyntax.js";

test("normalizes legacy column filters", () => {
  assert.deepEqual(normalizeFilterGroup("admin"), {
    combinator: "and",
    rules: [{ operator: "contains", value: "admin", enabled: true }],
  });
  assert.deepEqual(normalizeFilterGroup({ operator: "equals", value: "running" }), {
    combinator: "and",
    rules: [{ operator: "equals", value: "running", enabled: true }],
  });
});

test("builds an AND group with all four operators", () => {
  const expression = filtersToExpression({
    name: {
      combinator: "and",
      rules: [
        { operator: "contains", value: "admin" },
        { operator: "not-contains", value: "test", joiner: "and" },
        { operator: "equals", value: "admin portal", joiner: "and" },
        { operator: "not-equals", value: "legacy", joiner: "and" },
      ],
    },
  });

  assert.equal(expression, '((((name:"admin") && !(name:"test")) && (name="admin portal")) && (name!="legacy"))');
});

test("builds OR groups and ignores blank rules", () => {
  assert.equal(filtersToExpression({ status: { combinator: "or", rules: [
    { operator: "equals", value: "running" },
    { operator: "equals", value: "failed" },
    { operator: "contains", value: "   " },
  ] } }), '((status="running") || (status="failed"))');
  assert.equal(hasFilterRules({ combinator: "and", rules: [{ operator: "contains", value: "" }] }), false);
});

test("keeps legacy boolean values inside a single rule", () => {
  assert.equal(filtersToExpression({ name: { operator: "contains", value: "admin || login" } }), '(name:"admin" || name:"login")');
});

test("supports a different connector for each added rule", () => {
  assert.equal(filtersToExpression({ name: { combinator: "and", rules: [
    { operator: "contains", value: "api" },
    { operator: "contains", value: "admin", joiner: "and" },
    { operator: "contains", value: "login", joiner: "or" },
  ] } }), '(((name:"api") && (name:"admin")) || (name:"login"))');
});

test("keeps disabled rules but excludes them from expressions", () => {
  const filter = { rules: [
    { operator: "contains", value: "api", enabled: true },
    { operator: "contains", value: "legacy", enabled: false, joiner: "or" },
  ] };
  assert.equal(filtersToExpression({ name: filter }), '(name:"api")');
  assert.equal(hasFilterRules({ rules: [{ operator: "contains", value: "legacy", enabled: false }] }), false);
  assert.equal(normalizeFilterGroup(filter).rules[1].value, "legacy");
});
