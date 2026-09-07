export function validateSearchSyntax(raw, fields = []) {
  const value = raw.trim();
  if (!value) return "";
  let quoted = false;
  let depth = 0;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (char === '"' && value[index - 1] !== "\\") quoted = !quoted;
    if (quoted) continue;
    if (char === "(" ) depth += 1;
    if (char === ")") depth -= 1;
    if (depth < 0) return `位置 ${index + 1}：缺少左括号`;
    if ((char === "&" && value[index + 1] !== "&" && value[index - 1] !== "&") || (char === "|" && value[index + 1] !== "|" && value[index - 1] !== "|")) return `位置 ${index + 1}：运算符必须写成 && 或 ||`;
  }
  if (quoted) return "双引号未闭合";
  if (depth) return "括号未闭合";
  if (/^(?:&&|\|\|)/.test(value) || /(?:&&|\|\|)$/.test(value)) return "表达式不能以 && 或 || 开始或结束";
  if (/(?:&&|\|\|)\s*(?:&&|\|\|)/.test(value)) return "两个运算符之间缺少条件";
  if (/!\s*$/.test(value)) return "! 后缺少排除条件";
  const allowed = new Set(fields.map((field) => field.toLowerCase()));
  const fieldPattern = /(?:^|[\s(])([a-zA-Z_][\w-]*)\s*(?::|!?=)/g;
  let match = fieldPattern.exec(value);
  while (match) {
    if (allowed.size && !allowed.has(match[1].toLowerCase())) return `不支持字段 ${match[1]}`;
    match = fieldPattern.exec(value);
  }
  return "";
}

const FILTER_OPERATORS = new Set(["contains", "not-contains", "equals", "not-equals"]);

export function normalizeFilterGroup(filter) {
  if (typeof filter === "string") {
    return { combinator: "and", rules: filter.trim() ? [{ operator: "contains", value: filter, enabled: true }] : [] };
  }
  if (!filter || typeof filter !== "object") return { combinator: "and", rules: [] };

  const sourceRules = Array.isArray(filter.rules) ? filter.rules : filter.value != null ? [filter] : [];
  const rules = sourceRules.map((rule) => {
    const normalized = {
      operator: FILTER_OPERATORS.has(rule?.operator) ? rule.operator : "contains",
      value: String(rule?.value || ""),
      enabled: rule?.enabled !== false,
    };
    if (rule?.joiner === "and" || rule?.joiner === "or") normalized.joiner = rule.joiner;
    return normalized;
  });
  return { combinator: filter.combinator === "or" ? "or" : "and", rules };
}

export function hasFilterRules(filter) {
  return normalizeFilterGroup(filter).rules.some((rule) => rule.enabled && rule.value.trim());
}

function splitBooleanValue(raw) {
  const pieces = [];
  let current = "";
  let quote = false;
  const push = () => { if (current.trim()) pieces.push(current.trim()); current = ""; };
  for (let index = 0; index < raw.length; index += 1) {
    const char = raw[index];
    if (char === '"' && raw[index - 1] !== "\\") quote = !quote;
    if (!quote && ((char === "&" && raw[index + 1] === "&") || (char === "|" && raw[index + 1] === "|"))) {
      push();
      pieces.push(char === "&" ? "&&" : "||");
      index += 1;
      continue;
    }
    current += char;
  }
  push();
  return pieces;
}

function ruleToExpression(key, rule) {
  const raw = rule.value.trim();
  if (!raw) return "";
  const operator = FILTER_OPERATORS.has(rule.operator) ? rule.operator : "contains";
  const comparison = operator === "equals" ? "=" : operator === "not-equals" ? "!=" : ":";
  const expression = splitBooleanValue(raw).map((piece) => {
    if (piece === "&&" || piece === "||") return piece;
    const value = piece.replace(/^"|"$/g, "").replaceAll('"', '\\"');
    return `${key}${comparison}"${value}"`;
  }).join(" ");
  return operator === "not-contains" ? `!(${expression})` : `(${expression})`;
}

export function filtersToExpression(filters = {}) {
  return Object.entries(filters).map(([key, filter]) => {
    const group = normalizeFilterGroup(filter);
    const activeRules = group.rules.filter((rule) => rule.enabled && rule.value.trim());
    const rules = activeRules.map((rule) => ruleToExpression(key, rule));
    if (!rules.length) return "";
    const joiners = activeRules.map((rule) => rule.joiner || group.combinator);
    const expression = rules.reduce((current, rule, index) => index === 0 ? rule : `(${current} ${joiners[index] === "or" ? "||" : "&&"} ${rule})`, "");
    return expression;
  }).filter(Boolean).join(" && ");
}
