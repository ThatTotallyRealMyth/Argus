export const findingStatusOptions = [
  { value: "new", label: "新发现" },
  { value: "validated", label: "已验证" },
  { value: "submitted", label: "已提交" },
  { value: "resolved", label: "已解决" },
  { value: "false_positive", label: "误报" },
  { value: "regressed", label: "复发" },
];

export function findingStatusLabel(value) {
  return findingStatusOptions.find((option) => option.value === value)?.label || "新发现";
}

export function findingStatusTone(value) {
  return ({ validated: "ok", submitted: "accent", resolved: "muted", false_positive: "muted", regressed: "danger", new: "warn" })[value] || "warn";
}

export function verificationResultLabel(value) {
  return ({ vulnerable: "最近命中", safe: "最近未复现", error: "复测失败" })[value] || "尚未复测";
}

export function verificationResultTone(value) {
  return ({ vulnerable: "danger", safe: "ok", error: "warn" })[value] || "muted";
}
