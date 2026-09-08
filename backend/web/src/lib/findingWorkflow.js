export const findingStatusOptions = [
  { value: "new", label: "New Discovery" },
  { value: "validated", label: "Verifyed" },
  { value: "submitted", label: "Submitted" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "Misreporting" },
  { value: "regressed", label: "Relapsing" },
];

export function findingStatusLabel(value) {
  return findingStatusOptions.find((option) => option.value === value)?.label || "New Discovery";
}

export function findingStatusTone(value) {
  return ({ validated: "ok", submitted: "accent", resolved: "muted", false_positive: "muted", regressed: "danger", new: "warn" })[value] || "warn";
}

export function verificationResultLabel(value) {
  return ({ vulnerable: "Recently hit.", safe: "Not recently recreated", error: "Reaction Failed" })[value] || "Not yet recovered";
}

export function verificationResultTone(value) {
  return ({ vulnerable: "danger", safe: "ok", error: "warn" })[value] || "muted";
}
