export function normalizeSettingState(settings = []) {
  const values = {};
  const configuredKeys = new Set();
  settings.forEach((item) => {
    values[item.key] = item.value || "";
    if (item.configured || (!item.is_encrypted && Boolean(item.value)))
      configuredKeys.add(item.key);
  });
  return { values, configuredKeys };
}

export function hasConfiguredSetting(values, configuredKeys, key) {
  return Boolean(values[key]) || configuredKeys.has(key);
}
