import React, { useEffect, useState } from "react";
import { BellRing, Edit3, KeyRound, RefreshCw, Send, X } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { Badge, DataTable, Panel, Tabs } from "../components/ui.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api } from "../lib/api.js";
import { hasConfiguredSetting, normalizeSettingState } from "../lib/settings.js";

function SettingsMessage({ message, onClose }) {
  const reduceMotion = useReducedMotion();
  const failed = message.includes("Failed");
  return (
    <AnimatePresence initial={false} mode="wait">
      {message && (
        <motion.div
          key={message}
          role={failed ? "alert" : "status"}
          className={`${failed ? "error-box" : "success-box"} settings-message`}
          initial={{ opacity: 0, y: 5 }}
          animate={{ opacity: 1, y: 0 }}
          exit={
            reduceMotion
              ? { opacity: 0 }
              : { opacity: 0, y: -5, filter: "blur(2px)" }
          }
          transition={{ duration: reduceMotion ? 0.1 : 0.36, ease: "easeOut" }}
        >
          <span>{message}</span>
          <button
            type="button"
            className="settings-message-close"
            title="Close Message"
            aria-label="Close Message"
            onClick={onClose}
          >
            <X size={14} />
          </button>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export default function SpaceSettingsPage({ mode = "mapping" }) {
  const [settingsSection, setSettingsSection] = useState("scanner");
  const category = mode === "mapping" ? "api" : settingsSection;
  const [providerEditor, setProviderEditor] = useState(null);
  const [validatingProvider, setValidatingProvider] = useState("");
  const [togglingProvider, setTogglingProvider] = useState("");
  const [refresh, setRefresh] = useState(0);
  const providers = [
    {
      id: "fofa",
      name: "FOFA",
      region: "National",
      plan: "Free amount / Members",
      fields: [
        ["fofa_email", "Email", false],
        ["fofa_key", "API Key", true],
      ],
    },
    {
      id: "hunter",
      name: "Hunter",
      region: "National",
      plan: "A full set.",
      fields: [["hunter_api_key", "API Key", true]],
    },
    {
      id: "quake",
      name: "360 Quake",
      region: "National",
      plan: "Free amount / Members",
      fields: [["quake_api_key", "API Key", true]],
    },
    {
      id: "zoomeye",
      name: "ZoomEye",
      region: "National",
      plan: "Free amount / Subscriptions",
      fields: [["zoomeye_api_key", "API Key", true]],
    },
    {
      id: "shodan",
      name: "Shodan",
      region: "Overseas",
      plan: "Subscribe Package",
      fields: [["shodan_api_key", "API Key", true]],
    },
    {
      id: "virustotal",
      name: "VirusTotal",
      region: "Overseas",
      plan: "Free amount / Enterprise",
      fields: [["virustotal_api_key", "API Key", true]],
    },
    {
      id: "github",
      name: "GitHub",
      region: "Overseas",
      plan: "Free amount / Token",
      fields: [["github_token", "Personal Access Token", true]],
    },
    {
      id: "custom_space_api",
      name: "Custom interface",
      region: "Custom",
      plan: "Cost by interface",
      validate: false,
      requiredFields: ["custom_space_api_url"],
      fields: [
        ["custom_space_api_url", "Query URL", true],
        ["custom_space_api_headers", "Request JSON", true],
      ],
    },
    {
      id: "enterprise_icp",
      name: "ICP_Query",
      region: "Enterprise assets",
      plan: "From Trust / Compatibility Interface",
      validate: false,
      requiredFields: ["enterprise_icp_api_url"],
      fields: [
        ["enterprise_icp_api_url", "Interface Address", true],
        ["enterprise_icp_api_headers", "Request JSON (Optional)", true],
      ],
    },
  ];
  const scannerKeys = [
    ["domain_concurrency", "Concurrent domain requests", false, "50"],
    ["domain_timeout", "Domain timeout (seconds)", false, "3"],
    ["domain_retry", "Domain retries", false, "2"],
    ["subdomain_takeover_concurrency", "Concurrent subdomain-takeover checks", false, "20"],
    ["port_concurrency_small", "Small Port Collection and Distribution", false, "100"],
    ["port_concurrency_medium", "Medium Port Collection and Distribution", false, "300"],
    ["port_concurrency_large", "Full port and send", false, "500"],
    ["port_timeout", "Port timeout (sec)", false, "1.5"],
    ["site_concurrency", "Site detection and distribution", false, "30"],
    ["site_timeout", "Post timeout (sec)", false, "5"],
    ["crawler_max_depth", "Crawling depth", false, "3"],
    ["crawler_max_pages", "Maximum crawl pages", false, "500"],
    ["service_timeout", "Service detection timed out (sec)", false, "3"],
    ["banner_max_length", "Banner Maximum length", false, "2048"],
    ["file_leak_concurrency", "List of contents", false, "20"],
    ["file_leak_rate_limit", "Catalogue count rate (Request/sec, 0 No speed limit.)", false, "0"],
    ["proxy_auto_check_enabled", "Proxy automatic health check-ups", false, "true"],
    ["proxy_check_interval_seconds", "Proxy Check Interval (sec)", false, "30"],
    ["proxy_rotation_enabled", "Proxy Auto Rotation", false, "true"],
    ["proxy_rotation_interval_seconds", "Proxy Rotation (sec)", false, "30"],
  ];
  const scannerLimits = {
    domain_concurrency: [1, 1000, 1],
    domain_timeout: [0.1, 120, 0.1],
    domain_retry: [0, 10, 1],
    subdomain_takeover_concurrency: [1, 500, 1],
    port_concurrency_small: [1, 5000, 1],
    port_concurrency_medium: [1, 5000, 1],
    port_concurrency_large: [1, 5000, 1],
    port_timeout: [0.1, 60, 0.1],
    site_concurrency: [1, 1000, 1],
    site_timeout: [0.1, 120, 0.1],
    crawler_max_depth: [1, 20, 1],
    crawler_max_pages: [1, 100000, 1],
    service_timeout: [0.1, 60, 0.1],
    banner_max_length: [128, 1048576, 1],
    file_leak_concurrency: [1, 200, 1],
    file_leak_rate_limit: [0, 1000, 1],
    proxy_check_interval_seconds: [10, 86400, 1],
    proxy_rotation_interval_seconds: [10, 86400, 1],
  };
  const notificationChannels = [
    {
      id: "webhook",
      name: "Universal Webhook",
      enabledKey: "webhook_enabled",
      urlKey: "webhook_url",
      secretKey: "webhook_secret",
      urlPlaceholder: "https://example.com/hooks/eclipse-recon",
    },
    {
      id: "dingtalk",
      name: "Nails.",
      enabledKey: "dingding_enabled",
      urlKey: "dingding_webhook",
      secretKey: "dingding_secret",
      urlPlaceholder: "https://oapi.dingtalk.com/robot/send?access_token=...",
    },
    {
      id: "feishu",
      name: "Flying books.",
      enabledKey: "feishu_enabled",
      urlKey: "feishu_webhook",
      secretKey: "feishu_secret",
      urlPlaceholder: "https://open.feishu.cn/open-apis/bot/v2/hook/...",
    },
  ];
  const { data, loading, error } = useQuery(
    `settings-${category}-${refresh}`,
    () => api(`/settings?category=${category}`),
  );
  const [values, setValues] = useState({});
  const [configuredKeys, setConfiguredKeys] = useState(() => new Set());
  const [message, setMessage] = useState("");
  const [testingChannel, setTestingChannel] = useState("");

  useEffect(() => {
    if (!message) return undefined;
    const timer = window.setTimeout(() => setMessage(""), 3000);
    return () => window.clearTimeout(timer);
  }, [message]);

  useEffect(() => {
    if (!data?.settings) return;
    const next = normalizeSettingState(data.settings);
    setValues(next.values);
    setConfiguredKeys(next.configuredKeys);
  }, [data]);

  async function saveScanner(event) {
    event.preventDefault();
    try {
      await api("/settings/batch", {
        method: "POST",
        body: JSON.stringify({
          settings: scannerKeys.map(
            ([key, label, encrypted, defaultValue]) => ({
              category: "scanner",
              key,
              value: values[key] ?? defaultValue ?? "",
              description: label,
              is_encrypted: encrypted,
            }),
          ),
        }),
      });
      setMessage("Parameters saved");
    } catch (error) {
      setMessage(`Save failed: ${error.message}`);
    }
  }

  async function persistNotificationSettings() {
    await api("/settings/batch", {
      method: "POST",
      body: JSON.stringify({
        settings: notificationChannels.flatMap((channel) => [
          {
            category: "notification",
            key: channel.enabledKey,
            value: String(
              values[channel.enabledKey] === true ||
                values[channel.enabledKey] === "true",
            ),
            description: `${channel.name} Enable Status`,
            is_encrypted: false,
          },
          {
            category: "notification",
            key: channel.urlKey,
            value: values[channel.urlKey] || "",
            description: `${channel.name} Address`,
            is_encrypted: true,
          },
          {
            category: "notification",
            key: channel.secretKey,
            value: values[channel.secretKey] || "",
            description: `${channel.name} Sign Key`,
            is_encrypted: true,
          },
        ]),
      }),
    });
  }

  async function saveNotifications(event) {
    event.preventDefault();
    try {
      await persistNotificationSettings();
      setMessage("Notification Configuration Saved");
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`Save failed: ${error.message}`);
    }
  }

  async function testNotification(channel) {
    setTestingChannel(channel.id);
    setMessage("");
    try {
      await persistNotificationSettings();
      await api(`/settings/test-notification/${channel.id}`, {
        method: "POST",
        body: "{}",
      });
      setMessage(`${channel.name} Test message sent`);
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`${channel.name} Test Failed: ${error.message}`);
    } finally {
      setTestingChannel("");
    }
  }

  function editProvider(provider) {
    const credentials = {};
    provider.fields.forEach(([key, , encrypted]) => {
      credentials[key] = encrypted ? "" : values[key] || "";
    });
    setProviderEditor({ provider, credentials, validation: "" });
  }
  async function saveProvider() {
    const { provider, credentials } = providerEditor;
    if (provider.id === "enterprise_icp") {
      try {
        if (credentials.enterprise_icp_api_url) {
          const endpoint = new URL(credentials.enterprise_icp_api_url);
          if (
            !["http:", "https:"].includes(endpoint.protocol) ||
            endpoint.username ||
            endpoint.password
          )
            throw new Error(
              "The URL must use HTTP or HTTPS and must not include a path",
            );
        } else if (!configuredKeys.has("enterprise_icp_api_url")) {
          throw new Error("Interface address cannot be empty");
        }
        const rawHeaders = credentials.enterprise_icp_api_headers.trim();
        if (rawHeaders) {
          const parsedHeaders = JSON.parse(rawHeaders);
          if (!parsedHeaders || Array.isArray(parsedHeaders) || typeof parsedHeaders !== "object" || Object.values(parsedHeaders).some((value) => typeof value !== "string")) throw new Error("The request header must be for string keys JSON Object");
        }
      } catch (error) {
        setProviderEditor((current) => ({ ...current, validation: `Configuration invalid: ${error.message}` }));
        return;
      }
    }
    try {
      await api("/settings/batch", {
        method: "POST",
        body: JSON.stringify({
          settings: provider.fields.map(([key, label, encrypted]) => ({
            category: "api",
            key,
            value: credentials[key] || "",
            description: `${provider.name} ${label}`,
            is_encrypted: encrypted,
            clear_empty: false,
          })),
        }),
      });
      setMessage(`${provider.name} File saved`);
      setProviderEditor(null);
      setRefresh((x) => x + 1);
    } catch (error) {
      setProviderEditor((current) => ({
        ...current,
        validation: `Save failed: ${error.message}`,
      }));
    }
  }
  function providerValidationPayload(provider, credentials) {
    return provider.id === "fofa"
      ? { email: credentials.fofa_email, api_key: credentials.fofa_key }
      : { api_key: credentials[provider.fields[0][0]] };
  }
  async function requestProviderValidation(
    provider,
    credentials,
    useSaved = false,
  ) {
    if (provider.validate === false)
      throw new Error("Custom interfaces need to be saved and authenticated by task");
    return api(`/settings/validate/${provider.id}`, {
      method: "POST",
      body: JSON.stringify({
        credentials: useSaved
          ? {}
          : providerValidationPayload(provider, credentials),
        use_saved: useSaved,
      }),
    });
  }
  async function validateProvider() {
    const { provider, credentials } = providerEditor;
    if (provider.validate === false) {
      setProviderEditor((current) => ({
        ...current,
        validation: "Custom interfaces need to be saved and authenticated by task",
      }));
      return;
    }
    setProviderEditor((current) => ({ ...current, validation: "Validation..." }));
    try {
      await requestProviderValidation(provider, credentials);
      setProviderEditor((current) => ({
        ...current,
        validation: "The evidence is valid., Interface connection successfully",
      }));
    } catch (error) {
      setProviderEditor((current) => ({
        ...current,
        validation: error.message,
      }));
    }
  }
  async function validateSavedProvider(provider) {
    setValidatingProvider(provider.id);
    setMessage("");
    try {
      await requestProviderValidation(provider, {}, true);
      setMessage(`${provider.name} Validation`);
    } catch (error) {
      setMessage(`${provider.name} Validation failed: ${error.message}`);
    } finally {
      setValidatingProvider("");
    }
  }
  function providerEnabled(provider, configured) {
    if (!configured) return false;
    const value = values[`${provider.id}_enabled`];
    return (
      value === undefined ||
      !["false", "0", "no", "off", "disabled"].includes(
        String(value).trim().toLowerCase(),
      )
    );
  }
  async function toggleProvider(provider, configured) {
    if (!configured || togglingProvider) return;
    const key = `${provider.id}_enabled`;
    const enabled = !providerEnabled(provider, configured);
    setTogglingProvider(provider.id);
    setMessage("");
    try {
      await api("/settings", {
        method: "POST",
        body: JSON.stringify({
          category: "api",
          key,
          value: String(enabled),
          description: `${provider.name} Enable Status`,
          is_encrypted: false,
        }),
      });
      setValues((current) => ({ ...current, [key]: String(enabled) }));
      setMessage(`${provider.name} Already${enabled ? "Enable" : "Disable"}`);
    } catch (error) {
      setMessage(`${provider.name} Toggle Failed: ${error.message}`);
    } finally {
      setTogglingProvider("");
    }
  }

  const providerRows = providers.map((provider) => {
    const configured = (
      provider.requiredFields || provider.fields.map(([key]) => key)
    ).every((key) => hasConfiguredSetting(values, configuredKeys, key));

    const enabled = providerEnabled(provider, configured);
    const canValidate = configured && provider.validate !== false;
    const validating = validatingProvider === provider.id;
    const toggling = togglingProvider === provider.id;
    return [
      provider.name,
      provider.region,
      provider.plan,
      <Badge key="status" tone={configured ? "ok" : "muted"}>
        {configured ? "Configured" : "Not configured"}
      </Badge>,
      <button
        type="button"
        role="switch"
        aria-checked={enabled}
        aria-label={
          configured
            ? enabled
              ? `Disable ${provider.name}`
              : `Enable ${provider.name}`
            : `${provider.name} Not configured`
        }
        className={`provider-toggle ${enabled ? "active" : ""}`}
        disabled={!configured || Boolean(togglingProvider)}
        title={
          configured
            ? enabled
              ? `Disable ${provider.name}`
              : `Enable ${provider.name}`
            : "Please configure the documents first."
        }
        onClick={() => toggleProvider(provider, configured)}
      >
        <span className="provider-toggle-track" aria-hidden="true">
          <span />
        </span>
        <span className="provider-toggle-label">
          {toggling ? "Saving" : enabled ? "Enabled" : "Disabled"}
        </span>
      </button>,
      <div className="row-actions" key="actions">
        <button
          className="ghost-button compact"
          onClick={() => editProvider(provider)}
        >
          <Edit3 size={13} />
          Edit
        </button>
        <button
          className="ghost-button compact"
          disabled={!canValidate || validating}
          title={
            provider.validate === false
              ? "Custom interfaces need to be validated by actual request for task"
              : configured
                ? "Validation saved"
                : "Please configure the documents first."
          }
          onClick={() => validateSavedProvider(provider)}
        >
          <RefreshCw size={13} />
          {validating ? "Validation..." : "Validation"}
        </button>
      </div>,
    ];
  });

  return (
    <Panel
      title={category === "api" ? "Intelligence providers" : "System Settings"}
      icon={
        category === "notification" ? (
          <BellRing size={17} />
        ) : (
          <KeyRound size={17} />
        )
      }
    >
      {mode === "settings" && (
        <div className="settings-tabs">
          <Tabs
            value={settingsSection}
            setValue={(value) => {
              setSettingsSection(value);
              setMessage("");
            }}
            items={["scanner", "notification"]}
            labels={{ scanner: "Scan engines", notification: "Announcements" }}
          />
        </div>
      )}
      {category === "api" ? (
        <>
          <div className="provider-intro">
            <span>SPACE SEARCH PROVIDERS</span>
            <p>Configure each provider, Validate and activate suppliers, Validation request also follows an enabled proxy pool.</p>
          </div>
          <DataTable
            storageKey="settings-providers"
            loading={loading}
            columns={["Vendors", "Regional", "The package.", "Configuration", "Enable", "Actions"]}
            rows={providerRows}
            empty="No vendor at present"
          />
        </>
      ) : category === "scanner" ? (
        <form className="settings-form scanner-settings" onSubmit={saveScanner}>
          {scannerKeys.map(([key, label, encrypted, defaultValue]) => (
            <label key={key}>
              {label}
              {key === "proxy_auto_check_enabled" ||
              key === "proxy_rotation_enabled" ? (
                <span className="switch-line">
                  <input
                    id={key}
                    name={key}
                    type="checkbox"
                    checked={
                      (values[key] ?? defaultValue) === "true" ||
                      values[key] === true
                    }
                    onChange={(e) =>
                      setValues({ ...values, [key]: String(e.target.checked) })
                    }
                  />
                  <span>Enable</span>
                </span>
              ) : (
                <input
                  id={key}
                  name={key}
                  type={encrypted ? "password" : "number"}
                  min={scannerLimits[key]?.[0] ?? 0}
                  max={scannerLimits[key]?.[1]}
                  step={scannerLimits[key]?.[2] ?? 1}
                  value={values[key] ?? defaultValue ?? ""}
                  placeholder={
                    key === "custom_space_api_url"
                      ? "https://api.example.com/search?domain={domain}"
                      : ""
                  }
                  onChange={(e) =>
                    setValues({ ...values, [key]: e.target.value })
                  }
                />
              )}
            </label>
          ))}
          <div className="hint">
            Requests are balanced across healthy proxy nodes. Automatic rotation selects a new egress node for each request and applies only to newly started tasks. High concurrency may trigger target rate limits or exhaust local connections.
          </div>
          {loading && <div className="hint">Loading...</div>}
          {error && <div className="error-box">Failed to load: {error}</div>}
          <SettingsMessage message={message} onClose={() => setMessage("")} />
          <button className="primary-button">
            <KeyRound size={16} />
            Save Parameters
          </button>
        </form>
      ) : (
        <form
          className="settings-form notification-settings"
          onSubmit={saveNotifications}
        >
          <div className="provider-intro">
            <span>ALERT DELIVERY</span>
            <p>
              Send alerts through enabled channels when monitors find additions, changes, or execution failures. Individual monitors can disable a channel.
            </p>
          </div>
          {notificationChannels.map((channel) => {
            const enabled =
              values[channel.enabledKey] === true ||
              values[channel.enabledKey] === "true";
            const canTest =
              enabled &&
              hasConfiguredSetting(values, configuredKeys, channel.urlKey) &&
              !testingChannel;
            return (
              <section className="notification-channel" key={channel.id}>
                <div className="notification-channel-head">
                  <div>
                    <strong>{channel.name}</strong>
                    <span>{enabled ? "Enabled" : "Not enabled"}</span>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={enabled}
                    aria-label={`${enabled ? "Disable" : "Enable"}${channel.name}`}
                    className={`provider-toggle ${enabled ? "active" : ""}`}
                    onClick={() =>
                      setValues((current) => ({
                        ...current,
                        [channel.enabledKey]: String(!enabled),
                      }))
                    }
                  >
                    <span className="provider-toggle-track" aria-hidden="true">
                      <span />
                    </span>
                  </button>
                </div>
                <div className="editor-grid">
                  <label>
                    Webhook Address
                    <input
                      name={channel.urlKey}
                      type="password"
                      autoComplete="off"
                      value={values[channel.urlKey] || ""}
                      placeholder={
                        configuredKeys.has(channel.urlKey)
                          ? "Saved, Leave the space unchanged."
                          : channel.urlPlaceholder
                      }
                      onChange={(event) =>
                        setValues((current) => ({
                          ...current,
                          [channel.urlKey]: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <label>
                    Sign Key (Optional)
                    <input
                      name={channel.secretKey}
                      type="password"
                      autoComplete="new-password"
                      value={values[channel.secretKey] || ""}
                      placeholder={
                        configuredKeys.has(channel.secretKey)
                          ? "Saved, Leave the space unchanged."
                          : "Send no signature request when not configured"
                      }
                      onChange={(event) =>
                        setValues((current) => ({
                          ...current,
                          [channel.secretKey]: event.target.value,
                        }))
                      }
                    />
                  </label>
                </div>
                <div className="notification-channel-actions">
                  <button
                    type="button"
                    className="ghost-button compact"
                    disabled={!canTest}
                    title={
                      !enabled
                        ? "Please enable the passage first."
                        : !values[channel.urlKey]
                          ? "Please fill in first. Webhook Address"
                          : "Save the current configuration and send test messages"
                    }
                    onClick={() => testNotification(channel)}
                  >
                    <Send size={13} />
                    {testingChannel === channel.id ? "Sending..." : "Save and Test"}
                  </button>
                </div>
              </section>
            );
          })}
          {loading && <div className="hint">Loading...</div>}
          {error && <div className="error-box">Failed to load: {error}</div>}
          <SettingsMessage message={message} onClose={() => setMessage("")} />
          <button className="primary-button">
            <BellRing size={16} />
            Save Notification Configuration
          </button>
        </form>
      )}
      {category === "api" && (
        <SettingsMessage message={message} onClose={() => setMessage("")} />
      )}
      {providerEditor && (
        <div className="modal-backdrop">
          <div className="library-editor provider-editor">
            <div className="editor-head">
              <div>
                <span className="eyebrow">Provider credential</span>
                <h3>{providerEditor.provider.name}</h3>
              </div>
              <button
                type="button"
                className="icon-button"
                title="Close Configuration"
                aria-label="Close Configuration"
                onClick={() => setProviderEditor(null)}
              >
                <X size={16} />
              </button>
            </div>
            {providerEditor.provider.fields.map(([key, label, encrypted]) => (
              <label key={key}>
                {label}
                <input
                  name={key}
                  type={encrypted ? "password" : "text"}
                  autoComplete={encrypted ? "new-password" : "off"}
                  value={providerEditor.credentials[key] || ""}
                  placeholder={
                    encrypted && configuredKeys.has(key)
                      ? "Saved, Leave the space unchanged."
                      : ""
                  }
                  onChange={(e) =>
                    setProviderEditor((current) => ({
                      ...current,
                      credentials: {
                        ...current.credentials,
                        [key]: e.target.value,
                      },
                      validation: "",
                    }))
                  }
                />
              </label>
            ))}
            {providerEditor.validation && (
              <div
                className={
                  providerEditor.validation.startsWith("The evidence is valid.")
                    ? "success-box"
                    : "hint"
                }
              >
                {providerEditor.validation}
              </div>
            )}
            <div className="editor-actions">
              <button
                type="button"
                className="ghost-button"
                onClick={validateProvider}
              >
                <RefreshCw size={14} />
                Validation of the certificate
              </button>
              <button
                type="button"
                className="primary-button"
                onClick={saveProvider}
              >
                Save Configuration
              </button>
            </div>
          </div>
        </div>
      )}
    </Panel>
  );
}

export function MappingPage() {
  return <SpaceSettingsPage mode="mapping" />;
}

export function SystemSettingsPage() {
  return <SpaceSettingsPage mode="settings" />;
}
