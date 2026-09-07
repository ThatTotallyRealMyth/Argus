import React, { useEffect, useState } from "react";
import { BellRing, Edit3, KeyRound, RefreshCw, Send, X } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { Badge, DataTable, Panel, Tabs } from "../components/ui.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api } from "../lib/api.js";
import { hasConfiguredSetting, normalizeSettingState } from "../lib/settings.js";

function SettingsMessage({ message, onClose }) {
  const reduceMotion = useReducedMotion();
  const failed = message.includes("失败");
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
            title="关闭消息"
            aria-label="关闭消息"
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
      region: "国内",
      plan: "免费额度 / 会员",
      fields: [
        ["fofa_email", "Email", false],
        ["fofa_key", "API Key", true],
      ],
    },
    {
      id: "hunter",
      name: "Hunter",
      region: "国内",
      plan: "积分套餐",
      fields: [["hunter_api_key", "API Key", true]],
    },
    {
      id: "quake",
      name: "360 Quake",
      region: "国内",
      plan: "免费额度 / 会员",
      fields: [["quake_api_key", "API Key", true]],
    },
    {
      id: "zoomeye",
      name: "ZoomEye",
      region: "国内",
      plan: "免费额度 / 订阅",
      fields: [["zoomeye_api_key", "API Key", true]],
    },
    {
      id: "shodan",
      name: "Shodan",
      region: "海外",
      plan: "订阅套餐",
      fields: [["shodan_api_key", "API Key", true]],
    },
    {
      id: "virustotal",
      name: "VirusTotal",
      region: "海外",
      plan: "免费额度 / 企业",
      fields: [["virustotal_api_key", "API Key", true]],
    },
    {
      id: "github",
      name: "GitHub",
      region: "海外",
      plan: "免费额度 / Token",
      fields: [["github_token", "Personal Access Token", true]],
    },
    {
      id: "custom_space_api",
      name: "自定义接口",
      region: "自定义",
      plan: "按接口方计费",
      validate: false,
      requiredFields: ["custom_space_api_url"],
      fields: [
        ["custom_space_api_url", "查询 URL", true],
        ["custom_space_api_headers", "请求头 JSON", true],
      ],
    },
    {
      id: "enterprise_icp",
      name: "ICP_Query",
      region: "企业资产",
      plan: "自托管 / 兼容接口",
      validate: false,
      requiredFields: ["enterprise_icp_api_url"],
      fields: [
        ["enterprise_icp_api_url", "接口地址", true],
        ["enterprise_icp_api_headers", "请求头 JSON（可选）", true],
      ],
    },
  ];
  const scannerKeys = [
    ["domain_concurrency", "域名并发", false, "50"],
    ["domain_timeout", "域名超时（秒）", false, "3"],
    ["domain_retry", "域名重试", false, "2"],
    ["subdomain_takeover_concurrency", "子域接管检测并发", false, "20"],
    ["port_concurrency_small", "小端口集并发", false, "100"],
    ["port_concurrency_medium", "中端口集并发", false, "300"],
    ["port_concurrency_large", "全端口并发", false, "500"],
    ["port_timeout", "端口超时（秒）", false, "1.5"],
    ["site_concurrency", "站点探测并发", false, "30"],
    ["site_timeout", "站点超时（秒）", false, "5"],
    ["crawler_max_depth", "爬虫深度", false, "3"],
    ["crawler_max_pages", "爬虫最大页面", false, "500"],
    ["service_timeout", "服务识别超时（秒）", false, "3"],
    ["banner_max_length", "Banner 最大长度", false, "2048"],
    ["file_leak_concurrency", "目录枚举并发", false, "20"],
    ["file_leak_rate_limit", "目录枚举速率（请求/秒，0 不限速）", false, "0"],
    ["proxy_auto_check_enabled", "代理自动健康检查", false, "true"],
    ["proxy_check_interval_seconds", "代理检查间隔（秒）", false, "30"],
    ["proxy_rotation_enabled", "代理自动轮换", false, "true"],
    ["proxy_rotation_interval_seconds", "代理轮换间隔（秒）", false, "30"],
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
      name: "通用 Webhook",
      enabledKey: "webhook_enabled",
      urlKey: "webhook_url",
      secretKey: "webhook_secret",
      urlPlaceholder: "https://example.com/hooks/eclipse-recon",
    },
    {
      id: "dingtalk",
      name: "钉钉",
      enabledKey: "dingding_enabled",
      urlKey: "dingding_webhook",
      secretKey: "dingding_secret",
      urlPlaceholder: "https://oapi.dingtalk.com/robot/send?access_token=...",
    },
    {
      id: "feishu",
      name: "飞书",
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
      setMessage("参数已保存");
    } catch (error) {
      setMessage(`保存失败：${error.message}`);
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
            description: `${channel.name} 启用状态`,
            is_encrypted: false,
          },
          {
            category: "notification",
            key: channel.urlKey,
            value: values[channel.urlKey] || "",
            description: `${channel.name} 地址`,
            is_encrypted: true,
          },
          {
            category: "notification",
            key: channel.secretKey,
            value: values[channel.secretKey] || "",
            description: `${channel.name} 签名密钥`,
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
      setMessage("通知配置已保存");
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`保存失败：${error.message}`);
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
      setMessage(`${channel.name} 测试消息已发送`);
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`${channel.name} 测试失败：${error.message}`);
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
              "协议必须是 HTTP 或 HTTPS，且 URL 不能包含账号密码",
            );
        } else if (!configuredKeys.has("enterprise_icp_api_url")) {
          throw new Error("接口地址不能为空");
        }
        const rawHeaders = credentials.enterprise_icp_api_headers.trim();
        if (rawHeaders) {
          const parsedHeaders = JSON.parse(rawHeaders);
          if (!parsedHeaders || Array.isArray(parsedHeaders) || typeof parsedHeaders !== "object" || Object.values(parsedHeaders).some((value) => typeof value !== "string")) throw new Error("请求头必须是字符串键值的 JSON 对象");
        }
      } catch (error) {
        setProviderEditor((current) => ({ ...current, validation: `配置无效：${error.message}` }));
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
      setMessage(`${provider.name} 凭据已保存`);
      setProviderEditor(null);
      setRefresh((x) => x + 1);
    } catch (error) {
      setProviderEditor((current) => ({
        ...current,
        validation: `保存失败：${error.message}`,
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
      throw new Error("自定义接口需要保存后通过任务实际请求验证");
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
        validation: "自定义接口需要保存后通过任务实际请求验证",
      }));
      return;
    }
    setProviderEditor((current) => ({ ...current, validation: "验证中..." }));
    try {
      await requestProviderValidation(provider, credentials);
      setProviderEditor((current) => ({
        ...current,
        validation: "凭据有效，接口连接成功",
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
      setMessage(`${provider.name} 凭据验证通过`);
    } catch (error) {
      setMessage(`${provider.name} 验证失败：${error.message}`);
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
          description: `${provider.name} 启用状态`,
          is_encrypted: false,
        }),
      });
      setValues((current) => ({ ...current, [key]: String(enabled) }));
      setMessage(`${provider.name} 已${enabled ? "启用" : "停用"}`);
    } catch (error) {
      setMessage(`${provider.name} 切换失败：${error.message}`);
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
        {configured ? "已配置" : "未配置"}
      </Badge>,
      <button
        type="button"
        role="switch"
        aria-checked={enabled}
        aria-label={
          configured
            ? enabled
              ? `停用 ${provider.name}`
              : `启用 ${provider.name}`
            : `${provider.name} 未配置`
        }
        className={`provider-toggle ${enabled ? "active" : ""}`}
        disabled={!configured || Boolean(togglingProvider)}
        title={
          configured
            ? enabled
              ? `停用 ${provider.name}`
              : `启用 ${provider.name}`
            : "请先配置凭据"
        }
        onClick={() => toggleProvider(provider, configured)}
      >
        <span className="provider-toggle-track" aria-hidden="true">
          <span />
        </span>
        <span className="provider-toggle-label">
          {toggling ? "保存中" : enabled ? "已启用" : "已停用"}
        </span>
      </button>,
      <div className="row-actions" key="actions">
        <button
          className="ghost-button compact"
          onClick={() => editProvider(provider)}
        >
          <Edit3 size={13} />
          编辑
        </button>
        <button
          className="ghost-button compact"
          disabled={!canValidate || validating}
          title={
            provider.validate === false
              ? "自定义接口需通过任务实际请求验证"
              : configured
                ? "验证已保存凭据"
                : "请先配置凭据"
          }
          onClick={() => validateSavedProvider(provider)}
        >
          <RefreshCw size={13} />
          {validating ? "验证中..." : "验证"}
        </button>
      </div>,
    ];
  });

  return (
    <Panel
      title={category === "api" ? "测绘数据源" : "系统设置"}
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
            labels={{ scanner: "扫描引擎", notification: "通知" }}
          />
        </div>
      )}
      {category === "api" ? (
        <>
          <div className="provider-intro">
            <span>SPACE SEARCH PROVIDERS</span>
            <p>逐条配置、验证并启用供应商，验证请求同样遵循已启用的代理池。</p>
          </div>
          <DataTable
            storageKey="settings-providers"
            loading={loading}
            columns={["供应商", "区域", "套餐", "配置", "启用", "操作"]}
            rows={providerRows}
            empty="暂无供应商"
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
                  <span>启用</span>
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
            代理请求按健康节点轮询实现负载均衡；开启自动轮换后，轮询起点按间隔换位。修改后仅影响新启动的任务。并发值过高可能触发目标限速或耗尽本机连接。
          </div>
          {loading && <div className="hint">加载中...</div>}
          {error && <div className="error-box">加载失败：{error}</div>}
          <SettingsMessage message={message} onClose={() => setMessage("")} />
          <button className="primary-button">
            <KeyRound size={16} />
            保存参数
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
              监控发现新增、变化或执行失败时，通过启用的通道发送告警。每个监控仍可单独关闭某个通道。
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
                    <span>{enabled ? "已启用" : "未启用"}</span>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={enabled}
                    aria-label={`${enabled ? "停用" : "启用"}${channel.name}`}
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
                    Webhook 地址
                    <input
                      name={channel.urlKey}
                      type="password"
                      autoComplete="off"
                      value={values[channel.urlKey] || ""}
                      placeholder={
                        configuredKeys.has(channel.urlKey)
                          ? "已保存，留空保持不变"
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
                    签名密钥（可选）
                    <input
                      name={channel.secretKey}
                      type="password"
                      autoComplete="new-password"
                      value={values[channel.secretKey] || ""}
                      placeholder={
                        configuredKeys.has(channel.secretKey)
                          ? "已保存，留空保持不变"
                          : "未配置时发送无签名请求"
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
                        ? "请先启用该通道"
                        : !values[channel.urlKey]
                          ? "请先填写 Webhook 地址"
                          : "保存当前配置并发送测试消息"
                    }
                    onClick={() => testNotification(channel)}
                  >
                    <Send size={13} />
                    {testingChannel === channel.id ? "发送中..." : "保存并测试"}
                  </button>
                </div>
              </section>
            );
          })}
          {loading && <div className="hint">加载中...</div>}
          {error && <div className="error-box">加载失败：{error}</div>}
          <SettingsMessage message={message} onClose={() => setMessage("")} />
          <button className="primary-button">
            <BellRing size={16} />
            保存通知配置
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
                title="关闭配置"
                aria-label="关闭配置"
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
                      ? "已保存，留空保持不变"
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
                  providerEditor.validation.startsWith("凭据有效")
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
                验证凭据
              </button>
              <button
                type="button"
                className="primary-button"
                onClick={saveProvider}
              >
                保存配置
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
