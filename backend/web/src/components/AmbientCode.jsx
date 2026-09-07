import React from "react";

const snippets = [
  "> /bin/recon",
  "const surface = await map(target);",
  "ssh -i vault.key operator@node",
  "if (signal.risk > threshold) alert();",
  "nmap -sV --script safe target",
  "class ProxyPool extends Router {}",
  "await fingerprint(response.body);",
  "MCP / HTTP / ASSET / POC",
];

export default function AmbientCode() {
  return <div className="ambient-code" aria-hidden="true">{snippets.map((snippet, index) => <span key={snippet} style={{ "--code-index": index }}>{snippet}</span>)}</div>;
}
