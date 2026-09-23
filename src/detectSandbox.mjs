import https from "https";
import net from "net";

const SOURCES = [
  // OpenAI
  "https://openai.com/chatgpt-agents.json",
  "https://openai.com/chatgpt-connectors.json",
  "https://openai.com/chatgpt-user.json",

  // Cursor
  "https://cursor.com/docs/ips.json"
];

// Anthropic / Claude
const ANTHROPIC_RANGES = [
  "160.79.104.0/21",
  "2607:6bc0::/48"
];

let ranges = [];
let loaded = false;
let loadingPromise = null;

/* =========================
   DOWNLOAD JSON
========================= */

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(
      url,
      {
        headers: {
          "User-Agent": "AI-Agent-IP-Detector/1.0",
          "Accept": "application/json"
        }
      },
      res => {
        let body = "";

        res.on("data", chunk => {
          body += chunk;
        });

        res.on("end", () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`HTTP ${res.statusCode}`));
            return;
          }

          try {
            resolve(JSON.parse(body));
          } catch {
            reject(new Error("Invalid JSON"));
          }
        });
      }
    ).on("error", reject);
  });
}

/* =========================
   IPv4
========================= */

function ipv4ToNumber(ip) {
  const parts = ip.split(".");

  if (parts.length !== 4) {
    return null;
  }

  let result = 0;

  for (const part of parts) {
    const n = Number(part);

    if (!Number.isInteger(n) || n < 0 || n > 255) {
      return null;
    }

    result = ((result << 8) | n) >>> 0;
  }

  return result;
}

function matchesIPv4(ip, cidr) {
  const [network, prefixText] = cidr.split("/");
  const prefix = Number(prefixText);

  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }

  const ipNum = ipv4ToNumber(ip);
  const networkNum = ipv4ToNumber(network);

  if (ipNum === null || networkNum === null) {
    return false;
  }

  if (prefix === 0) {
    return true;
  }

  const mask = (0xffffffff << (32 - prefix)) >>> 0;

  return (ipNum & mask) === (networkNum & mask);
}

/* =========================
   IPv6
========================= */

function expandIPv6(ip) {
  // IPv4-mapped IPv6
  if (ip.includes(".")) {
    const index = ip.lastIndexOf(":");

    if (index === -1) {
      return null;
    }

    const ipv4 = ip.slice(index + 1);
    const num = ipv4ToNumber(ipv4);

    if (num === null) {
      return null;
    }

    const high = ((num >>> 16) & 0xffff)
      .toString(16)
      .padStart(4, "0");

    const low = (num & 0xffff)
      .toString(16)
      .padStart(4, "0");

    ip = ip.slice(0, index + 1) + high + ":" + low;
  }

  const parts = ip.split("::");

  if (parts.length > 2) {
    return null;
  }

  let groups;

  if (parts.length === 2) {
    const left = parts[0] ? parts[0].split(":") : [];
    const right = parts[1] ? parts[1].split(":") : [];

    const missing = 8 - left.length - right.length;

    if (missing < 1) {
      return null;
    }

    groups = [
      ...left,
      ...Array(missing).fill("0"),
      ...right
    ];
  } else {
    groups = ip.split(":");

    if (groups.length !== 8) {
      return null;
    }
  }

  if (groups.length !== 8) {
    return null;
  }

  const numbers = groups.map(x => parseInt(x, 16));

  if (
    numbers.some(
      x => !Number.isInteger(x) || x < 0 || x > 0xffff
    )
  ) {
    return null;
  }

  return numbers;
}

function matchesIPv6(ip, cidr) {
  const [network, prefixText] = cidr.split("/");
  const prefix = Number(prefixText);

  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) {
    return false;
  }

  const ipGroups = expandIPv6(ip);
  const networkGroups = expandIPv6(network);

  if (!ipGroups || !networkGroups) {
    return false;
  }

  let remaining = prefix;

  for (let i = 0; i < 8; i++) {
    if (remaining <= 0) {
      break;
    }

    const bits = Math.min(remaining, 16);

    const mask =
      bits === 16
        ? 0xffff
        : (0xffff << (16 - bits)) & 0xffff;

    if ((ipGroups[i] & mask) !== (networkGroups[i] & mask)) {
      return false;
    }

    remaining -= bits;
  }

  return true;
}

/* =========================
   CIDR MATCH
========================= */

function matches(ip, cidr) {
  if (!ip || !cidr) {
    return false;
  }

  if (cidr.includes(":")) {
    return net.isIPv6(ip) && matchesIPv6(ip, cidr);
  }

  return net.isIPv4(ip) && matchesIPv4(ip, cidr);
}

/* =========================
   EXTRACT RANGES
========================= */

function extractRanges(data, output) {
  if (!data || typeof data !== "object") {
    return;
  }

  // OpenAI
  if (Array.isArray(data.prefixes)) {
    output.push(...data.prefixes);
  }

  // Generic formats
  if (Array.isArray(data.ipv4)) {
    output.push(...data.ipv4);
  }

  if (Array.isArray(data.ipv6)) {
    output.push(...data.ipv6);
  }

  // Cursor Cloud Agents
  if (data.cloudAgents) {
    for (const region of Object.values(data.cloudAgents)) {
      if (Array.isArray(region)) {
        output.push(...region);
      }
    }
  }

  // Cursor Git egress
  if (Array.isArray(data.gitEgressProxy)) {
    output.push(...data.gitEgressProxy);
  }
}

/* =========================
   LOAD ALL PROVIDERS
========================= */

async function loadRanges() {
  const newRanges = [
    ...ANTHROPIC_RANGES
  ];

  for (const url of SOURCES) {
    try {
      const data = await fetchJSON(url);

      extractRanges(data, newRanges);

    } catch (error) {
      console.error(
        `Failed to load ${url}: ${error.message}`
      );
    }
  }

  ranges = [
    ...new Set(
      newRanges.filter(
        range =>
          typeof range === "string" &&
          range.includes("/")
      )
    )
  ];

  loaded = true;

  console.log(
    `Loaded ${ranges.length} AI IP ranges`
  );
}

/* =========================
   MAIN FUNCTION
========================= */

export async function isAIAgent(ip) {
  if (!net.isIP(ip)) {
    return false;
  }

  if (!loaded) {
    // Ensure concurrent calls share a single in-flight load
    if (!loadingPromise) {
      loadingPromise = loadRanges().finally(() => {
        loadingPromise = null;
      });
    }
    await loadingPromise;
  }

  return ranges.some(range =>
    matches(ip, range)
  );
}

export default isAIAgent;