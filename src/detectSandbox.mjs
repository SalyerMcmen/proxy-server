import dns from 'node:dns/promises';
import net from 'node:net';

const KNOWN_RANGES = {
  cursor: [
    '100.26.13.169/32',
    '34.195.201.10/32',
    '54.184.235.255/32',
    '35.167.37.158/32',
    '3.12.82.200/32',
    '52.14.104.140/32',
    '184.73.225.134/32',
    '3.209.66.12/32',
    '52.44.113.131/32',
  ],

  github_copilot: [],
  codex: [],
  claude: [],
  replit: [],
  gitpod: [],
  codespaces: [],

  aws: [],
  azure: [],
  gcp: [],
};

const AI_PROVIDERS = new Set([
  'cursor',
  'github_copilot',
  'codex',
  'claude',
  'replit',
  'gitpod',
  'codespaces',
]);

function ipToInt(ip) {
  if (!net.isIPv4(ip)) {
    return null;
  }

  return ip
    .split('.')
    .map(Number)
    .reduce(
      (result, octet) =>
        ((result << 8) | octet) >>> 0,
      0
    );
}

function matchesCIDR(ip, cidr) {
  const [network, prefixText] = cidr.split('/');
  const prefix = Number(prefixText);

  const ipInt = ipToInt(ip);
  const networkInt = ipToInt(network);

  if (ipInt === null || networkInt === null) {
    return false;
  }

  if (
    !Number.isInteger(prefix) ||
    prefix < 0 ||
    prefix > 32
  ) {
    return false;
  }

  if (prefix === 0) {
    return true;
  }

  const mask =
    (0xffffffff << (32 - prefix)) >>> 0;

  return (
    (ipInt & mask) ===
    (networkInt & mask)
  );
}

/**
 * Detect the network origin of a request.
 *
 * IMPORTANT:
 * This identifies infrastructure/network origin.
 * It does NOT prove that a human is using AI.
 */
export async function detectSandbox(ip) {
  ip = String(ip || '')
    .replace(/^::ffff:/, '')
    .trim();

  const result = {
    ip,
    provider: null,
    type: 'unknown',
    confidence: 'low',
    reverseDNS: [],
    evidence: [],
  };

  if (!net.isIPv4(ip)) {
    result.type = 'invalid_ip';
    return result;
  }

  /*
   * 1. Exact / known CIDR match
   */
  for (const [provider, ranges] of Object.entries(
    KNOWN_RANGES
  )) {
    for (const cidr of ranges) {
      if (matchesCIDR(ip, cidr)) {
        result.provider = provider;

        result.type = AI_PROVIDERS.has(provider)
          ? 'known_ai_agent'
          : 'cloud_provider';

        result.confidence = 'high';

        result.evidence.push({
          method: 'cidr',
          value: cidr,
        });

        return result;
      }
    }
  }

  /*
   * 2. Reverse DNS
   */
  try {
    result.reverseDNS = await dns.reverse(ip);
  } catch {
    result.reverseDNS = [];
  }

  const hostname = result.reverseDNS
    .join(' ')
    .toLowerCase();

  /*
   * 3. Infrastructure hints
   *
   * These are NOT proof.
   */
  const hints = [
    ['cursor', 'cursor'],
    ['codespaces', 'codespaces'],
    ['gitpod', 'gitpod'],
    ['replit', 'replit'],
    ['copilot', 'github_copilot'],
    ['github', 'github_copilot'],
    ['codex', 'codex'],
    ['claude', 'claude'],
    ['amazonaws', 'aws'],
    ['azure', 'azure'],
    ['googleusercontent', 'gcp'],
  ];

  for (const [keyword, provider] of hints) {
    if (hostname.includes(keyword)) {
      result.provider = provider;

      if (AI_PROVIDERS.has(provider)) {
        result.type =
          'possible_ai_or_cloud_environment';
      } else {
        result.type =
          'possible_cloud_provider';
      }

      result.confidence = 'medium';

      result.evidence.push({
        method: 'reverse_dns',
        keyword,
      });

      return result;
    }
  }

  /*
   * 4. Nothing recognized
   */
  result.type = 'unknown_or_residential';

  return result;
}