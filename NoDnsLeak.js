function main(config) {
  // --- 1. 基础性能与本地开发优化 ---
  config['tcp-concurrent'] = true;      // 开启 TCP 并发
  config['fast-open'] = true;           // 开启 TCP Fast Open
  config['read-buffer-size'] = 131072;  // 128KB 缓冲区：兼顾 1080p 的起跳和 8K 的吞吐
  config['unified-delay'] = true;       // 统一延迟计算
  config['find-process-mode'] = 'always';
  config['skip-proxy'] = ['localhost', '127.0.0.1', '::1', '192.168.*', '10.*'];

  // --- 2. 规则集配置 (Rule Provider) ---
  if (!config['rule-providers']) config['rule-providers'] = {};
  config['rule-providers']['prevent_dns_leak'] = {
    type: "http",
    interval: 86400,
    behavior: "domain",
    format: "text",
    url: "https://raw.githubusercontent.com/xishang0128/rules/main/clash%20or%20stash/prevent_dns_leak/prevent_dns_leak_domain.list"
  };

  // --- 3. 动态提取代理组名称 ---
  const matchRule = config.rules.find(rule => rule.startsWith("MATCH"));
  const proxyName = matchRule ? matchRule.split(",").pop() : "DIRECT";

  // --- 4. 规则置顶与逻辑规则 (广告拦截 + 视频置顶 + 开发优化) ---
  const customRules = [
    `DOMAIN-KEYWORD,googlevideo,${proxyName}`,    // 视频流强制置顶，起跳更快
    `RULE-SET,prevent_dns_leak,${proxyName}`,    // DNS 防泄露列表
    `AND,((DOMAIN-SUFFIX,github.com),(NETWORK,TCP)),${proxyName}`, // GitHub TCP 稳连
    'DOMAIN-KEYWORD,adscore,REJECT-DROP',        // 广告黑洞
    'DOMAIN-KEYWORD,analytics,REJECT-DROP',      // 追踪器黑洞
    'DOMAIN-KEYWORD,analysis,REJECT-DROP'
  ];
  config.rules = [...customRules, ...config.rules];

  // --- 5. DNS 零泄露架构 (Policy 模式) ---
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false,
    'prefer-h3': true,
    'default-nameserver': ['223.5.5.5'],
    'proxy-server-nameserver': ['223.5.5.5'],    // 节点解析加速
    'nameserver': ['https://dns.google/dns-query#proxy'],
    'nameserver-policy': {
      'geosite:cn': ['https://dns.alidns.com/dns-query'],
      'geosite:gfw,geolocation-!cn': ['https://dns.google/dns-query#proxy']
    }
  };

  // --- 6. 嗅探配置---
  config.sniffer = {
    'enable': true,
    'sniff': {
      'TLS': { 'ports': [443], 'override-destination': true },
      'QUIC': { 'ports': [443], 'override-destination': true }
    },
    'force-domain': ['googlevideo.com']
  };

  return config;
}
