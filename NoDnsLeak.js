function main(config) {
  // 1. 全局性能与大带宽优化
  config['tcp-concurrent'] = true;      // TCP 并发
  config['fast-open'] = true;          // TCP Fast Open
  config['read-buffer-size'] = 524288; // 512KB 缓冲区，支持 8K/16K
  config['unified-delay'] = true;       // 统一延迟
  config['find-process-mode'] = 'always';
  // 过滤本地开发环境
  config['skip-proxy'] = ['localhost', '127.0.0.1', '::1', '192.168.*', '10.*'];

  // 2. 规则集配置 (Rule Provider)
  if (!config['rule-providers']) config['rule-providers'] = {};
  config['rule-providers']['prevent_dns_leak'] = {
    type: "http",
    interval: 86400,
    behavior: "domain",
    format: "text",
    url: "https://raw.githubusercontent.com/xishang0128/rules/main/clash%20or%20stash/prevent_dns_leak/prevent_dns_leak_domain.list"
  };

  // 3. 动态匹配代理组
  const matchRule = config.rules.find(rule => rule.startsWith("MATCH"));
  const proxyName = matchRule ? matchRule.split(",").pop() : "DIRECT";

  // 4. 规则置顶与逻辑规则 (整合广告拦截、GitHub 优化、视频加速)
  const customRules = [
    `DOMAIN-KEYWORD,googlevideo,${proxyName}`,    // 视频流强制置顶
    `RULE-SET,prevent_dns_leak,${proxyName}`,    // DNS 防泄露列表
    `AND,((DOMAIN-SUFFIX,github.com),(NETWORK,TCP)),${proxyName}`, // GitHub TCP 稳连
    'DOMAIN-KEYWORD,adscore,REJECT-DROP',        // 广告黑洞拦截
    'DOMAIN-KEYWORD,analytics,REJECT-DROP',      // 追踪器黑洞拦截
    'DOMAIN-KEYWORD,analysis,REJECT-DROP'
  ];
  config.rules = [...customRules, ...config.rules];

  // 5. 终极 DNS 零泄露架构 (使用 policy 替代 fallback-filter)
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false,
    'prefer-h3': true,
    'default-nameserver': ['223.5.5.5'],
    'proxy-server-nameserver': ['223.5.5.5'], // 节点解析直连加速
    'nameserver': ['https://dns.google/dns-query#proxy'],
    'nameserver-policy': {
      'geosite:cn': ['https://dns.alidns.com/dns-query'],
      'geosite:gfw,geolocation-!cn': ['https://dns.google/dns-query#proxy']
    }
  };

  // 6. 流量嗅探
  config.sniffer = {
    'enable': true,
    'sniff': {
      'TLS': { 'ports': [443, 8443], 'override-destination': true },
      'HTTP': { 'ports': [80, '8080-8880'], 'override-destination': true },
      'QUIC': { 'ports': [443, 8443], 'override-destination': true }
    },
    'force-domain': ['googlevideo.com']
  };

  return config;
}
