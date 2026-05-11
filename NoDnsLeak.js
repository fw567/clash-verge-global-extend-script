function main(config) {
  // 1. 规则集配置保持不变
  if (!config['rule-providers']) config['rule-providers'] = {};
  config['rule-providers']['prevent_dns_leak'] = {
    type: "http",
    interval: 86400,
    behavior: "domain",
    format: "text",
    url: "https://raw.githubusercontent.com/xishang0128/rules/main/clash%20or%20stash/prevent_dns_leak/prevent_dns_leak_domain.list"
  };

  const matchRule = config.rules.find(rule => rule.startsWith("MATCH"));
  const proxyName = matchRule ? matchRule.split(",").pop() : null;
  if (proxyName) {
    config.rules.unshift(`RULE-SET,prevent_dns_leak,${proxyName}`);
  }

  // 2. DNS 进阶配置：使用 nameserver-policy 主导分流
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false,
    'prefer-h3': true,
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    
    // 默认 DNS：作为兜底，走代理远端解析
    'nameserver': [
      'https://dns.google/dns-query#proxy',
      'https://1.1.1.1/dns-query#proxy'
    ],

    // 精准路由策略 (取代被动的 fallback-filter 逻辑)
    'nameserver-policy': {
      // 明确是国内的走国内解析
      'geosite:cn': [
        'https://dns.alidns.com/dns-query',
        'https://doh.pub/dns-query'
      ],
      // 明确是被墙的域名，强制只走代理端解析，不经过任何本地 DNS
      'geosite:gfw,geolocation-!cn': [
        'https://dns.google/dns-query#proxy',
        'https://1.1.1.1/dns-query#proxy'
      ]
    },

    // 虽然有了 policy，但 fallback-filter 依然建议保留作为最后的 IP 审计手段
    'fallback-filter': {
      'geoip': true,
      'geoip-code': 'CN',
      'ipmask': ['240.0.0.0/4']
    },
    'fake-ip-filter': ['*.lan', 'localhost.ptlogin2.qq.com', '+.stun.*.*', '+.msftconnecttest.com']
  };

  config.sniffer = {
    'enable': true,
    'sniff': {
      'TLS': { 'ports': [443, 8443] },
      'HTTP': { 'ports': [80, '8080-8880'], 'override-destination': true },
      'QUIC': { 'ports': [443, 8443] }
    }
  };

  return config;
}
