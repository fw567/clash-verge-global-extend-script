function main(config) {
  // 1. 全局性能优化
  config['unified-delay'] = true;   // 统一延迟计算
  config['tcp-concurrent'] = true;  // TCP 并发连接，提升首屏速度
  config['skip-proxy'] = ['localhost', '127.0.0.1', '::1', '192.168.*', '10.*'];

  // 2. 填充 Rule Providers (包含去广告集)
  if (!config['rule-providers']) config['rule-providers'] = {};
  
  // 防泄露列表
  config['rule-providers']['prevent_dns_leak'] = {
    type: "http",
    interval: 86400,
    behavior: "domain",
    format: "text",
    url: "https://raw.githubusercontent.com/xishang0128/rules/main/clash%20or%20stash/prevent_dns_leak/prevent_dns_leak_domain.list"
  };

  // 3. 提取代理组名称
  const matchRule = config.rules.find(rule => rule.startsWith("MATCH"));
  const proxyName = matchRule ? matchRule.split(",").pop() : "DIRECT";

  // 4. 规则组合
  const customRules = [
    // 使用 REJECT-DROP 彻底屏蔽广告
    'RULE-SET,prevent_dns_leak,' + proxyName, // 你原本的防泄露规则
    
    //逻辑规则示例：GitHub 强制走 TCP 且走代理，防止某些环境下 UDP 导致的连接重置
    `AND,((DOMAIN-SUFFIX,github.com),(NETWORK,TCP)),${proxyName}`,
    `AND,((DOMAIN-KEYWORD,github),(NETWORK,TCP)),${proxyName}`,

    // 屏蔽特定运营商的劫持/测速域名 (使用 REJECT-DROP)
    'DOMAIN-KEYWORD,adscore,REJECT-DROP',
    'DOMAIN-KEYWORD,analytics,REJECT-DROP'
  ];

  // 将自定义规则插入到原规则的最前面
  config.rules = [...customRules, ...config.rules];

  // 5. 进阶 DNS 配置
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false,
    'prefer-h3': true,
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    'proxy-server-nameserver': ['223.5.5.5', '119.29.29.29'], // 节点解析加速
    'nameserver': [
      'https://dns.google/dns-query#proxy',
      'https://1.1.1.1/dns-query#proxy'
    ],
    'nameserver-policy': {
      'geosite:cn': ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'],
      'geosite:gfw,geolocation-!cn': ['https://dns.google/dns-query#proxy', 'https://1.1.1.1/dns-query#proxy']
    },
    'fallback-filter': {
      'geoip': true,
      'geoip-code': 'CN',
      'ipmask': ['240.0.0.0/4']
    },
    'fake-ip-filter': ['*.lan', 'localhost.ptlogin2.qq.com', '+.stun.*.*', '+.msftconnecttest.com']
  };

  // 6. 配置嗅探 (Sniffer)
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
