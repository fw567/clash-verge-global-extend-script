function main(config) {
  // 1. 填充 rule-provider (防泄露域名集)
  if (!config['rule-providers']) {
    config['rule-providers'] = {};
  }
  config['rule-providers']['prevent_dns_leak'] = {
    type: "http",
    interval: 86400,
    behavior: "domain",
    format: "text",
    url: "https://raw.githubusercontent.com/xishang0128/rules/main/clash%20or%20stash/prevent_dns_leak/prevent_dns_leak_domain.list"
  };

  // 2. 填充规则：自动寻找 MATCH 组并将防泄露规则置顶
  const matchRule = config.rules.find(rule => rule.startsWith("MATCH"));
  const proxyName = matchRule ? matchRule.split(",").pop() : null;
  if (proxyName) {
    // 强制让防泄露列表里的域名走代理组
    config.rules.unshift(`RULE-SET,prevent_dns_leak,${proxyName}`);
  }

  // 3. 核心 DNS 进阶配置 (覆盖原有的简单修改)
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false, // 彻底禁用 IPv6 解析
    'prefer-h3': true, // 开启 HTTP/3 优化
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    // 基础 DNS：默认全部走国外加密 DoH，确保未知域名不泄露
    'nameserver': [
      'https://dns.google/dns-query',
      'https://1.1.1.1/dns-query'
    ],
    // 策略分流：只有明确的中国域名，才允许走国内 DNS
    'nameserver-policy': {
      'geosite:cn': [
        'https://dns.alidns.com/dns-query',
        'https://doh.pub/dns-query'
      ]
    },
    // 强制过滤逻辑：防止国内 DNS 抢答国外域名
    'fallback-filter': {
      'geoip': true,
      'geoip-code': 'CN',
      'geosite': ['gfw'],
      'ipmask': ['240.0.0.0/4']
    },
    'fake-ip-filter': [
      '*.lan',
      'localhost.ptlogin2.qq.com',
      '+.stun.*.*',
      '+.stun.*.*.*',
      '+.msftconnecttest.com',
      '+.msftncsi.com'
    ]
  };

  // 4. 配置流量嗅探 (Sniffer)
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
