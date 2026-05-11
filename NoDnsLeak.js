export default function main(config) {
  // 1. 填充 rule-provider (防泄露域名集)
  if (!config['rule-providers']) config['rule-providers'] = {};
  config['rule-providers']['prevent_dns_leak'] = {
    type: "http",
    interval: 86400,
    behavior: "domain",
    format: "text",
    url: "https://raw.githubusercontent.com/xishang0128/rules/main/clash%20or%20stash/prevent_dns_leak/prevent_dns_leak_domain.list"
  };

  // 2. 规则置顶：确保防泄露规则最先匹配
  const matchRule = config.rules.find(rule => rule.startsWith("MATCH"));
  const proxyGroupName = matchRule ? matchRule.split(",").pop() : "DIRECT"; 
  config.rules.unshift(`RULE-SET,prevent_dns_leak,${proxyGroupName}`);

  // 3. DNS 模块深度优化
  config['dns'] = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false, // 建议关闭 IPv6 以彻底杜绝双栈泄露
    'prefer-h3': true, // 【进阶】开启 HTTP/3 优先，利用节点的 UDP 转发加速
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    'nameserver': [
      'https://dns.alidns.com/dns-query',
      'https://doh.pub/dns-query'
    ],
    'fallback': [
      'https://dns.google/dns-query',
      'https://1.1.1.1/dns-query'
    ],
    'nameserver-policy': {
      'geosite:cn': ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'],
      'geosite:gfw,geolocation-!cn': ['https://dns.google/dns-query', 'https://1.1.1.1/dns-query']
    },
    'fake-ip-filter': [
      '*.lan',
      '+.stun.*.*',
      '+.stun.*.*.*',
      '+.msftconnecttest.com',
      '+.msftncsi.com', // 解决 Windows 网络图标感叹号
      'localhost.ptlogin2.qq.com'
    ]
  };

  // 4. 流量嗅探 (Sniffer)：识别加密流量中的真实域名
  config['sniffer'] = {
    'enable': true,
    'sniff': {
      'TLS': { 'ports': [443, 8443] },
      'HTTP': { 'ports': [80, '8080-8880'], 'override-destination': true },
      'QUIC': { 'ports': [443, 8443] } // 【进阶】开启 QUIC 嗅探
    },
    'force-domain': ['google.com'] // 强制特定域名进行嗅探
  };

  return config;
}
