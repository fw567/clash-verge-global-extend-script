function main(config) {
  // 1. 极致起跳优化 (针对 TTFB 和首包响应)
  config['tcp-concurrent'] = true;       // TCP 并发
  config['fast-open'] = true;           // 开启 TCP Fast Open (减少握手往返)
  config['read-buffer-size'] = 262144;  
  config['udp-timeout'] = 300;
  config['unified-delay'] = true;

  // 2. DNS 极致加速
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false,
    'prefer-h3': true,
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    'proxy-server-nameserver': ['223.5.5.5'], // 节点解析直连化
    'nameserver': ['https://dns.google/dns-query#proxy'],
    'nameserver-policy': {
      'geosite:cn': ['https://dns.alidns.com/dns-query'],
      'geosite:gfw,geolocation-!cn': ['https://dns.google/dns-query#proxy']
    }
  };

  // 3. 嗅探逻辑精简
  config.sniffer = {
    'enable': true,
    'sniff': {
      'TLS': { 'ports': [443, 8443], 'override-destination': true },
      'HTTP': { 'ports': [80, '8080-8880'], 'override-destination': true },
      'QUIC': { 'ports': [443, 8443], 'override-destination': true }
    },
    'force-domain': ['googlevideo.com'] // 仅针对视频流强制还原，减少其他干扰
  };

  // 4. 规则置顶
  if (!config['rule-providers']) config['rule-providers'] = {};
  config['rule-providers']['prevent_dns_leak'] = {
    type: "http",
    interval: 86400,
    behavior: "domain",
    format: "text",
    url: "https://raw.githubusercontent.com/xishang0128/rules/main/clash%20or%20stash/prevent_dns_leak/prevent_dns_leak_domain.list"
  };

  const matchRule = config.rules.find(rule => rule.startsWith("MATCH"));
  const proxyName = matchRule ? matchRule.split(",").pop() : "DIRECT";
  config.rules = [
    `RULE-SET,prevent_dns_leak,${proxyName}`,
    `AND,((DOMAIN-SUFFIX,github.com),(NETWORK,TCP)),${proxyName}`,
    ...config.rules
  ];

  return config;
}
