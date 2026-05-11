function main(config) {
  // 1. 暴力吞吐优化 (针对极高码率流媒体)
  config['read-buffer-size'] = 524288;   // 提升至 512KB，降低超高带宽下的 CPU 负载
  config['tcp-concurrent'] = true;       // 开启 TCP 并发
  config['tcp-keep-alive-idle'] = 600;   // 延长空闲存活，防止高负载下断流
  config['udp-timeout'] = 900;           // 针对 QUIC (h3) 的暴力超时等待

  // 2. 规则集配置
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

  // 3. 核心规则置顶
  const customRules = [
    `RULE-SET,prevent_dns_leak,${proxyName}`,
    `AND,((DOMAIN-SUFFIX,github.com),(NETWORK,TCP)),${proxyName}`,
    'DOMAIN-KEYWORD,adscore,REJECT-DROP'
  ];
  config.rules = [...customRules, ...config.rules];

  // 4. DNS 零泄露
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'ipv6': false,
    'prefer-h3': true,
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    'proxy-server-nameserver': ['223.5.5.5', '119.29.29.29'],
    'nameserver': ['https://dns.google/dns-query#proxy', 'https://1.1.1.1/dns-query#proxy'],
    'nameserver-policy': {
      'geosite:cn': ['https://dns.alidns.com/dns-query'],
      'geosite:gfw,geolocation-!cn': ['https://dns.google/dns-query#proxy']
    },
    'fallback-filter': { 'geoip': true, 'geoip-code': 'CN', 'ipmask': ['240.0.0.0/4'] },
    'fake-ip-filter': ['*.lan', 'localhost.ptlogin2.qq.com', '+.stun.*.*']
  };

  // 5. 增强型嗅探
  config.sniffer = {
    'enable': true,
    'sniff': {
      'TLS': { 'ports': [443, 8443] },
      'HTTP': { 'ports': [80, '8080-8880'], 'override-destination': true },
      'QUIC': { 'ports': [443, 8443] }
    },
    'force-domain': ['googlevideo.com'] // 重点嗅探视频流
  };

  return config;
}
