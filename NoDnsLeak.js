function main(config) {
  // 1. 极限吞吐量优化 (针对 8K/16K 视频流)
  config['read-buffer-size'] = 262144;   // 暴力提升缓冲区到 256KB，减少高带宽下的 CPU 中断
  config['tcp-concurrent'] = true;       // TCP 并发
  config['unified-delay'] = true;        // 统一延迟
  config['udp-timeout'] = 600;           // 延长 UDP 超时，防止大文件分段加载时断流
  
  // 2. 核心：开启逻辑进程模式，提升多核 CPU 处理效率
  config['find-process-mode'] = 'always'; 

  // 3. 规则集配置
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

  // 4. 逻辑规则与置顶
  const customRules = [
    `RULE-SET,prevent_dns_leak,${proxyName}`,
    `AND,((DOMAIN-SUFFIX,github.com),(NETWORK,TCP)),${proxyName}`,
    'DOMAIN-KEYWORD,adscore,REJECT-DROP',
    'DOMAIN-KEYWORD,analytics,REJECT-DROP'
  ];
  config.rules = [...customRules, ...config.rules];

  // 5. 零泄露 DNS 架构
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false,
    'prefer-h3': true,
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    'proxy-server-nameserver': ['223.5.5.5', '119.29.29.29'],
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

  // 6. 嗅探配置
  config.sniffer = {
    'enable': true,
    'sniff': {
      'TLS': { 'ports': [443, 8443] },
      'HTTP': { 'ports': [80, '8080-8880'], 'override-destination': true },
      'QUIC': { 'ports': [443, 8443] }
    },
    'force-domain': ['google.com', 'youtube.com', 'googlevideo.com']
  };

  return config;
}
