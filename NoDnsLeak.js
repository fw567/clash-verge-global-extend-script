function main(config) {
  // 1. 爆发力优化：强制内核在建立连接时更激进
  config['tcp-concurrent'] = true;      // 开启 TCP 并发
  config['fast-open'] = true;          // 开启 TCP Fast Open
  config['read-buffer-size'] = 524288; // 回调到 512KB (针对 8K 大数据包优化)
  config['udp-timeout'] = 300;
  
  // 2. 节点与链路选择优化
  config['unified-delay'] = true;
  config['find-process-mode'] = 'always';

  // 3. DNS 加速：极致精简
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false,
    'prefer-h3': true,
    'default-nameserver': ['223.5.5.5'],
    'proxy-server-nameserver': ['223.5.5.5'],
    'nameserver': ['https://dns.google/dns-query#proxy'],
    'nameserver-policy': {
      'geosite:cn': ['https://dns.alidns.com/dns-query'],
      'geosite:gfw,geolocation-!cn': ['https://dns.google/dns-query#proxy']
    }
  };

  // 4. 规则置顶：确保视频流路径最短
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
  
  // 增加强制视频流走代理的规则，防止嗅探导致的延迟
  config.rules = [
    `DOMAIN-KEYWORD,googlevideo,${proxyName}`, 
    `RULE-SET,prevent_dns_leak,${proxyName}`,
    `AND,((DOMAIN-SUFFIX,github.com),(NETWORK,TCP)),${proxyName}`,
    ...config.rules
  ];

  // 5. 嗅探逻辑优化
  config.sniffer = {
    'enable': true,
    'sniff': {
      'TLS': { 'ports': [443, 8443], 'override-destination': true },
      'QUIC': { 'ports': [443, 8443], 'override-destination': true }
    },
    'force-domain': ['googlevideo.com']
  };

  return config;
}
