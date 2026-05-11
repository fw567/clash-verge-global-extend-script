function main(config) {
  // 1. 核心性能平衡：消除起跳延迟
  config['tcp-concurrent'] = true;       // TCP 并发连接
  config['fast-open'] = true;            // 开启 TCP Fast Open (减少握手往返)
  config['read-buffer-size'] = 65536;    // 调整为 64KB：1080p 响应最快，同时足以支撑 8K 持续播放
  config['unified-delay'] = true;        // 统一延迟计算
  config['find-process-mode'] = 'always';
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

  // 3. 策略组适配
  const matchRule = config.rules.find(rule => rule.startsWith("MATCH"));
  const proxyName = matchRule ? matchRule.split(",").pop() : "DIRECT";

  // 4. 规则逻辑
  const customRules = [
    `DOMAIN-KEYWORD,googlevideo,${proxyName}`,    // 视频流首包强制置顶
    `RULE-SET,prevent_dns_leak,${proxyName}`,    // DNS 防泄露
    `AND,((DOMAIN-SUFFIX,github.com),(NETWORK,TCP)),${proxyName}`, // GitHub 优化
    'DOMAIN-KEYWORD,adscore,REJECT-DROP',        // 广告黑洞
    'DOMAIN-KEYWORD,analytics,REJECT-DROP',      // 追踪器黑洞
    'DOMAIN-KEYWORD,analysis,REJECT-DROP'
  ];
  config.rules = [...customRules, ...config.rules];

  // 5. DNS 零泄露架构
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false,
    'prefer-h3': true,
    'default-nameserver': ['223.5.5.5'],
    'proxy-server-nameserver': ['223.5.5.5'],    // 节点域名秒解析
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
      'TLS': { 'ports': [443], 'override-destination': true },
      'QUIC': { 'ports': [443], 'override-destination': true }
    },
    'force-domain': ['googlevideo.com']
  };

  return config;
}
