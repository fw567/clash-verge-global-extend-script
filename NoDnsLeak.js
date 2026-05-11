function main(config) {
  // 1. 全局基础优化 & 开发者保护
  config['unified-delay'] = true; 
  //确保你运行 Python/PyQt 项目或本地服务时不走代理，避免连接失败
  config['skip-proxy'] = [
    'localhost',
    '127.0.0.1',
    '::1',
    '*.local',
    '192.168.*',
    '10.*'
  ];

  // 2. 规则集配置 (Rule Provider)
  if (!config['rule-providers']) {
    config['rule-providers'] = {};
  }
  //引入外部防 DNS 泄露域名清单
  config['rule-providers']['prevent_dns_leak'] = {
    type: "http",
    interval: 86400,
    behavior: "domain",
    format: "text",
    url: "https://raw.githubusercontent.com/xishang0128/rules/main/clash%20or%20stash/prevent_dns_leak/prevent_dns_leak_domain.list"
  };

  // 3. 动态提取代理组名称
  const matchRule = config.rules.find(rule => rule.startsWith("MATCH"));
  const proxyName = matchRule ? matchRule.split(",").pop() : "DIRECT";

  // 4. 规则置顶逻辑 (整合：视频加速、防泄露、GitHub 优化、广告拦截)
  if (proxyName) {
    const customRules = [
      `DOMAIN-KEYWORD,googlevideo,${proxyName}`,    // [功能：视频秒开] 视频流强制置顶
      `RULE-SET,prevent_dns_leak,${proxyName}`,    // [功能：DNS 防泄露规则]
      `AND,((DOMAIN-SUFFIX,github.com),(NETWORK,TCP)),${proxyName}`, // [功能：GitHub 稳连] 强制走 TCP 解决 Reset
      'DOMAIN-KEYWORD,adscore,REJECT-DROP',        // [功能：广告黑洞] 屏蔽且不重连
      'DOMAIN-KEYWORD,analytics,REJECT-DROP',      // [功能：隐私保护] 屏蔽追踪器
      'DOMAIN-KEYWORD,analysis,REJECT-DROP'
    ];
    // 采用解构赋值将自定义规则插入到原规则最前面
    config.rules = [...customRules, ...config.rules];
  }

  // 5. DNS 配置：保留你测试最快的 nameserver-policy 架构
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false,
    'prefer-h3': true,
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    'nameserver': [
      'https://dns.google/dns-query#proxy',
      'https://1.1.1.1/dns-query#proxy'
    ],
    // [功能：精准分流] 主动识别域名归属，彻底杜绝泄露
    'nameserver-policy': {
      'geosite:cn': [
        'https://dns.alidns.com/dns-query',
        'https://doh.pub/dns-query'
      ],
      'geosite:gfw,geolocation-!cn': [
        'https://dns.google/dns-query#proxy',
        'https://1.1.1.1/dns-query#proxy'
      ]
    },
    'fallback-filter': {
      'geoip': true,
      'geoip-code': 'CN',
      'ipmask': ['240.0.0.0/4']
    },
    'fake-ip-filter': ['*.lan', 'localhost.ptlogin2.qq.com', '+.stun.*.*', '+.msftconnecttest.com']
  };

  // 6. 流量嗅探 (Sniffer)
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
