function main(config) {
  // ============================================================
  // 1. 全局基础优化 & 开发者保护
  // ============================================================
  config['unified-delay'] = true;                 // 统一延迟计算，测速更准
  config['tcp-concurrent'] = true;                // TCP 并发握手，首屏加速
  config['find-process-mode'] = 'strict';         // 精准识别进程流量
  config['geodata-mode'] = true;                  // 启用 geosite 数据
  config['global-client-fingerprint'] = 'chrome'; // 统一 TLS 指纹，抗干扰

  config['skip-proxy'] = [
    'localhost',
    '127.0.0.1',
    '::1',
    '*.local',
    '192.168.*',
    '10.*'
  ];

  // ============================================================
  // 2. 规则集配置 (Rule Providers)
  // ============================================================
  if (!config['rule-providers']) {
    config['rule-providers'] = {};
  }

  // [功能：防 DNS 泄露列表]
  config['rule-providers']['prevent_dns_leak'] = {
    type: "http",
    interval: 86400,
    behavior: "domain",
    format: "text",
    url: "https://raw.githubusercontent.com/xishang0128/rules/main/clash%20or%20stash/prevent_dns_leak/prevent_dns_leak_domain.list"
  };

  // [功能：广告拦截增强] Loyalsoldier 广告规则集（主流广告商/追踪器）
  config['rule-providers']['reject_ads'] = {
    type: "http",
    interval: 86400,
    behavior: "domain",
    format: "yaml",
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt"
  };

  // ============================================================
  // 3. 动态提取代理组名称
  // ============================================================
  const matchRule = config.rules.find(rule => rule.startsWith("MATCH"));
  const proxyName = matchRule ? matchRule.split(",").pop() : "DIRECT";

  // ============================================================
  // 4. 规则置顶逻辑
  //    顺序：广告拦截 → YouTube 加速 → 防泄露 → GitHub → 追踪拦截
  // ============================================================
  if (proxyName) {
    const customRules = [
      // [功能：广告黑洞 - 规则集] 主流广告/追踪域名直接拦截
      'RULE-SET,reject_ads,REJECT',

      // [功能：YouTube 全家桶加速] 充分利用 Hysteria2 UDP/QUIC 性能
      `DOMAIN-KEYWORD,googlevideo,${proxyName}`,
      `DOMAIN-SUFFIX,youtube.com,${proxyName}`,
      `DOMAIN-SUFFIX,ytimg.com,${proxyName}`,
      `DOMAIN-SUFFIX,ggpht.com,${proxyName}`,
      `DOMAIN-SUFFIX,youtu.be,${proxyName}`,
      `DOMAIN-SUFFIX,youtube-nocookie.com,${proxyName}`,

      // [功能：DNS 防泄露规则]
      `RULE-SET,prevent_dns_leak,${proxyName}`,

      // [功能：GitHub 稳连] 强制 TCP 解决 Connection Reset
      `AND,((DOMAIN-SUFFIX,github.com),(NETWORK,TCP)),${proxyName}`,

      // [功能：隐私保护 - 关键词兜底] 捕漏网之鱼
      'DOMAIN-KEYWORD,adscore,REJECT-DROP',
      'DOMAIN-KEYWORD,analytics,REJECT-DROP',
      'DOMAIN-KEYWORD,analysis,REJECT-DROP'
    ];
    config.rules = [...customRules, ...config.rules];
  }

  // ============================================================
  // 5. DNS 配置：精准分流，防泄露
  // ============================================================
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false,
    'prefer-h3': true,                          // DoH 启用 HTTP/3，Hysteria2 链路友好
    'respect-rules': true,                      // DNS 查询遵循规则分流
    'cache-algorithm': 'arc',                   // 更优缓存淘汰算法
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    'nameserver': [
      'https://dns.google/dns-query#proxy',
      'https://1.1.1.1/dns-query#proxy'
    ],
    'nameserver-policy': {
      // [YouTube/Google DNS 定向] 拿到最优 CDN IP
      'geosite:youtube,google': [
        'https://dns.google/dns-query#proxy'
      ],
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
    'fake-ip-filter': [
      '*.lan',
      'localhost.ptlogin2.qq.com',
      '+.stun.*.*',
      '+.msftconnecttest.com'
    ]
  };

  // ============================================================
  // 6. 流量嗅探 (Sniffer)
  // ============================================================
  config.sniffer = {
    'enable': true,
    'force-dns-mapping': true,                  // 强制用嗅探结果覆盖 fake-ip
    'parse-pure-ip': true,                      // 解析纯 IP 流量
    'sniff': {
      'TLS': { 'ports': [443, 8443] },
      'HTTP': { 'ports': [80, '8080-8880'], 'override-destination': true },
      'QUIC': { 'ports': [443, 8443] }          
    }
  };

  return config;
}
