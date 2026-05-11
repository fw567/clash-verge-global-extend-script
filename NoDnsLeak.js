function main(config) {
  // ============================================================
  // 1. 全局基础优化
  // ============================================================
  config['unified-delay'] = true;
  config['tcp-concurrent'] = true;
  config['find-process-mode'] = 'strict';
  config['geodata-mode'] = true;
  config['global-client-fingerprint'] = 'chrome';
  
  // 保持连接池复用，省去反复握手
  config['keep-alive-interval'] = 30;
  config['disable-keep-alive'] = false;

  config['skip-proxy'] = [
    'localhost', '127.0.0.1', '::1',
    '*.local', '192.168.*', '10.*'
  ];

  // ============================================================
  // 2. 规则集
  // ============================================================
  if (!config['rule-providers']) config['rule-providers'] = {};
  
  config['rule-providers']['prevent_dns_leak'] = {
    type: "http", interval: 86400, behavior: "domain", format: "text",
    url: "https://raw.githubusercontent.com/xishang0128/rules/main/clash%20or%20stash/prevent_dns_leak/prevent_dns_leak_domain.list"
  };
  
  config['rule-providers']['reject_ads'] = {
    type: "http", interval: 86400, behavior: "domain", format: "yaml",
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt"
  };

  // ============================================================
  // 3. 代理组名
  // ============================================================
  const matchRule = config.rules.find(rule => rule.startsWith("MATCH"));
  const proxyName = matchRule ? matchRule.split(",").pop() : "DIRECT";

  // ============================================================
  // 4. 规则置顶
  // ============================================================
  if (proxyName) {
    const customRules = [
      'RULE-SET,reject_ads,REJECT',
      
      // YouTube 加速
      `DOMAIN-KEYWORD,googlevideo,${proxyName}`,
      `DOMAIN-SUFFIX,youtube.com,${proxyName}`,
      `DOMAIN-SUFFIX,ytimg.com,${proxyName}`,
      `DOMAIN-SUFFIX,ggpht.com,${proxyName}`,
      `DOMAIN-SUFFIX,youtu.be,${proxyName}`,
      `DOMAIN-SUFFIX,youtube-nocookie.com,${proxyName}`,
      // [新增] YouTube API 和认证域名（这些是转圈时最先请求的）
      `DOMAIN-SUFFIX,googleapis.com,${proxyName}`,
      `DOMAIN-SUFFIX,gstatic.com,${proxyName}`,
      `DOMAIN-SUFFIX,googleusercontent.com,${proxyName}`,
      
      `RULE-SET,prevent_dns_leak,${proxyName}`,
      `AND,((DOMAIN-SUFFIX,github.com),(NETWORK,TCP)),${proxyName}`,
      
      'DOMAIN-KEYWORD,adscore,REJECT-DROP',
      'DOMAIN-KEYWORD,analytics,REJECT-DROP',
      'DOMAIN-KEYWORD,analysis,REJECT-DROP'
    ];
    config.rules = [...customRules, ...config.rules];
  }

  // ============================================================
  // 5. DNS：大幅提升缓存和预解析能力
  // ============================================================
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false,
    'prefer-h3': true,
    'respect-rules': true,
    'cache-algorithm': 'arc',
    'cache-size': 4096,                         // [新增] 大幅扩大 DNS 缓存
    'use-hosts': true,                          // [新增] 启用 hosts 加速
    'use-system-hosts': true,                   // [新增] 复用系统 hosts
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    'nameserver': [
      'https://dns.google/dns-query#proxy',
      'https://1.1.1.1/dns-query#proxy'
    ],
    'nameserver-policy': {
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
  // 6. 嗅探
  // ============================================================
  config.sniffer = {
    'enable': true,
    'force-dns-mapping': true,
    'parse-pure-ip': true,
    'sniff': {
      'TLS': { 'ports': [443, 8443] },
      'HTTP': { 'ports': [80, '8080-8880'], 'override-destination': true },
      'QUIC': { 'ports': [443, 8443] }
    }
  };

  // ============================================================
  // 7. 进程和连接性能
  // ============================================================
  config['profile'] = {
    ...config['profile'],
    'store-selected': true,
    'store-fake-ip': true                       // 重启后 fake-ip 保持，避免重新解析
  };

  return config;
}
