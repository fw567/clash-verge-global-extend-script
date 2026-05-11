export default function main(config) {
  // 1. 深度重置 DNS 模块
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false, // 彻底禁用 IPv6 是防泄露的前提
    'prefer-h3': true,
    'default-nameserver': [
      '223.5.5.5',
      '119.29.29.29'
    ],
    // 基础 DNS 设置：默认全部走国外加密 DoH，确保未知域名不泄露给运营商
    'nameserver': [
      'https://dns.google/dns-query',
      'https://1.1.1.1/dns-query'
    ],
    // 策略分流：只有明确的中国域名，才允许通过国内 DNS 解析，保证访问速度
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

  // 2. 配置流量嗅探 (Sniffer)
  // 识别那些直接连 IP 地址的流氓流量，并还原为域名进行规则匹配
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
