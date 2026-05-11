export default function main(config) {
  // 1. 初始化 DNS 配置
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false, // 禁用 IPv6 防止双栈泄露
    'prefer-h3': true, // 开启 HTTP/3 支持
    'default-nameserver': [
      '223.5.5.5',
      '119.29.29.29'
    ],
    'nameserver': [
      'https://dns.alidns.com/dns-query',
      'https://doh.pub/dns-query'
    ],
    'fallback': [
      'https://dns.google/dns-query',
      'https://1.1.1.1/dns-query'
    ],
    // 策略分流：国内域名只允许询问国内 DNS
    'nameserver-policy': {
      'geosite:cn': [
        'https://dns.alidns.com/dns-query',
        'https://doh.pub/dns-query'
      ]
    },
    // 防泄露核心：如果国内 DNS 返回了国外 IP，或者属于 GFW 域名，强制丢弃并启用 Fallback
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
