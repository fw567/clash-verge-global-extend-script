export default function main(config) {
  // 1. DNS 核心配置
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false, // 告诉内核不解析 IPv6 地址
    'prefer-h3': true,
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    // 默认 DNS 全部走代理端的加密通道
    'nameserver': [
      'https://dns.google/dns-query',
      'https://1.1.1.1/dns-query'
    ],
    // 只有命中中国域名列表，才允许走国内 DoH
    'nameserver-policy': {
      'geosite:cn': [
        'https://dns.alidns.com/dns-query',
        'https://doh.pub/dns-query'
      ]
    },
    // 严格过滤器：防止任何国内 DNS 污染或抢答国外域名
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

  // 2. 流量嗅探 (Sniffer) - 确保 IP 请求也能被还原为域名
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
