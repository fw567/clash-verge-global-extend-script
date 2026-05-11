export default function main(config) {
  // 1. 终极防泄露 DNS 配置
  config.dns = {
    'enable': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'ipv6': false,
    'prefer-h3': true,
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    // 强制：所有的基础 DNS 查询必须走代理节点在远端进行
    'nameserver': [
      'https://dns.google/dns-query#proxy',
      'https://1.1.1.1/dns-query#proxy'
    ],
    // 强制：Fallback 同样走代理，彻底切断与国内运营商 DNS 的非必要联系
    'fallback': [
      'https://dns.cloudflare.com/dns-query#proxy',
      'https://9.9.9.9/dns-query#proxy'
    ],
    // 性能分流：只有命中 geosite:cn（国内域名）时，才允许本地直连解析
    'nameserver-policy': {
      'geosite:cn': [
        'https://dns.alidns.com/dns-query',
        'https://doh.pub/dns-query'
      ]
    },
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

  // 2. 嗅探配置：识别并还原加密流量中的域名
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
