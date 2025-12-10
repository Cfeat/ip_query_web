from flask import Flask, render_template, request, jsonify
import socket
import requests
import ipaddress
from typing import Optional, Dict, Any, List, Tuple
import json
import logging
from functools import lru_cache
from dataclasses import dataclass
import os
import re
from datetime import datetime
import time

# 设置日志
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')

# 已知的中转/代理节点CIDR范围
TRANSPARENT_PROXY_CIDRS = {
    'ipv4': [
        '74.125.0.0/16',      # Google
        '142.250.0.0/15',     # Google
        '172.217.0.0/16',     # Google
        '8.8.4.0/24',         # Google DNS
        '8.8.8.0/24',         # Google DNS
        '1.1.1.0/24',         # Cloudflare DNS
        '1.0.0.0/24',         # Cloudflare
        '104.16.0.0/12',      # Cloudflare
        '208.67.222.0/24',    # OpenDNS
        '208.67.220.0/24',    # OpenDNS
        '52.0.0.0/8',         # Amazon AWS
        '34.0.0.0/8',         # Google Cloud
        '35.0.0.0/8',         # Google Cloud
    ],
    'ipv6': [
        '2001:4860:4860::/48',    # Google DNS
        '2001:4860:4860::8888/128',
        '2001:4860:4860::8844/128',
        '2606:4700::/32',         # Cloudflare
        '2606:4700:4700::/48',    # Cloudflare DNS
        '2a0d:2a00:1::/48',       # Cloudflare
        '2a0d:2a00:2::/48',       # Cloudflare
        '2600:1900:4000::/36',    # Amazon AWS
        '2600:1f00::/36',         # Google Cloud
        '2400:cb00::/32',         # Cloudflare
    ]
}

# 已知VPN/代理服务商ASN
PROXY_ASNS = {
    '13335': 'Cloudflare',
    '15169': 'Google',
    '16509': 'Amazon',
    '8075': 'Microsoft',
    '36692': 'OpenDNS',
    '16276': 'OVH',
    '14061': 'DigitalOcean',
    '24940': 'Hetzner',
    '60068': 'M247',
    '20473': 'Choopa',
    '40065': 'G-Core Labs',
    '51167': 'Contabo',
    '21412': 'NFOrce',
    '60781': 'Leaseweb',
    '3549': 'Level3',
    '3356': 'Level3',
    '6939': 'Hurricane Electric',
    '3257': 'GTT',
    '1299': 'Telia',
    '2914': 'NTT',
    '6461': 'Zayo',
    '6762': 'Seabone',
    '209': 'CenturyLink',
    '7922': 'Comcast',
    '701': 'Verizon',
    '7018': 'AT&T',
}

IP_EXAMPLES_DATABASE = {
    "public_services": [
        {
            "ip": "8.8.8.8",
            "name": "Google Public DNS (IPv4)",
            "type": "dns",
            "provider": "Google",
            "description": "谷歌公共DNS服务器，全球最知名的DNS服务"
        },
        {
            "ip": "8.8.4.4",
            "name": "Google Public DNS Backup (IPv4)",
            "type": "dns",
            "provider": "Google",
            "description": "谷歌公共DNS备用服务器"
        },
        {
            "ip": "1.1.1.1",
            "name": "Cloudflare DNS (IPv4)",
            "type": "dns",
            "provider": "Cloudflare",
            "description": "Cloudflare公共DNS，注重隐私保护"
        },
        {
            "ip": "1.0.0.1",
            "name": "Cloudflare DNS Backup (IPv4)",
            "type": "dns",
            "provider": "Cloudflare",
            "description": "Cloudflare公共DNS备用服务器"
        },
        {
            "ip": "208.67.222.222",
            "name": "OpenDNS (IPv4)",
            "type": "dns",
            "provider": "OpenDNS",
            "description": "思科旗下的公共DNS服务"
        },
        {
            "ip": "208.67.220.220",
            "name": "OpenDNS Backup (IPv4)",
            "type": "dns",
            "provider": "OpenDNS",
            "description": "OpenDNS备用服务器"
        },
        {
            "ip": "9.9.9.9",
            "name": "Quad9 DNS (IPv4)",
            "type": "dns",
            "provider": "Quad9",
            "description": "专注于安全的公共DNS服务"
        },
        {
            "ip": "149.112.112.112",
            "name": "Quad9 DNS Backup (IPv4)",
            "type": "dns",
            "provider": "Quad9",
            "description": "Quad9备用DNS服务器"
        },
        {
            "ip": "64.6.64.6",
            "name": "Verisign Public DNS (IPv4)",
            "type": "dns",
            "provider": "Verisign",
            "description": "Verisign公共DNS服务"
        },
        {
            "ip": "64.6.65.6",
            "name": "Verisign Public DNS Backup (IPv4)",
            "type": "dns",
            "provider": "Verisign",
            "description": "Verisign备用DNS服务器"
        }
    ],
    "ipv6_services": [
        {
            "ip": "2001:4860:4860::8888",
            "name": "Google Public DNS (IPv6)",
            "type": "dns",
            "provider": "Google",
            "description": "谷歌公共DNS IPv6版本"
        },
        {
            "ip": "2001:4860:4860::8844",
            "name": "Google Public DNS Backup (IPv6)",
            "type": "dns",
            "provider": "Google",
            "description": "谷歌公共DNS IPv6备用"
        },
        {
            "ip": "2606:4700:4700::1111",
            "name": "Cloudflare DNS (IPv6)",
            "type": "dns",
            "provider": "Cloudflare",
            "description": "Cloudflare公共DNS IPv6版本"
        },
        {
            "ip": "2606:4700:4700::1001",
            "name": "Cloudflare DNS Backup (IPv6)",
            "type": "dns",
            "provider": "Cloudflare",
            "description": "Cloudflare公共DNS IPv6备用"
        },
        {
            "ip": "2620:fe::fe",
            "name": "Quad9 DNS (IPv6)",
            "type": "dns",
            "provider": "Quad9",
            "description": "Quad9 DNS IPv6版本"
        },
        {
            "ip": "2620:fe::9",
            "name": "Quad9 DNS Backup (IPv6)",
            "type": "dns",
            "provider": "Quad9",
            "description": "Quad9 DNS IPv6备用"
        },
        {
            "ip": "2620:74:1b::1:1",
            "name": "OpenDNS (IPv6)",
            "type": "dns",
            "provider": "OpenDNS",
            "description": "OpenDNS IPv6版本"
        },
        {
            "ip": "2620:74:1c::2:2",
            "name": "OpenDNS Backup (IPv6)",
            "type": "dns",
            "provider": "OpenDNS",
            "description": "OpenDNS IPv6备用"
        }
    ],
    "cdn_networks": [
        {
            "ip": "104.16.0.0",
            "name": "Cloudflare CDN",
            "type": "cdn",
            "provider": "Cloudflare",
            "description": "Cloudflare CDN网络地址"
        },
        {
            "ip": "172.217.0.0",
            "name": "Google CDN",
            "type": "cdn",
            "provider": "Google",
            "description": "谷歌CDN网络地址"
        },
        {
            "ip": "13.107.246.0",
            "name": "Microsoft Azure CDN",
            "type": "cdn",
            "provider": "Microsoft",
            "description": "微软Azure CDN网络"
        },
        {
            "ip": "99.84.0.0",
            "name": "Amazon CloudFront",
            "type": "cdn",
            "provider": "Amazon",
            "description": "亚马逊CloudFront CDN"
        }
    ],
    "vpn_services": [
        {
            "ip": "185.159.157.1",
            "name": "NordVPN Server",
            "type": "vpn",
            "provider": "NordVPN",
            "description": "NordVPN服务器节点"
        },
        {
            "ip": "162.245.241.221",
            "name": "ExpressVPN Server",
            "type": "vpn",
            "provider": "ExpressVPN",
            "description": "ExpressVPN服务器节点"
        },
        {
            "ip": "45.90.28.0",
            "name": "ProtonVPN Server",
            "type": "vpn",
            "provider": "ProtonVPN",
            "description": "ProtonVPN服务器网络"
        }
    ],
    "time_servers": [
        {
            "ip": "time.google.com",
            "name": "Google Time Server",
            "type": "ntp",
            "provider": "Google",
            "description": "谷歌时间服务器（可通过DNS解析）"
        },
        {
            "ip": "time.windows.com",
            "name": "Microsoft Time Server",
            "type": "ntp",
            "provider": "Microsoft",
            "description": "微软时间服务器"
        },
        {
            "ip": "time.apple.com",
            "name": "Apple Time Server",
            "type": "ntp",
            "provider": "Apple",
            "description": "苹果时间服务器"
        },
        {
            "ip": "pool.ntp.org",
            "name": "NTP Pool Project",
            "type": "ntp",
            "provider": "NTP Pool",
            "description": "NTP时间服务器池"
        }
    ],
    "educational_ips": [
        {
            "ip": "93.184.216.34",
            "name": "Example.com",
            "type": "website",
            "provider": "IANA",
            "description": "IANA保留的示例网站地址"
        },
        {
            "ip": "192.0.2.1",
            "name": "TEST-NET-1",
            "type": "test",
            "provider": "IANA",
            "description": "IANA保留的测试网络地址"
        },
        {
            "ip": "198.51.100.1",
            "name": "TEST-NET-2",
            "type": "test",
            "provider": "IANA",
            "description": "IANA保留的测试网络地址"
        },
        {
            "ip": "203.0.113.1",
            "name": "TEST-NET-3",
            "type": "test",
            "provider": "IANA",
            "description": "IANA保留的测试网络地址"
        },
        {
            "ip": "192.168.1.1",
            "name": "Private Network Example",
            "type": "private",
            "provider": "RFC 1918",
            "description": "私有网络地址示例（C类）"
        },
        {
            "ip": "10.0.0.1",
            "name": "Private Network Example",
            "type": "private",
            "provider": "RFC 1918",
            "description": "私有网络地址示例（A类）"
        },
        {
            "ip": "172.16.0.1",
            "name": "Private Network Example",
            "type": "private",
            "provider": "RFC 1918",
            "description": "私有网络地址示例（B类）"
        }
    ],
    "well_known_websites": [
        {
            "ip": "142.250.185.78",
            "name": "Google.com",
            "type": "website",
            "provider": "Google",
            "description": "谷歌搜索服务器"
        },
        {
            "ip": "104.244.42.1",
            "name": "Twitter.com",
            "type": "website",
            "provider": "Twitter",
            "description": "Twitter/X服务器"
        },
        {
            "ip": "31.13.72.1",
            "name": "Facebook.com",
            "type": "website",
            "provider": "Meta",
            "description": "Facebook服务器"
        },
        {
            "ip": "13.33.243.1",
            "name": "Amazon.com",
            "type": "website",
            "provider": "Amazon",
            "description": "亚马逊服务器"
        },
        {
            "ip": "20.231.239.246",
            "name": "Microsoft.com",
            "type": "website",
            "provider": "Microsoft",
            "description": "微软服务器"
        },
        {
            "ip": "140.82.121.3",
            "name": "GitHub.com",
            "type": "website",
            "provider": "GitHub",
            "description": "GitHub服务器"
        },
        {
            "ip": "151.101.1.1",
            "name": "Reddit.com",
            "type": "website",
            "provider": "Reddit",
            "description": "Reddit服务器"
        }
    ],
    "tor_exit_nodes": [
        {
            "ip": "51.222.86.1",
            "name": "Tor Exit Node",
            "type": "tor",
            "provider": "Tor Project",
            "description": "Tor网络出口节点（示例）"
        },
        {
            "ip": "185.220.101.1",
            "name": "Tor Exit Node",
            "type": "tor",
            "provider": "Tor Project",
            "description": "Tor网络出口节点（示例）"
        }
    ]
}

@dataclass
class GeoAPI:
    name: str
    url: str
    fields_mapping: Dict[str, List[str]]
    supports_ipv6: bool = True
    
    def get_url(self, ip: Optional[str] = None) -> str:
        """获取API URL"""
        if ip and '{ip}' in self.url:
            return self.url.format(ip=ip)
        return self.url.replace('{ip}/', '').replace('{ip}', '')
    
    def extract_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """从API响应中提取标准化的数据"""
        result = {}
        
        # 提取IP地址
        for field in self.fields_mapping.get('ip', ['ip', 'query']):
            if field in data:
                ip_val = data.get(field)
                if ip_val and str(ip_val).lower() not in ['n/a', 'none', 'null']:
                    result['ip'] = str(ip_val).split(',')[0].strip()
                    break
        
        if not result.get('ip'):
            return {}
        
        # 提取其他字段
        for std_field, api_fields in self.fields_mapping.items():
            if std_field == 'ip':
                continue
            for api_field in api_fields:
                if api_field in data:
                    val = data.get(api_field)
                    if val and str(val).lower() not in ['n/a', 'none', 'null']:
                        result[std_field] = val
                        break
            if std_field not in result:
                result[std_field] = '未知'
        
        return result

# API配置列表
GEO_APIS = [
    GeoAPI(
        name='ipinfo.io',
        url='https://ipinfo.io/{ip}/json',
        fields_mapping={
            'ip': ['ip'],
            'country': ['country'],
            'region': ['region'],
            'city': ['city'],
            'latitude': ['loc'],
            'longitude': ['loc'],
            'timezone': ['timezone'],
            'isp': ['org'],
            'asn': ['org'],
            'asn_name': ['org']
        },
        supports_ipv6=True
    ),
    GeoAPI(
        name='ip-api.com',
        url='http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query',
        fields_mapping={
            'ip': ['query'],
            'country': ['country', 'countryCode'],
            'region': ['regionName', 'region'],
            'city': ['city'],
            'latitude': ['lat'],
            'longitude': ['lon'],
            'timezone': ['timezone'],
            'isp': ['isp', 'org'],
            'asn': ['as'],
            'asn_name': ['isp', 'org']
        },
        supports_ipv6=True
    ),
    GeoAPI(
        name='ipapi.co',
        url='https://ipapi.co/{ip}/json/',
        fields_mapping={
            'ip': ['ip'],
            'country': ['country_name', 'country'],
            'region': ['region', 'region_code'],
            'city': ['city'],
            'latitude': ['latitude'],
            'longitude': ['longitude'],
            'timezone': ['timezone'],
            'isp': ['org'],
            'asn': ['asn'],
            'asn_name': ['asn']
        },
        supports_ipv6=True
    )
]

class IPAnalyzer:
    """IP地址分析器"""
    
    @staticmethod
    def is_ipv6(ip_str: str) -> bool:
        """检查是否为IPv6地址"""
        try:
            ipaddress.IPv6Address(ip_str)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    @staticmethod
    def is_ipv4(ip_str: str) -> bool:
        """检查是否为IPv4地址"""
        try:
            ipaddress.IPv4Address(ip_str)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    @staticmethod
    def validate_ip(ip_str: str) -> Tuple[bool, str]:
        """验证IP地址格式"""
        if not ip_str:
            return False, "IP地址不能为空"
        
        ip_str = ip_str.strip()
        
        # 检查是否为有效的IP地址
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            
            # 检查是否为保留地址
            if ip_obj.is_private:
                return True, "private"
            if ip_obj.is_loopback:
                return True, "loopback"
            if ip_obj.is_link_local:
                return True, "link_local"
            if ip_obj.is_multicast:
                return True, "multicast"
            if ip_obj.is_reserved:
                return True, "reserved"
            if ip_obj.is_unspecified:
                return True, "unspecified"
            
            return True, "public"
            
        except ValueError as e:
            return False, f"无效的IP地址格式: {str(e)}"
    
    @staticmethod
    def get_local_ip() -> str:
        """获取本地IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 53))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            logger.error(f"获取本地IP失败: {e}")
            return "127.0.0.1"
    
    @staticmethod
    def get_local_ipv6() -> Optional[str]:
        """获取本地IPv6地址"""
        try:
            # 尝试通过socket获取IPv6地址
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.connect(("2001:4860:4860::8888", 53))  # Google DNS IPv6
            local_ipv6 = s.getsockname()[0]
            s.close()
            return local_ipv6
        except Exception as e:
            logger.debug(f"获取本地IPv6失败: {e}")
            return None
    
    @staticmethod
    def get_all_local_ips() -> Dict[str, List[str]]:
        """获取所有本地IP地址"""
        result = {
            'ipv4': [],
            'ipv6': []
        }
        
        try:
            hostname = socket.gethostname()
            all_ips = socket.getaddrinfo(hostname, None)
            
            for addr_info in all_ips:
                ip = addr_info[4][0]
                if IPAnalyzer.is_ipv4(ip) and ip not in result['ipv4']:
                    result['ipv4'].append(ip)
                elif IPAnalyzer.is_ipv6(ip) and ip not in result['ipv6']:
                    result['ipv6'].append(ip)
        except Exception as e:
            logger.error(f"获取所有本地IP失败: {e}")
        
        return result
    
    @staticmethod
    def check_transparent_proxy(ip_str: str, asn_info: Optional[str] = None) -> Dict[str, Any]:
        """检查是否为透明代理/中转节点"""
        result = {
            'is_proxy': False,
            'proxy_type': None,
            'confidence': 0,
            'indicators': [],
            'service_provider': None,
            'asn_info': asn_info
        }
        
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            is_ipv6 = isinstance(ip_obj, ipaddress.IPv6Address)
            cidr_list = TRANSPARENT_PROXY_CIDRS['ipv6' if is_ipv6 else 'ipv4']
            
            # 检查是否在已知代理CIDR范围内
            for cidr_str in cidr_list:
                try:
                    network = ipaddress.ip_network(cidr_str, strict=False)
                    if ip_obj in network:
                        result['is_proxy'] = True
                        result['confidence'] = 85
                        result['indicators'].append(f"IP在已知代理网络 {cidr_str} 中")
                        
                        # 识别服务提供商
                        if 'google' in cidr_str.lower() or '74.125' in cidr_str or '142.250' in cidr_str:
                            result['service_provider'] = 'Google'
                        elif 'cloudflare' in cidr_str.lower() or '1.1.1' in cidr_str or '104.16' in cidr_str:
                            result['service_provider'] = 'Cloudflare'
                        elif 'amazon' in cidr_str.lower() or '52.' in cidr_str:
                            result['service_provider'] = 'Amazon AWS'
                        elif 'opendns' in cidr_str.lower() or '208.67.22' in cidr_str:
                            result['service_provider'] = 'OpenDNS'
                        break
                except ValueError:
                    continue
            
            # 检查ASN信息
            if asn_info:
                asn_match = re.search(r'AS(\d+)', asn_info)
                if asn_match:
                    asn_number = asn_match.group(1)
                    if asn_number in PROXY_ASNS:
                        result['is_proxy'] = True
                        result['confidence'] = max(result['confidence'], 75)
                        result['service_provider'] = PROXY_ASNS[asn_number]
                        result['indicators'].append(f"ASN {asn_number} 属于已知服务商: {PROXY_ASNS[asn_number]}")
                
                # 检查ASN描述中是否包含代理关键词
                proxy_keywords = ['cloud', 'hosting', 'data center', 'datacenter', 'server', 
                                 'vpn', 'proxy', 'tor', 'anonymizer', 'cdn', 'network', 'isp']
                for keyword in proxy_keywords:
                    if keyword.lower() in asn_info.lower():
                        result['is_proxy'] = True
                        result['confidence'] = min(result['confidence'] + 10, 90)
                        result['indicators'].append(f"ASN描述包含 '{keyword}'")
                        break
            
            # 检查是否为已知的DNS服务器
            dns_servers = [
                '8.8.8.8', '8.8.4.4',  # Google DNS
                '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
                '208.67.222.222', '208.67.220.220',  # OpenDNS
                '2001:4860:4860::8888', '2001:4860:4860::8844',  # Google DNS IPv6
                '2606:4700:4700::1111', '2606:4700:4700::1001',  # Cloudflare DNS IPv6
            ]
            if ip_str in dns_servers:
                result['is_proxy'] = True
                result['confidence'] = 95
                result['proxy_type'] = 'dns_server'
                result['indicators'].append("已知的公共DNS服务器")
            
            # 检查是否为Teredo/6to4中继
            if is_ipv6:
                if ip_str.startswith('2001:0:'):  # Teredo
                    result['is_proxy'] = True
                    result['confidence'] = 80
                    result['proxy_type'] = 'teredo_relay'
                    result['indicators'].append("Teredo IPv6中继地址")
                elif ip_str.startswith('2002:'):  # 6to4
                    result['is_proxy'] = True
                    result['confidence'] = 80
                    result['proxy_type'] = '6to4_relay'
                    result['indicators'].append("6to4 IPv6中继地址")
            
            # 设置代理类型
            if result['is_proxy']:
                if not result['proxy_type']:
                    if result['service_provider'] in ['Google', 'Cloudflare', 'OpenDNS']:
                        result['proxy_type'] = 'public_service'
                    elif asn_info and 'dns' in asn_info.lower():
                        result['proxy_type'] = 'dns_server'
                    else:
                        result['proxy_type'] = 'transparent_proxy'
            
            return result
            
        except Exception as e:
            logger.error(f"检查代理节点失败: {e}")
            return result
    
    @staticmethod
    def get_ip_version(ip_str: str) -> str:
        """获取IP版本"""
        if IPAnalyzer.is_ipv6(ip_str):
            return "IPv6"
        elif IPAnalyzer.is_ipv4(ip_str):
            return "IPv4"
        return "Unknown"
    
    @staticmethod
    def compress_ipv6(ip_str: str) -> str:
        """压缩IPv6地址"""
        try:
            ip_obj = ipaddress.IPv6Address(ip_str)
            return ip_obj.compressed
        except:
            return ip_str
    
    @staticmethod
    def get_reverse_dns(ip_str: str) -> Optional[str]:
        """获取反向DNS记录"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_str)
            return hostname
        except (socket.herror, socket.gaierror):
            return None
        except Exception as e:
            logger.debug(f"反向DNS查询失败: {e}")
            return None
    
    @staticmethod
    def get_network_info(ip_str: str) -> Dict[str, Any]:
        """获取网络信息"""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            is_ipv6 = isinstance(ip_obj, ipaddress.IPv6Address)
            
            info = {
                'version': 6 if is_ipv6 else 4,
                'is_multicast': ip_obj.is_multicast,
                'is_private': ip_obj.is_private,
                'is_global': ip_obj.is_global,
                'is_reserved': ip_obj.is_reserved,
                'is_loopback': ip_obj.is_loopback,
                'is_link_local': ip_obj.is_link_local,
            }
            
            if is_ipv6:
                info['is_teredo'] = str(ip_obj).startswith('2001:0:')
                info['is_6to4'] = str(ip_obj).startswith('2002:')
            
            return info
        except Exception as e:
            logger.debug(f"获取网络信息失败: {e}")
            return {}

class GeoLocator:
    """IP地理位置查询器"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json"
        })
        self.ip_analyzer = IPAnalyzer()
    
    def get_public_ip(self, force_ipv6: bool = False) -> Optional[str]:
        """获取本机公网IP，支持IPv6"""
        ip_services = [
            ("https://api64.ipify.org?format=json", True),  # 支持IPv6
            ("https://api.ipify.org?format=json", False),   # IPv4
            ("https://ipv6.icanhazip.com", True),          # IPv6
            ("https://icanhazip.com", False),              # IPv4
        ]
        
        for service_url, supports_ipv6 in ip_services:
            if force_ipv6 and not supports_ipv6:
                continue
                
            try:
                response = self.session.get(service_url, timeout=3)
                if response.status_code == 200:
                    if 'json' in service_url:
                        return response.json().get("ip")
                    else:
                        return response.text.strip()
            except Exception as e:
                logger.debug(f"IP服务 {service_url} 失败: {e}")
                continue
        
        # 备用：从请求头获取
        try:
            if hasattr(request, 'headers') and 'X-Forwarded-For' in request.headers:
                ips = request.headers['X-Forwarded-For'].split(',')
                for ip in ips:
                    ip = ip.strip()
                    if self.ip_analyzer.validate_ip(ip)[0]:
                        return ip
            if hasattr(request, 'remote_addr') and request.remote_addr and request.remote_addr != '127.0.0.1':
                return request.remote_addr
        except Exception as e:
            logger.debug(f"从请求头获取IP失败: {e}")
        
        return None
    
    def query_ip_location(self, ip_address: str) -> Dict[str, Any]:
        """查询IP地址的地理位置信息"""
        # 验证IP地址
        is_valid, ip_type = self.ip_analyzer.validate_ip(ip_address)
        if not is_valid:
            return {"error": f"无效的IP地址: {ip_type}", "ip": ip_address}
        
        # 检查IP类型
        ip_version = self.ip_analyzer.get_ip_version(ip_address)
        result = {
            "ip": ip_address,
            "ip_version": ip_version,
            "ip_type": ip_type,
            "compressed_ip": ip_address,
            "is_special": ip_type != "public"
        }
        
        # 压缩IPv6地址
        if ip_version == "IPv6":
            result["compressed_ip"] = self.ip_analyzer.compress_ipv6(ip_address)
        
        # 特殊地址处理
        if ip_type != "public":
            result.update({
                "country": "特殊地址",
                "region": ip_type.replace("_", " ").title(),
                "city": "N/A",
                "latitude": 0,
                "longitude": 0,
                "timezone": "UTC",
                "isp": "特殊网络",
                "asn": "N/A",
                "asn_name": "N/A",
                "network_info": self.ip_analyzer.get_network_info(ip_address)
            })
            return result
        
        # 尝试所有API
        for api in GEO_APIS:
            # 如果是IPv6但API不支持，跳过
            if ip_version == "IPv6" and not api.supports_ipv6:
                continue
                
            try:
                url = api.get_url(ip_address)
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # 检查API特定错误
                    if api.name == 'ip-api.com' and data.get('status') != 'success':
                        continue
                    
                    extracted = api.extract_data(data)
                    if extracted.get('ip'):
                        result.update(extracted)
                        result['api_source'] = api.name
                        
                        # 处理坐标
                        if 'latitude' in result and isinstance(result['latitude'], str) and ',' in result['latitude']:
                            coords = result['latitude'].split(',')
                            result['latitude'] = coords[0].strip()
                            result['longitude'] = coords[1].strip() if len(coords) > 1 else 0
                        
                        # 确保坐标是数字
                        try:
                            if result.get('latitude') and result.get('latitude') != '未知':
                                result['latitude'] = float(result['latitude'])
                        except (ValueError, TypeError):
                            result['latitude'] = 0
                        
                        try:
                            if result.get('longitude') and result.get('longitude') != '未知':
                                result['longitude'] = float(result['longitude'])
                        except (ValueError, TypeError):
                            result['longitude'] = 0
                        
                        # 添加地图标记
                        if result.get('latitude') and result.get('longitude') and result['latitude'] != 0 and result['longitude'] != 0:
                            result['has_coordinates'] = True
                        else:
                            result['has_coordinates'] = False
                        
                        # 添加网络信息
                        result['network_info'] = self.ip_analyzer.get_network_info(ip_address)
                        result['reverse_dns'] = self.ip_analyzer.get_reverse_dns(ip_address)
                        
                        # 检查中转节点
                        proxy_info = self.ip_analyzer.check_transparent_proxy(
                            ip_address, 
                            result.get('asn', '') + " " + result.get('asn_name', '')
                        )
                        result['proxy_info'] = proxy_info
                        
                        return result
                        
            except Exception as e:
                logger.debug(f"API {api.name} 查询失败: {e}")
                continue
        
        return {"error": "无法获取地理位置信息", "ip": ip_address}
    
    def test_ping(self, ip_address: str) -> Optional[bool]:
        """测试IP是否可ping（通过HTTP请求模拟）"""
        try:
            # 尝试通过HTTP请求测试连通性
            test_url = f"http://{ip_address}" if self.ip_analyzer.is_ipv4(ip_address) else f"http://[{ip_address}]"
            response = self.session.get(test_url, timeout=2, allow_redirects=False)
            return response.status_code < 500
        except Exception:
            return False
        
    def get_example_ips(self, category: str = None, limit: int = None) -> List[Dict[str, Any]]:
        """获取示例IP地址"""
        examples = []
        
        if category and category in IP_EXAMPLES_DATABASE:
            examples = IP_EXAMPLES_DATABASE[category]
        else:
            # 返回所有示例
            for cat, ips in IP_EXAMPLES_DATABASE.items():
                examples.extend(ips)
        
        if limit and len(examples) > limit:
            return examples[:limit]
        
        return examples

    def get_random_example_ip(self) -> Dict[str, Any]:
        """随机获取一个示例IP"""
        import random
        all_examples = []
        for category in IP_EXAMPLES_DATABASE.values():
            all_examples.extend(category)
        
        if all_examples:
            return random.choice(all_examples)
        return None

    def resolve_domain_to_ip(self, domain: str) -> Optional[str]:
        """解析域名到IP地址"""
        try:
            import socket
            # 首先尝试获取IPv4地址
            ipv4_info = socket.getaddrinfo(domain, None, socket.AF_INET)
            if ipv4_info:
                return ipv4_info[0][4][0]
            
            # 如果没有IPv4，尝试IPv6
            ipv6_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
            if ipv6_info:
                return ipv6_info[0][4][0]
                
        except (socket.gaierror, socket.herror) as e:
            logger.error(f"域名解析失败 {domain}: {e}")
        except Exception as e:
            logger.error(f"域名解析错误 {domain}: {e}")
        
        return None

# 创建地理定位器实例
geo_locator = GeoLocator()

@app.route('/')
def index():
    """首页 - 显示IP查询和地图"""
    try:
        # 获取IPv4和IPv6地址
        public_ipv4 = geo_locator.get_public_ip(force_ipv6=False)
        public_ipv6 = geo_locator.get_public_ip(force_ipv6=True)
        
        # 获取本地IP
        local_ips = geo_locator.ip_analyzer.get_all_local_ips()
        local_ip = local_ips.get('ipv4', ['127.0.0.1'])[0] if local_ips.get('ipv4') else "127.0.0.1"
        
        # 默认查询IPv4
        geo_info = {}
        if public_ipv4 and public_ipv4 != "127.0.0.1":
            geo_info = geo_locator.query_ip_location(public_ipv4)
        
        # 确保geo_info包含所有必要字段
        if geo_info and not geo_info.get('error'):
            if 'latitude' not in geo_info:
                geo_info['latitude'] = 0
            if 'longitude' not in geo_info:
                geo_info['longitude'] = 0
            if 'has_coordinates' not in geo_info:
                geo_info['has_coordinates'] = bool(
                    geo_info.get('latitude') and 
                    geo_info.get('longitude') and 
                    geo_info['latitude'] != 0 and 
                    geo_info['longitude'] != 0
                )
        
        return render_template(
            'index.html',
            public_ipv4=public_ipv4 or "未知",
            public_ipv6=public_ipv6 or "未检测到IPv6",
            local_ip=local_ip,
            local_ips=local_ips,
            geo_info=geo_info
        )
        
    except Exception as e:
        logger.error(f"首页加载错误: {e}")
        return render_template('index.html', 
                             error=str(e),
                             public_ipv4="未知",
                             public_ipv6="未知",
                             local_ip="127.0.0.1",
                             local_ips={'ipv4': [], 'ipv6': []})

@app.route('/api/geo/<path:ip_address>')
def api_geo_location(ip_address: str):
    """API接口 - 查询指定IP的地理位置"""
    try:
        result = geo_locator.query_ip_location(ip_address)
        
        if "error" in result:
            return jsonify(result), 404
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"API查询错误: {e}")
        return jsonify({"error": "服务器内部错误"}), 500

@app.route('/api/detect-proxy/<ip_address>')
def api_detect_proxy(ip_address: str):
    """专门检测IP是否为中转节点"""
    try:
        # 先获取地理信息
        geo_result = geo_locator.query_ip_location(ip_address)
        
        if "error" in geo_result:
            return jsonify(geo_result), 404
        
        # 详细检测代理信息
        proxy_info = geo_locator.ip_analyzer.check_transparent_proxy(
            ip_address, 
            geo_result.get('asn', '') + " " + geo_result.get('asn_name', '')
        )
        
        # 添加网络测试
        proxy_info['network_tests'] = {
            'reverse_dns': geo_locator.ip_analyzer.get_reverse_dns(ip_address),
            'ping_available': geo_locator.test_ping(ip_address),
        }
        
        return jsonify({
            "ip": ip_address,
            "geo_info": geo_result,
            "proxy_analysis": proxy_info
        })
        
    except Exception as e:
        logger.error(f"代理检测错误: {e}")
        return jsonify({"error": "代理检测失败"}), 500

@app.route('/api/compare-ips', methods=['POST'])
def api_compare_ips():
    """批量比较多个IP地址"""
    try:
        data = request.get_json()
        if not data or 'ips' not in data:
            return jsonify({"error": "缺少ips参数"}), 400
        
        ips = data['ips']
        if not isinstance(ips, list) or len(ips) > 10:
            return jsonify({"error": "ips必须是数组且最多10个"}), 400
        
        results = []
        for ip in ips:
            geo_info = geo_locator.query_ip_location(ip)
            proxy_info = geo_locator.ip_analyzer.check_transparent_proxy(
                ip, 
                geo_info.get('asn', '') + " " + geo_info.get('asn_name', '')
            )
            
            results.append({
                "ip": ip,
                "geo_info": geo_info,
                "proxy_info": proxy_info
            })
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"批量比较错误: {e}")
        return jsonify({"error": "服务器内部错误"}), 500

@app.route('/api/network-info/<ip_address>')
def api_network_info(ip_address: str):
    """获取IP网络信息"""
    try:
        network_info = geo_locator.ip_analyzer.get_network_info(ip_address)
        reverse_dns = geo_locator.ip_analyzer.get_reverse_dns(ip_address)
        
        return jsonify({
            "ip": ip_address,
            "network_info": network_info,
            "reverse_dns": reverse_dns,
            "is_valid": geo_locator.ip_analyzer.validate_ip(ip_address)[0]
        })
        
    except Exception as e:
        logger.error(f"网络信息查询错误: {e}")
        return jsonify({"error": "查询失败"}), 500
    
@app.route('/api/examples')
def api_get_examples():
    """获取示例IP地址"""
    try:
        category = request.args.get('category', '')
        limit = request.args.get('limit', type=int)
        
        examples = geo_locator.get_example_ips(category if category else None, limit)
        
        # 解析域名类型的示例
        for example in examples:
            if example['ip'] and '.' in example['ip'] and not example['ip'][0].isdigit():
                # 可能是域名，尝试解析
                ip_address = geo_locator.resolve_domain_to_ip(example['ip'])
                if ip_address:
                    example['resolved_ip'] = ip_address
                    example['original'] = example['ip']
                    example['ip'] = ip_address
        
        return jsonify({
            "count": len(examples),
            "category": category or "all",
            "examples": examples
        })
    except Exception as e:
        logger.error(f"获取示例IP失败: {e}")
        return jsonify({"error": "获取示例IP失败"}), 500

@app.route('/api/examples/random')
def api_get_random_example():
    """随机获取一个示例IP"""
    try:
        example = geo_locator.get_random_example_ip()
        if example:
            # 解析域名
            if example['ip'] and '.' in example['ip'] and not example['ip'][0].isdigit():
                ip_address = geo_locator.resolve_domain_to_ip(example['ip'])
                if ip_address:
                    example['resolved_ip'] = ip_address
                    example['original'] = example['ip']
                    example['ip'] = ip_address
            
            return jsonify(example)
        return jsonify({"error": "没有可用的示例IP"}), 404
    except Exception as e:
        logger.error(f"获取随机示例失败: {e}")
        return jsonify({"error": "获取随机示例失败"}), 500

@app.route('/api/examples/categories')
def api_get_categories():
    """获取示例IP分类"""
    try:
        categories = []
        for category_name, items in IP_EXAMPLES_DATABASE.items():
            categories.append({
                "name": category_name,
                "display_name": category_name.replace('_', ' ').title(),
                "count": len(items),
                "description": get_category_description(category_name)
            })
        
        return jsonify({
            "count": len(categories),
            "categories": categories
        })
    except Exception as e:
        logger.error(f"获取分类失败: {e}")
        return jsonify({"error": "获取分类失败"}), 500

def get_category_description(category: str) -> str:
    """获取分类描述"""
    descriptions = {
        "public_services": "公共网络服务IP地址，如DNS服务器、NTP时间服务器等",
        "ipv6_services": "IPv6网络服务地址",
        "cdn_networks": "内容分发网络(CDN)IP地址",
        "vpn_services": "VPN服务提供商服务器IP",
        "time_servers": "网络时间协议(NTP)服务器",
        "educational_ips": "教育用途的测试和示例IP地址",
        "well_known_websites": "知名网站的服务器IP",
        "tor_exit_nodes": "Tor网络出口节点IP地址"
    }
    return descriptions.get(category, "IP地址示例")

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=debug_mode
    )