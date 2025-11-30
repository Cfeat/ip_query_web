from flask import Flask, render_template, request  # 关键：添加request导入
import socket
import requests
from typing import Optional, Dict, Any

app = Flask(__name__)

# 替换为更稳定的免费API（优先选择无访问限制的）
IP_GEO_API_LIST = [
    "https://ipinfo.io/json",          # 最稳定的免费API，无访问限制
    "https://api.ip.sb/jsonip",        # 仅返回IP，配合ipinfo补全地理信息
    "https://ipapi.co/json/",
    "https://ifconfig.me/all.json"
]

def get_local_ip() -> Optional[str]:
    """获取服务器本地IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"本地IP获取失败：{e}")
        return None

def get_real_public_ip() -> Optional[str]:
    """优先通过API获取真实公网IP（解决局域网部署时无法获取用户IP的问题）"""
    try:
        # 先用简单API获取公网IP
        response = requests.get("https://api.ip.sb/jsonip", timeout=5)
        response.raise_for_status()
        return response.json()["ip"]
    except Exception:
        # 备用：通过Flask请求头获取
        try:
            if 'X-Forwarded-For' in request.headers:
                return request.headers['X-Forwarded-For'].split(',')[0].strip()
            return request.remote_addr
        except Exception as e:
            print(f"公网IP获取失败：{e}")
            return None

def get_public_ip_geo_info(target_ip: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """获取公网IP及地理位置（优化API调用逻辑）"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    # 优先使用ipinfo.io（最稳定）
    primary_api = f"https://ipinfo.io/{target_ip}/json" if target_ip else "https://ipinfo.io/json"
    try:
        response = requests.get(primary_api, headers=headers, timeout=8)
        response.raise_for_status()
        data = response.json()
        result = {
            "public_ip": data.get("ip", "未知"),
            "country": data.get("country", "未知"),
            "region": data.get("region", "未知"),
            "city": data.get("city", "未知"),
            "latitude": data.get("loc", "未知").split(',')[0] if data.get("loc") else "未知",
            "longitude": data.get("loc", "未知").split(',')[1] if data.get("loc") else "未知",
            "timezone": data.get("timezone", "未知"),
            "isp": data.get("org", "未知")
        }
        return result
    except Exception as e:
        print(f"主API（ipinfo.io）失败：{e}")

    # 备用API（逐个尝试）
    for api in IP_GEO_API_LIST[1:]:  # 跳过已尝试的ipinfo
        try:
            api_url = f"{api}/{target_ip}" if target_ip and api.endswith('/') else api
            response = requests.get(api_url, headers=headers, timeout=8)
            response.raise_for_status()
            data = response.json()
            result = {}

            # 提取IP
            ip_fields = ["ip", "query", "public_ip", "origin"]
            for field in ip_fields:
                if field in data:
                    result["public_ip"] = str(data[field]).strip().split(',')[0]
                    break
            if not result.get("public_ip"):
                continue

            # 提取地理信息
            result["country"] = data.get("country_name", data.get("country", "未知"))
            result["region"] = data.get("region_name", data.get("region", "未知"))
            result["city"] = data.get("city", "未知")
            result["latitude"] = data.get("latitude", data.get("loc", "未知").split(',')[0] if data.get("loc") else "未知")
            result["longitude"] = data.get("longitude", data.get("loc", "未知").split(',')[1] if data.get("loc") else "未知")
            result["timezone"] = data.get("timezone", data.get("utc_offset", "未知"))
            result["isp"] = data.get("isp", data.get("organization", data.get("org", "未知")))

            # 过滤无效值
            for key, val in result.items():
                result[key] = val if val and val not in ["N/A", "None"] else "未知"

            return result
        except Exception as e:
            print(f"备用API {api} 失败：{e}")
            continue

    return None

@app.route('/')
def index():
    """首页：修复IP查询逻辑"""
    server_local_ip = get_local_ip()
    # 1. 先获取真实公网IP
    visitor_public_ip = get_real_public_ip()
    print(f"获取到的公网IP：{visitor_public_ip}")  # 调试用，可删除
    # 2. 根据公网IP获取地理信息
    public_geo_info = get_public_ip_geo_info(visitor_public_ip) if visitor_public_ip else None

    return render_template(
        'index.html',
        server_local_ip=server_local_ip,
        public_geo_info=public_geo_info,
        visitor_public_ip=visitor_public_ip  # 传递给前端，方便调试
    )

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)  # debug=True便于查看错误