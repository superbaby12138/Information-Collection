import sys
import socket
import json
import time
import threading
import os
import shutil
import csv
import re
from typing import List, Dict, Set, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import dns.resolver
import whois
import ipaddress
import pandas as pd
from flask import Flask, request, jsonify, send_from_directory, make_response, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename

# -------------------------- 关键修复：Flask 静态文件路径配置 --------------------------
# 获取当前文件所在目录的绝对路径
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# 初始化Flask应用，指定static_folder为绝对路径
app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, 'static'),  # 静态文件目录（绝对路径）
    static_url_path=''  # 静态文件URL路径为空，直接通过文件名访问
)
CORS(app)

# 全局配置（路径改为绝对路径，避免相对路径错误）
DICT_FOLDER = os.path.join(BASE_DIR, 'static', 'dict')  # 字典文件夹路径
RESULT_FOLDER = os.path.join(BASE_DIR, 'asset_results')  # 结果文件夹路径
os.makedirs(DICT_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

# 字典配置（支持的技术栈对应字典文件名）
SUPPORTED_DICTS = {
    'php': 'PHP.txt',
    'asp': 'ASP.txt',
    'aspx': 'ASPX.txt',
    'jsp': 'JSP.txt',
    'mdb': 'MDB.txt'
}
DEFAULT_DICT = 'DIR.txt'  # 默认字典

# 多DNS解析器
DNS_RESOLVERS = [
    "8.8.8.8", "8.8.4.4", "223.5.5.5", "223.6.6.6", "119.29.29.29", "180.76.76.76"
]

# 全局状态管理
# 添加线程锁保护全局状态
global_state_lock = threading.Lock()
global_state = {
    'collecting': False,
    'log': [],
    'results': [],
    'current_target': '',
    'stop_event': threading.Event()
}

# -------------------------- 以下代码与之前完全一致，无需修改 --------------------------
class AssetCollectorCore:
    """核心资产收集逻辑"""
    def __init__(self, target: str, params: Dict):
        self.target = target.strip()
        self.params = params
        self.stop_event = global_state['stop_event']
        
        # 基础配置
        self.threads = params.get('threads', 20)
        self.timeout = params.get('timeout', 5)
        self.retry = params.get('retry', 2)
        
        # 目录爆破配置
        self.http_method = params.get('http_method', 'GET')
        self.status_whitelist = params.get('status_whitelist', [200, 301, 302, 401, 403, 500])
        self.status_blacklist = [404]
        self.min_size = params.get('min_size', 0)
        self.max_size = params.get('max_size', 1024*1024)
        self.custom_404 = params.get('custom_404', '')
        
        # 子域名爆破配置
        self.check_http = True
        self.dns_resolvers = DNS_RESOLVERS
        self.subdomain_dict_file = params.get('subdomain_dict', '')  # 用户选择的子域名字典文件
        self.enable_subdomain_brute = params.get('enable_subdomain_brute', True)  # 是否启用子域名爆破
        self.enable_directory_brute = params.get('enable_directory_brute', True)  # 是否启用目录爆破
        
        # 结果存储
        self.result = {
            'target': self.target,
            'collect_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'is_ip': self.is_ip(self.target),
            'ips': [],
            'open_ports': [],
            'http_service_info': [],
            'subdomains': [],
            'directories': [],
            '旁站_info': {},
            'tech_stack': [],  # 识别的技术栈
            'dict_used': ''     # 使用的字典文件名
        }

    def log(self, msg: str, level: str = 'info'):
        """日志记录（添加到全局日志）"""
        log_entry = {
            'time': datetime.now().strftime("%H:%M:%S"),
            'target': self.target,
            'level': level,
            'msg': msg
        }
        with global_state_lock:
            global_state['log'].append(log_entry)
        print(f"[{log_entry['time']}] [{log_entry['level']}] {self.target}: {msg}")

    # -------------------------- 基础工具方法 --------------------------
    def is_ip(self, target: str) -> bool:
        """判断是否为IPv4"""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False

    def resolve_domain(self, domain: str, resolver: str = None) -> Optional[List[str]]:
        """域名解析"""
        try:
            res = dns.resolver.Resolver()
            res.timeout = self.timeout
            res.lifetime = self.timeout
            res.nameservers = [resolver] if resolver else self.dns_resolvers[:2]
            answers = res.query(domain, 'A')
            return [str(rdata.address) for rdata in answers]
        except Exception as e:
            self.log(f"域名解析失败：{str(e)}", 'error')
            return None

    def scan_port(self, ip: str, port: int) -> Optional[Dict]:
        """端口扫描"""
        if self.stop_event.is_set():
            return None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = ""
                try:
                    if port in [80, 443, 8080, 8443]:
                        sock.send(b"HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % ip.encode())
                    elif port == 22:
                        sock.send(b"\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:200]
                except:
                    banner = "Unknown Service"
                sock.close()
                port_type = self.get_port_type(port)
                self.log(f"发现开放端口：{ip}:{port}（{port_type}）", 'success')
                return {
                    "ip": ip,
                    "port": port,
                    "status": "open",
                    "banner": banner,
                    "port_type": port_type
                }
            sock.close()
            return None
        except Exception as e:
            return None

    @staticmethod
    def get_port_type(port: int) -> str:
        """端口类型映射"""
        port_type_map = {
            80: "HTTP", 443: "HTTPS", 8080: "HTTP(备用)", 8443: "HTTPS(备用)",
            22: "SSH", 3389: "RDP", 1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL"
        }
        return port_type_map.get(port, "Unknown")

    # -------------------------- 1. 技术栈识别（用于智能字典匹配） --------------------------
    def identify_tech_stack(self, url: str) -> List[str]:
        """识别网站技术栈（从响应头和页面内容）"""
        tech_stack = set()
        try:
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            headers = response.headers
            
            # 从响应头识别
            server = headers.get('Server', '').lower()
            x_powered_by = headers.get('X-Powered-By', '').lower()
            if 'php' in x_powered_by or 'php' in server:
                tech_stack.add('php')
            if 'asp' in x_powered_by or 'asp' in server:
                tech_stack.add('asp')
            if 'aspx' in x_powered_by or 'aspx' in server:
                tech_stack.add('aspx')
            if 'jsp' in x_powered_by or 'jsp' in server:
                tech_stack.add('jsp')
            
            # 从页面内容识别
            if '.php' in response.text:
                tech_stack.add('php')
            if '.asp' in response.text or '.aspx' in response.text:
                tech_stack.add('asp')
                tech_stack.add('aspx')
            if '.jsp' in response.text:
                tech_stack.add('jsp')
            if '.mdb' in response.text:
                tech_stack.add('mdb')
        
        except Exception as e:
            self.log(f"技术栈识别失败：{str(e)}", 'warning')
        
        tech_stack = list(tech_stack)
        self.log(f"识别到技术栈：{tech_stack}", 'info')
        return tech_stack

    # -------------------------- 2. 智能字典加载 --------------------------
    def load_intelligent_dict(self, tech_stack: List[str]) -> List[str]:
        """智能加载字典（优先技术栈对应字典，无则用默认）"""
        dict_path = None
        
        # 优先匹配技术栈对应的字典
        for tech in tech_stack:
            if tech in SUPPORTED_DICTS:
                dict_filename = SUPPORTED_DICTS[tech]
                dict_path = os.path.join(DICT_FOLDER, dict_filename)
                if os.path.exists(dict_path):
                    self.result['dict_used'] = dict_filename
                    break
        
        # 无对应字典，使用默认DIR.txt
        if not dict_path or not os.path.exists(dict_path):
            dict_path = os.path.join(DICT_FOLDER, DEFAULT_DICT)
            self.result['dict_used'] = DEFAULT_DICT
        
        # 加载字典（去重、过滤空行）
        if not os.path.exists(dict_path):
            self.log(f"未找到字典文件，使用内置默认字典", 'warning')
            return self.get_default_dir_dict()
        
        try:
            with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
            unique_lines = list(set(lines))
            self.log(f"加载字典成功：{os.path.basename(dict_path)} → {len(unique_lines)} 个条目", 'success')
            return unique_lines
        except Exception as e:
            self.log(f"字典加载失败：{str(e)}", 'error')
            return self.get_default_dir_dict()

    @staticmethod
    def get_default_dir_dict() -> List[str]:
        """内置默认目录字典"""
        return [
            "/", "/admin", "/login", "/dashboard", "/panel", "/manage", "/user", "/auth",
            "/api", "/v1", "/v2", "/doc", "/docs", "/help", "/support", "/blog", "/news",
            "/about", "/contact", "/register", "/signup", "/logout", "/settings", "/config",
            "/backup", "/backup.zip", "/db.sql", "/phpmyadmin", "/phpinfo.php", "/robots.txt"
        ]

    # -------------------------- 3. 子域名爆破（Layer级） --------------------------
    def load_subdomain_dict(self) -> List[str]:
        """加载子域名字典（优先使用用户选择的字典，然后尝试默认路径）"""
        subdomain_folder = os.path.join(BASE_DIR, 'static', '子域名')
        
        # 1. 如果用户指定了字典文件
        if self.subdomain_dict_file:
            sub_dict_path = os.path.join(subdomain_folder, self.subdomain_dict_file)
            if os.path.exists(sub_dict_path):
                try:
                    with open(sub_dict_path, "r", encoding="utf-8") as f:
                        lines = [line.strip() for line in f.readlines() if line.strip()]
                    self.result['dict_used'] = self.subdomain_dict_file
                    return list(set(lines))
                except Exception as e:
                    self.log(f"用户选择的子域名字典加载失败：{str(e)}", 'error')
        
        # 2. 尝试读取默认子域名字典文件
        for dict_file in ['dic.txt', '子域名.txt', 'dic1.txt']:
            sub_dict_path = os.path.join(subdomain_folder, dict_file)
            if os.path.exists(sub_dict_path):
                try:
                    with open(sub_dict_path, "r", encoding="utf-8") as f:
                        lines = [line.strip() for line in f.readlines() if line.strip()]
                    self.result['dict_used'] = dict_file
                    return list(set(lines))
                except Exception as e:
                    self.log(f"子域名字典 {dict_file} 加载失败：{str(e)}", 'error')
        
        # 3. 内置默认子域名字典
        self.result['dict_used'] = '内置字典'
        return [
            "www", "admin", "api", "blog", "test", "dev", "app", "web", "m", "mobile",
            "ftp", "mail", "smtp", "pop3", "imap", "dns", "ns1", "ns2", "cdn", "static"
        ]

    def generate_subdomains(self, domain: str) -> List[str]:
        """生成子域名列表"""
        sub_dict = self.load_subdomain_dict()
        subdomains = [f"{sub}.{domain}" for sub in sub_dict]
        return list(set(subdomains))

    def check_subdomain(self, subdomain: str) -> Optional[Dict]:
        """子域名存活检测"""
        if self.stop_event.is_set():
            return None
        try:
            # DNS解析（多解析器重试）
            ip_list = None
            for resolver in self.dns_resolvers[:3]:
                ip_list = self.resolve_domain(subdomain, resolver)
                if ip_list:
                    break
            if not ip_list:
                return None
            
            # HTTP验证
            http_info = None
            if self.check_http:
                for port in [80, 443]:
                    scheme = "https" if port == 443 else "http"
                    url = f"{scheme}://{subdomain}:{port}"
                    try:
                        response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                        http_info = {
                            "url": url,
                            "status_code": response.status_code,
                            "title": self.extract_title(response.text)
                        }
                        break
                    except:
                        continue
            
            self.log(f"发现存活子域名：{subdomain} → IP: {ip_list}", 'success')
            return {
                "subdomain": subdomain,
                "ips": ip_list,
                "http_info": http_info,
                "check_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e:
            return None

    def brute_force_subdomains(self) -> List[Dict]:
        """子域名爆破主逻辑"""
        if self.result['is_ip']:
            self.log("目标是IP，跳过子域名爆破", 'info')
            return []
        
        domain = self.target
        self.log(f"开始子域名爆破（字典大小：{len(self.load_subdomain_dict())}）", 'info')
        subdomains = self.generate_subdomains(domain)
        results = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            tasks = [executor.submit(self.check_subdomain, sub) for sub in subdomains]
            for future in as_completed(tasks):
                if self.stop_event.is_set():
                    executor.shutdown(wait=False)
                    break
                res = future.result()
                if res:
                    results.append(res)
        
        self.log(f"子域名爆破完成：共发现 {len(results)} 个存活子域名", 'info')
        return results

    # -------------------------- 4. 目录爆破（御剑级） --------------------------
    def extract_title(self, html: str) -> str:
        """提取页面标题"""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip().replace("\n", "").replace("\r", "")[:50]
        return "No Title"

    def is_custom_404(self, response: requests.Response) -> bool:
        """自定义404识别"""
        if not self.custom_404:
            return False
        if self.custom_404.isdigit():
            return len(response.text) == int(self.custom_404)
        return self.custom_404 in response.text

    def scan_directory(self, url: str, dir_path: str) -> Optional[Dict]:
        """单个目录扫描"""
        if self.stop_event.is_set():
            return None
        target_url = f"{url.rstrip('/')}/{dir_path.lstrip('/')}"
        try:
            # 超时重试
            response = None
            for _ in range(self.retry):
                try:
                    if self.http_method == "HEAD":
                        response = requests.head(target_url, timeout=self.timeout, verify=False, allow_redirects=True)
                    else:
                        response = requests.get(target_url, timeout=self.timeout, verify=False, allow_redirects=True)
                    break
                except:
                    time.sleep(0.5)
                    continue
            if not response:
                return None
        
            # 状态码过滤
            if response.status_code in self.status_blacklist:
                return None
            if self.status_whitelist and response.status_code not in self.status_whitelist:
                return None
        
            # 自定义404过滤
            if self.is_custom_404(response):
                return None
        
            # 大小过滤
            content_length = len(response.text)
            if not (self.min_size <= content_length <= self.max_size):
                return None
        
            # 提取信息
            title = self.extract_title(response.text) if self.http_method == "GET" else "N/A"
            self.log(f"发现有效目录：{target_url} → 状态码: {response.status_code}, 大小: {content_length}B", 'success')
            return {
                "url": target_url,
                "status_code": response.status_code,
                "content_length": content_length,
                "title": title,
                "redirect_url": str(response.url) if response.url != target_url else "None",
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e:
            return None

    def brute_force_directories(self, web_urls: List[str], tech_stack: List[str]) -> List[Dict]:
        """目录爆破主逻辑（智能字典）"""
        if not web_urls:
            self.log("无可用Web URL，跳过目录爆破", 'info')
            return []
        
        # 智能加载字典
        dir_dict = self.load_intelligent_dict(tech_stack)
        self.log(f"开始目录爆破（字典：{self.result['dict_used']}，目标URL数：{len(web_urls)}）", 'info')
        results = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            tasks = []
            for url in web_urls:
                for dir_path in dir_dict:
                    tasks.append(executor.submit(self.scan_directory, url, dir_path))
            for future in as_completed(tasks):
                if self.stop_event.is_set():
                    executor.shutdown(wait=False)
                    break
                res = future.result()
                if res:
                    results.append(res)
        
        self.log(f"目录爆破完成：共发现 {len(results)} 个有效目录", 'info')
        return results

    # -------------------------- 5. 旁站探测 --------------------------
    def reverse_ip_lookup(self, ip: str) -> List[str]:
        """IP反查域名"""
        domains = []
        try:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200 and "error" not in response.text.lower():
                domains = [d.strip() for d in response.text.split("\n") if d.strip() and "." in d]
            self.log(f"IP反查完成：{ip} → 发现 {len(domains)} 个旁站域名", 'info')
        except Exception as e:
            self.log(f"IP反查失败：{str(e)}", 'error')
        return list(set(domains))

    def scan_c_segment(self, ip: str) -> List[Dict]:
        """C段扫描"""
        assets = []
        try:
            c_segment = ".".join(ip.split(".")[:3]) + ".0"
            network = ipaddress.ip_network(f"{c_segment}/24", strict=False)
            self.log(f"开始C段扫描：{network}（共 {network.num_addresses} 个IP）", 'info')
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                tasks = []
                for ip_obj in network.hosts():
                    ip_str = str(ip_obj)
                    if ip_str == c_segment or ip_str.endswith(".255"):
                        continue
                    tasks.append(executor.submit(self.scan_port, ip_str, 80))
                for future in as_completed(tasks):
                    if self.stop_event.is_set():
                        break
                    res = future.result()
                    if res:
                        assets.append(res)
            
            self.log(f"C段扫描完成：发现 {len(assets)} 个开放80端口的资产", 'info')
        except Exception as e:
            self.log(f"C段扫描失败：{str(e)}", 'error')
        return assets

    # -------------------------- 主收集逻辑 --------------------------
    def collect(self) -> Dict:
        """执行收集任务"""
        self.log("开始资产收集", 'info')
        
        # 1. 基础信息解析
        if not self.result['is_ip']:
            self.result['ips'] = self.resolve_domain(self.target) or []
            if self.enable_subdomain_brute:
                self.result['subdomains'] = self.brute_force_subdomains()
            else:
                self.log("已禁用子域名爆破", 'info')
        else:
            self.result['ips'] = [self.target]
            self.log("目标是IP，跳过子域名爆破", 'info')
        
        if not self.result['ips']:
            self.log("未获取到有效IP，收集终止", 'error')
            return self.result
        
        # 2. 端口扫描
        self.log(f"开始端口扫描（目标IP：{self.result['ips']}）", 'info')
        common_ports = [80, 443, 8080, 8443, 22, 3389, 3306, 1433]
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            tasks = []
            for ip in self.result['ips']:
                for port in common_ports:
                    tasks.append(executor.submit(self.scan_port, ip, port))
            for future in as_completed(tasks):
                if self.stop_event.is_set():
                    executor.shutdown(wait=False)
                    break
                res = future.result()
                if res:
                    self.result['open_ports'].append(res)
        
        # 3. Web服务信息与技术栈识别
        web_urls = []
        tech_stack = set()
        for port_info in self.result['open_ports']:
            if port_info["port_type"] in ["HTTP", "HTTPS", "HTTP(备用)", "HTTPS(备用)"]:
                scheme = "https" if port_info["port"] in [443, 8443] else "http"
                url = f"{scheme}://{port_info['ip']}:{port_info['port']}"
                web_urls.append(url)
                # 识别技术栈
                stack = self.identify_tech_stack(url)
                tech_stack.update(stack)
        
        self.result['tech_stack'] = list(tech_stack)
        self.result['http_service_info'] = [{"url": url} for url in web_urls]
        
        # 4. 目录爆破（智能字典）
        if self.enable_directory_brute:
            self.result['directories'] = self.brute_force_directories(web_urls, self.result['tech_stack'])
        else:
            self.log("已禁用目录爆破", 'info')
        
        # 5. 旁站探测
        旁站_info = {
            "reverse_ip_domains": [],
            "c_segment_assets": []
        }
        for ip in self.result['ips']:
            旁站_info["reverse_ip_domains"].extend(self.reverse_ip_lookup(ip))
            旁站_info["c_segment_assets"].extend(self.scan_c_segment(ip))
        self.result['旁站_info'] = 旁站_info
        
        # 6. 导出结果（按域名分文件夹）
        self.export_result()
        
        self.log("资产收集完成", 'success')
        return self.result

    # -------------------------- 按域名分文件夹导出（JSON+CSV） --------------------------
    def export_result(self):
        """导出结果到独立文件夹（JSON+CSV）"""
        # 创建目标文件夹（域名/IP作为文件夹名）
        target_folder_name = secure_filename(self.target)
        target_folder = os.path.join(RESULT_FOLDER, target_folder_name)
        os.makedirs(target_folder, exist_ok=True)
        
        # 导出JSON
        json_path = os.path.join(target_folder, 'result.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.result, f, ensure_ascii=False, indent=2)
        
        # 导出CSV（扁平化数据）
        csv_data = []
        
        # 开放端口
        for port in self.result['open_ports']:
            csv_data.append({
                '目标': self.result['target'],
                '类型': '开放端口',
                '内容': f"{port['ip']}:{port['port']}",
                '状态': '开放',
                '额外信息': f"{port['port_type']} | {port['banner'][:30]}",
                '时间': self.result['collect_time']
            })
        
        # 子域名
        for sub in self.result['subdomains']:
            extra = f"IP: {','.join(sub['ips'])}"
            if sub['http_info']:
                extra += f" | URL: {sub['http_info']['url']} | 状态码: {sub['http_info']['status_code']}"
            csv_data.append({
                '目标': self.result['target'],
                '类型': '存活子域名',
                '内容': sub['subdomain'],
                '状态': '存活',
                '额外信息': extra,
                '时间': sub['check_time']
            })
        
        # 有效目录
        for dir_info in self.result['directories']:
            csv_data.append({
                '目标': self.result['target'],
                '类型': '有效目录',
                '内容': dir_info['url'],
                '状态': f"状态码: {dir_info['status_code']}",
                '额外信息': f"大小: {dir_info['content_length']}B | 标题: {dir_info['title']}",
                '时间': dir_info['scan_time']
            })
        
        # 旁站域名
        for domain in self.result['旁站_info']['reverse_ip_domains']:
            csv_data.append({
                '目标': self.result['target'],
                '类型': '旁站域名',
                '内容': domain,
                '状态': '存在',
                '额外信息': f"关联IP: {','.join(self.result['ips'])}",
                '时间': self.result['collect_time']
            })
        
        # C段资产
        for c_asset in self.result['旁站_info']['c_segment_assets']:
            csv_data.append({
                '目标': self.result['target'],
                '类型': 'C段资产',
                '内容': f"{c_asset['ip']}:{c_asset['port']}",
                '状态': '开放',
                '额外信息': f"{c_asset['port_type']} | {c_asset['banner'][:30]}",
                '时间': self.result['collect_time']
            })
        
        # 写入CSV
        csv_path = os.path.join(target_folder, 'result.csv')
        if csv_data:
            df = pd.DataFrame(csv_data)
            df.to_csv(csv_path, index=False, encoding='utf-8-sig')
        else:
            # 无数据时创建空CSV
            with open(csv_path, 'w', encoding='utf-8-sig', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['目标', '类型', '内容', '状态', '额外信息', '时间'])
        
        self.log(f"结果已导出至：{target_folder}", 'success')

# -------------------------- Flask API接口 --------------------------
@app.route('/')
def index():
    """前端页面入口（修复：直接读取static目录下的index.html）"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/start', methods=['POST'])
def start_collect():
    """启动收集任务"""
    with global_state_lock:
        if global_state['collecting']:
            return jsonify({'code': 400, 'msg': '当前已有收集任务在运行！'})
    
    data = request.json
    targets = [t.strip() for t in data.get('targets', '').split('\n') if t.strip()]
    params = data.get('params', {})
    
    if not targets:
        return jsonify({'code': 400, 'msg': '请输入至少一个目标！'})
    
    # 初始化全局状态
    with global_state_lock:
        global_state['collecting'] = True
        global_state['log'] = []
        global_state['results'] = []
    global_state['stop_event'].clear()
    
    # 启动收集线程（多目标串行执行）
    def collect_thread():
        try:
            for target in targets:
                if global_state['stop_event'].is_set():
                    break
                with global_state_lock:
                    global_state['current_target'] = target
                collector = AssetCollectorCore(target, params)
                result = collector.collect()
                with global_state_lock:
                    global_state['results'].append(result)
        finally:
            with global_state_lock:
                global_state['collecting'] = False
                global_state['current_target'] = ''
    
    threading.Thread(target=collect_thread, daemon=True).start()
    return jsonify({'code': 200, 'msg': '收集任务已启动！'})

@app.route('/api/start_subdomain_brute', methods=['POST'])
def start_subdomain_brute():
    """仅启动子域名爆破"""
    with global_state_lock:
        if global_state['collecting']:
            return jsonify({'code': 400, 'msg': '当前已有收集任务在运行！'})
    
    data = request.json
    targets = [t.strip() for t in data.get('targets', '').split('\n') if t.strip()]
    params = data.get('params', {})
    
    if not targets:
        return jsonify({'code': 400, 'msg': '请输入至少一个目标！'})
    
    # 初始化全局状态
    with global_state_lock:
        global_state['collecting'] = True
        global_state['log'] = []
        global_state['results'] = []
    global_state['stop_event'].clear()
    
    # 启动子域名爆破线程
    def subdomain_thread():
        try:
            for target in targets:
                if global_state['stop_event'].is_set():
                    break
                with global_state_lock:
                    global_state['current_target'] = target
                collector = AssetCollectorCore(target, params)
                
                # 仅执行子域名爆破
                collector.log(f"开始对 {target} 进行子域名爆破", 'info')
                collector.result['target'] = target
                collector.result['is_ip'] = collector.is_ip(target)
                
                if not collector.result['is_ip']:
                    subdomains = collector.brute_force_subdomains()
                    collector.result['subdomains'] = subdomains
                    collector.result['subdomain_count'] = len(subdomains)
                else:
                    collector.log(f"{target} 是IP地址，跳过子域名爆破", 'info')
                    collector.result['subdomains'] = []
                    collector.result['subdomain_count'] = 0
                
                # 导出结果
                collector.export_result()
                
                with global_state_lock:
                    global_state['results'].append(collector.result)
        finally:
            with global_state_lock:
                global_state['collecting'] = False
                global_state['current_target'] = ''
    
    threading.Thread(target=subdomain_thread, daemon=True).start()
    return jsonify({'code': 200, 'msg': '子域名爆破任务已启动！'})

@app.route('/api/start_directory_brute', methods=['POST'])
def start_directory_brute():
    """仅启动目录爆破"""
    with global_state_lock:
        if global_state['collecting']:
            return jsonify({'code': 400, 'msg': '当前已有收集任务在运行！'})
    
    data = request.json
    targets = [t.strip() for t in data.get('targets', '').split('\n') if t.strip()]
    params = data.get('params', {})
    
    if not targets:
        return jsonify({'code': 400, 'msg': '请输入至少一个目标！'})
    
    # 初始化全局状态
    with global_state_lock:
        global_state['collecting'] = True
        global_state['log'] = []
        global_state['results'] = []
    global_state['stop_event'].clear()
    
    # 启动目录爆破线程
    def directory_thread():
        try:
            for target in targets:
                if global_state['stop_event'].is_set():
                    break
                with global_state_lock:
                    global_state['current_target'] = target
                collector = AssetCollectorCore(target, params)
                
                # 执行目录爆破前的必要准备
                collector.log(f"开始对 {target} 进行目录爆破", 'info')
                collector.result['target'] = target
                collector.result['is_ip'] = collector.is_ip(target)
                
                # 解析域名或直接使用IP
                if collector.result['is_ip']:
                    ip = target
                    collector.result['resolved_ips'] = [ip]
                else:
                    collector.result['resolved_ips'] = collector.resolve_domain(target)
                    if not collector.result['resolved_ips']:
                        collector.log(f"无法解析域名 {target}", 'error')
                        continue
                    ip = collector.result['resolved_ips'][0]
                
                # 端口扫描获取web服务
                collector.result['open_ports'] = []
                collector.result['web_services'] = []
                collector.result['directories'] = []
                collector.result['directory_count'] = 0
                
                # 扫描常见web端口
                web_ports = [80, 443, 8080, 8443, 8000, 8888]
                for port in web_ports:
                    if global_state['stop_event'].is_set():
                        break
                    result = collector.scan_port(ip, port)
                    if result:
                        collector.result['open_ports'].append(result)
                        if result['service'] in ['http', 'https']:
                            collector.result['web_services'].append(result)
                
                # 如果没有发现web服务，尝试添加默认的http和https
                if not collector.result['web_services']:
                    collector.result['web_services'].append({'ip': ip, 'port': 80, 'service': 'http', 'status': 'open'})
                    collector.result['web_services'].append({'ip': ip, 'port': 443, 'service': 'https', 'status': 'open'})
                
                # 构建web_urls
                web_urls = []
                for service in collector.result['web_services']:
                    protocol = service['service']
                    web_urls.append(f"{protocol}://{ip}:{service['port']}")
                    if not collector.result['is_ip']:
                        web_urls.append(f"{protocol}://{target}:{service['port']}")
                
                # 识别技术栈
                tech_stack = []
                for url in web_urls:
                    if global_state['stop_event'].is_set():
                        break
                    try:
                        stack = collector.identify_tech_stack(url)
                        tech_stack.extend(stack)
                    except:
                        pass
                tech_stack = list(set(tech_stack))
                collector.result['tech_stack'] = tech_stack
                
                # 执行目录爆破
                directories = collector.brute_force_directories(web_urls, tech_stack)
                collector.result['directories'] = directories
                collector.result['directory_count'] = len(directories)
                
                # 导出结果
                collector.export_result()
                
                with global_state_lock:
                    global_state['results'].append(collector.result)
        finally:
            with global_state_lock:
                global_state['collecting'] = False
                global_state['current_target'] = ''
    
    threading.Thread(target=directory_thread, daemon=True).start()
    return jsonify({'code': 200, 'msg': '目录爆破任务已启动！'})

@app.route('/api/stop', methods=['POST'])
def stop_collect():
    """停止收集任务"""
    global_state['stop_event'].set()
    with global_state_lock:
        global_state['collecting'] = False
    return jsonify({'code': 200, 'msg': '收集任务已停止！'})

@app.route('/api/status', methods=['GET'])
def get_status():
    """获取当前状态（收集状态、日志、结果）"""
    # 限制返回的日志数量，只返回最新的100条
    recent_logs = global_state['log'][-100:] if len(global_state['log']) > 100 else global_state['log']
    return jsonify({
        'code': 200,
        'data': {
            'collecting': global_state['collecting'],
            'current_target': global_state['current_target'],
            'log': recent_logs,
            'results': global_state['results']
        }
    })

@app.route('/api/export/<target>', methods=['GET'])
def export_target(target):
    """下载单个目标的结果（ZIP压缩包）"""
    target_folder_name = secure_filename(target)
    target_folder = os.path.join(RESULT_FOLDER, target_folder_name)
    
    if not os.path.exists(target_folder):
        return jsonify({'code': 404, 'msg': '目标结果文件夹不存在！'})
    
    # 压缩文件夹
    zip_path = os.path.join(RESULT_FOLDER, f"{target_folder_name}.zip")
    shutil.make_archive(zip_path.replace('.zip', ''), 'zip', target_folder)
    
    # 下载压缩包
    response = make_response(send_from_directory(RESULT_FOLDER, f"{target_folder_name}.zip"))
    response.headers['Content-Disposition'] = f'attachment; filename="{target_folder_name}.zip"'
    return response

@app.route('/api/export/all', methods=['GET'])
def export_all():
    """下载所有目标的结果（ZIP压缩包）"""
    zip_path = os.path.join(RESULT_FOLDER, 'all_results.zip')
    shutil.make_archive(zip_path.replace('.zip', ''), 'zip', RESULT_FOLDER)
    
    response = make_response(send_from_directory(RESULT_FOLDER, 'all_results.zip'))
    response.headers['Content-Disposition'] = f'attachment; filename="all_results.zip"'
    return response

@app.route('/api/dict/list', methods=['GET'])
def list_dict():
    """列出可用的目录字典文件"""
    try:
        dicts = []
        for filename in os.listdir(DICT_FOLDER):
            if filename.endswith('.txt'):
                dicts.append(filename)
        return jsonify({'code': 200, 'data': dicts})
    except Exception as e:
        return jsonify({'code': 500, 'msg': str(e)})

@app.route('/api/get_result', methods=['GET'])
def get_result():
    """获取资产收集结果数据"""
    try:
        target = request.args.get('target', '').strip()
        if not target:
            return jsonify({'success': False, 'message': '缺少目标参数'})
        
        # 查找目标结果文件夹
        target_folder_name = secure_filename(target)
        target_folder = os.path.join(RESULT_FOLDER, target_folder_name)
        
        if not os.path.exists(target_folder):
            return jsonify({'success': False, 'message': '未找到该目标的收集结果'})
        
        # 读取result.json文件
        json_path = os.path.join(target_folder, 'result.json')
        if not os.path.exists(json_path):
            return jsonify({'success': False, 'message': '结果文件不存在'})
        
        with open(json_path, 'r', encoding='utf-8') as f:
            result_data = json.load(f)
        
        return jsonify({'success': True, 'data': result_data})
    except Exception as e:
        return jsonify({'success': False, 'message': f'获取结果失败: {str(e)}'})

@app.route('/api/subdomain/dict/list', methods=['GET'])
def list_subdomain_dict():
    """列出可用的子域名字典文件"""
    try:
        subdomain_folder = os.path.join(BASE_DIR, 'static', '子域名')
        dicts = []
        for filename in os.listdir(subdomain_folder):
            if filename.endswith('.txt'):
                dicts.append(filename)
        return jsonify({'code': 200, 'data': dicts})
    except Exception as e:
        return jsonify({'code': 500, 'msg': str(e)})

if __name__ == "__main__":
    # 启动Flask服务（支持外部访问）
    app.run(host='0.0.0.0', port=5000, debug=False)