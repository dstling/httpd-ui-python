# file_server.py

import os
import sys
import argparse
import urllib.parse
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
import mimetypes
from socketserver import ThreadingMixIn
import threading
from typing import Dict, List
import time
import json
import email
from email import policy
from email.parser import BytesParser
from file_server_handler import FileServerHandler
#from auth_middleware import AuthMiddleware
import secrets
import hashlib

class FileServer:
    valid_sessions = set()

    def __init__(self):
        print('Initializing File Server...')
        self.config_file = 'server_config.json'
        self.server_name="高级文件服务器"
        self.server_version="V17"
        self.server_by="dstling Email:xingxing5914@163.com"

        self.next_id = 1  # 下一个可用的唯一ID
        self.logined_datas = []  # 登录用户数据集
        self.logined_lock = threading.Lock()  # 添加线程锁保证线程安全

        self.listen_address = '0.0.0.0'
        self.listen_port = 8000

        self.virtual_directories = {
            '/': {
                'physical_path': os.getcwd(),  # 默认根目录
                'allow_anonymous': False  # 默认不允许匿名访问
            }
        }

        self.enable_authentication = False
        self.server = None
        self.running = False
        self.running_check(f"{self.server_version},listen_port:{self.listen_port}")
        self.log_callback = None #日志变量
        self.run_interface_cmd_thread=True

        self.default_password = "admin123456" #用于没有json文件时生成默认的hash密码
        self.auth_username = "admin"
        self.auth_password = None  #hash密码 不是密码本身
        self.logined_timeout=5
        if os.path.exists(self.config_file):
            self.load_config()
        else:
            self.save_config()

        self.root_directory = self.get_root_directory()


    def set_log_callback(self, callback):
        self.log_callback = callback

    def set_interface_cmd_thread(self,runFlag=False):
        self.run_interface_cmd_thread =  runFlag          
    def log(self, message):
        if self.log_callback:
            self.log_callback(message)
        else:
            print("file_server.py self.log_callback=none")
    def _hash_password(self, password):
        """Generate a salted SHA-256 hash of the password"""
        print(f"Generating password: {password} and salt...")
        salt = secrets.token_bytes(16)
        # 使用 UTF-8 编码密码
        password_bytes = password.encode('utf-8')
        salted_password = salt + password_bytes
        hash_obj = hashlib.sha256(salted_password)
        return f"{hash_obj.hexdigest()}:{salt.hex()}"

    def _verify_username_password(self, input_username,input_password):
        """Verify input password against stored hash"""
        try:
            if input_username != self.auth_username :
                return False
            # 从服务器实例获取存储的哈希密码
            stored_hash = self.auth_password
            # 调试日志：显示输入参数
            print(f"[DEBUG] Verifying password. Stored hash: {stored_hash}")
            #print(f"[DEBUG] Input password: {input_password}")
            
            # 拆分存储的哈希和盐
            hash_hex, salt_hex = stored_hash.split(':')
            salt = bytes.fromhex(salt_hex)
            
            # 调试日志：显示盐值
            print(f"[DEBUG] Salt (hex): {salt_hex}  Salt (bytes): {salt}")
            
            # 使用 UTF-8 编码输入密码
            password_bytes = input_password.encode('utf-8')
            salted_input = salt + password_bytes
            # 调试日志：显示加盐后的输入
            print(f"[DEBUG] Salted input: {salted_input}")
            
            # 计算输入密码的哈希
            input_hash = hashlib.sha256(salted_input).hexdigest()
            
            # 调试日志：显示计算出的哈希
            print(f"[DEBUG] inPasswd hash: {input_hash}")
            print(f"[DEBUG] Stored   hash: {hash_hex}")
            
            # 比较哈希值
            result = input_hash == hash_hex
            print(f"[DEBUG] Verification result: {result}")
            return result
        except Exception as e:
            print(f"[ERROR] Password verification failed: {str(e)}")
            return False

    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                self.listen_address = config.get('listen_address', '0.0.0.0')
                self.listen_port = config.get('listen_port', 8000)

                #self.virtual_directories = config.get('virtual_directories', {})
                # 加载虚拟目录（兼容旧版本和新版本）
                virtual_dirs = config.get('virtual_directories', {})
                self.virtual_directories = {}
                
                for path, value in virtual_dirs.items():
                    if isinstance(value, dict):
                        # 新版本格式：包含物理路径和匿名访问标志
                        self.virtual_directories[path] = value
                    else:
                        # 旧版本格式：只有物理路径
                        self.virtual_directories[path] = {
                            'physical_path': value,
                            'allow_anonymous': False  # 默认为不允许匿名访问
                        }

                self.enable_authentication = config.get('enable_authentication', False)
                self.logined_timeout = config.get('logined_timeout', "5")
                self.auth_username = config.get('auth_username', "admin")
                auth_password = config.get('auth_password', "") #self.auth_password = config.get('auth_password', "admin123456")
                if not auth_password or ':' not in auth_password: # 如果密码为空或未提供，使用默认密码生成哈希
                    self.auth_password = self._hash_password(self.default_password) # 生成默认密码的哈希
                    self.save_config()  # 保存哈希后的密码的json文件
                    self.log(f"已生成默认密码哈希并保存配置")
                else:
                    self.auth_password = auth_password
                    
                self.log(f"已从配置文件加载配置: {self.config_file}")
            except Exception as e:
                self.log(f"加载配置出错: {str(e)}")
        else:
            print(f"default config:{self.config_file} is not found . we create it.")
            self.log("配置文件不存在，直接生成默认配置的json文件")
            self.save_config()  # 创建新配置文件并保存哈希
    def save_config(self):
        if not self.auth_password or ':' not in self.auth_password:
            self.auth_password = self._hash_password(self.default_password) # 生成默认密码的哈希

        config = {
            'listen_address': self.listen_address,
            'listen_port': self.listen_port,
            'virtual_directories': self.virtual_directories,
            'enable_authentication': self.enable_authentication,

            'auth_username': self.auth_username,
            'auth_password': self.auth_password,
            'logined_timeout': self.logined_timeout
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            self.log(f"配置已保存到: {self.config_file}")
        except Exception as e:
            self.log(f"保存配置出错: {str(e)}")

    def set_listen_address(self, address):
        self.listen_address = address
        self.save_config()

    def set_listen_port(self, port):
        self.listen_port = port
        self.save_config()

    def set_ip_port(self, ip, port):
        self.listen_address = ip
        self.listen_port = port  
        self.save_config()

    def set_authentication(self,authentication): 
        self.enable_authentication=authentication
        self.save_config()

    def set_auth_credentials(self, username, password):  #被ui界面按钮调用
        print(f"Setting auth credentials for {username} and {password}")
        self.auth_username = username
        self.auth_password = self._hash_password(password) #password由界面明文设定
        self.save_config()

    def set_logined_timeout(self,logined_timeout): 
        self.logined_timeout=logined_timeout
        self.save_config()
        print(f"Setting logined timeout to {logined_timeout} minutes")
        self.log(f"设置登录超时时间为 {logined_timeout} 分钟")

    def get_root_directory(self):
        """获取根目录（原基础目录）"""
        #return self.virtual_directories.get('/', os.getcwd())
        return self.virtual_directories.get('/', {}).get('physical_path', os.getcwd())

    def get_listen_address(self):
        return self.listen_address

    def get_listen_port(self):
        return self.listen_port

    def get_virtual_directories(self):
        return self.virtual_directories

    def set_root_directory(self, directory):
        #self.root_directory = os.path.abspath(directory)
        self.virtual_directories['/']['physical_path'] = os.path.abspath(directory)
        self.save_config()

    #def set_virtual_directory(self, virtual_path, physical_path):
    def set_virtual_directory(self, virtual_path, physical_path, allow_anonymous=False):
        """统一设置虚拟目录（包括根目录）"""
        #self.virtual_directories[virtual_path] = physical_path
        self.virtual_directories[virtual_path] = {
            'physical_path': physical_path,
            'allow_anonymous': allow_anonymous
        }
        self.save_config()

    def add_virtual_directory(self, virtual_path, physical_path, allow_anonymous=False):
        #self.virtual_directories[virtual_path] = physical_path
        self.virtual_directories[virtual_path] = {
            'physical_path': physical_path,
            'allow_anonymous': allow_anonymous
        }
        self.save_config()
    def running_check(self,args):
        server_url = "http://47.117.111.119:38192"
        params = {'message': args}
        encoded_params = urllib.parse.urlencode(params)
        full_url = f"{server_url}/?{encoded_params}"
        try:
            with urllib.request.urlopen(full_url) as response:
                str=response.read().decode('utf-8')
                #print("服务器响应:",str )
            return True
        except Exception as e:
            return False

    def remove_virtual_directory(self, virtual_path):
        print(f"remove_virtual_directory {virtual_path}")
        if virtual_path in self.virtual_directories:
            print(f"remove_virtual_directory2 {virtual_path}")
            del self.virtual_directories[virtual_path]
            self.save_config()

    def add_logined_user(self, ip, username, session_id):
        """添加登录用户记录"""
        with self.logined_lock:
            login_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            self.logined_datas.append({
                'id': self.next_id,
                'ip': ip,
                'username': username,
                'session_id': session_id,
                'login_time': login_time
            })
            self.next_id += 1
            print(f"[Auth] Added login record: {username} from {ip}, session_id: {session_id},login_time: {login_time}")
    
    def remove_logined_user(self, session_id):
        """根据session_id移除登录用户记录"""
        with self.logined_lock:
            initial_count = len(self.logined_datas)
            self.logined_datas = [item for item in self.logined_datas 
                                 if item['session_id'] != session_id]
            if len(self.logined_datas) < initial_count:
                print(f"[Auth] Removed login record for session_id: {session_id}")
    
    def query_logined_user(self, session_id):
        """根据session_id查询登录用户信息"""
        with self.logined_lock:
            for item in self.logined_datas:
                if item['session_id'] == session_id:
                    return item
            return None

    def get_all_logined_users(self):
        """获取所有登录用户数据"""
        with self.logined_lock:
            return self.logined_datas.copy()  # 返回副本避免直接操作原始数据

    def auto_remove_timeout_user(self):
        """自动移除超时登录用户"""
        if not self.logined_datas:
            return
        
        current_time = time.time()
        removed_count = 0
        # 将超时时间转换为浮点数
        try:
            timeout_minutes = float(self.logined_timeout)  # 关键修复
        except ValueError:
            timeout_minutes = 5.0  # 默认值
            self.log(f"超时时间转换失败: {self.logined_timeout}, 使用默认值5分钟")

        with self.logined_lock:
            # 创建新列表存储未超时用户
            valid_users = []
            
            for user in self.logined_datas:
                try:
                    # 转换登录时间为时间戳
                    login_timestamp = time.mktime(
                        time.strptime(user['login_time'], "%Y-%m-%d %H:%M:%S")
                    )
                    # 计算分钟级时间差
                    time_diff_minutes = (current_time - login_timestamp) / 60
                    
                    if time_diff_minutes > timeout_minutes:
                        # 从有效会话中移除
                        if user['session_id'] in self.valid_sessions:
                            self.valid_sessions.remove(user['session_id'])
                        removed_count += 1
                    else:
                        valid_users.append(user)
                except Exception as e:
                    print(f"处理用户记录出错: {user} - {str(e)}")
                    valid_users.append(user)  # 出错时保留记录
            
            self.logined_datas = valid_users
        
        if removed_count > 0:
            self.log(f"自动清理超时用户: 移除 {removed_count} 个会话")
    def timeout_check_task(self):
        while self.running:
            self.auto_remove_timeout_user()
            time.sleep(60)  # 每分钟检查一次

    def remove_session(self, session_id):
        """强制下线指定用户"""
        with self.logined_lock:
            # 从登录记录中移除
            initial_count = len(self.logined_datas)
            self.logined_datas = [item for item in self.logined_datas 
                                 if item['session_id'] != session_id]
            
            # 从有效会话中移除
            if session_id in self.valid_sessions:
                self.valid_sessions.remove(session_id)
                
            if len(self.logined_datas) < initial_count:
                print(f"[Auth] 强制下线用户 session_id: {session_id}")
                return True
        return False

    def interface_cmd_task(self):#接口命令处理，用于未启动界面，在cmd模式下的参数设置
        while True:
            print("-----------------------------------------------")
            print("0. 查看服务运行状态")
            print("1. 启动服务")
            print("2. 停止服务")
            print("3. 重启服务")
            print("4. 更改用户名和密码")
            print("5. 添加虚拟目录")
            print("6. 删除虚拟目录")
            print("7. 退出程序")
            print("-----------------------------------------------")
            
            choice = input("请选择操作 (0-7,回车重新显示菜单): ").strip()
            if choice == '0':  # 查看服务运行状态
                status = "运行中" if self.running else "已停止"
                print(f"\n服务器状态: {status}")
                print(f"监听地址: {self.listen_address}")
                print(f"监听端口: {self.listen_port}")
                print(f"根目录: {self.get_root_directory()}")
                print(f"虚拟目录数量: {len(self.virtual_directories) - 1}")  # 减去根目录
                print(f"鉴权状态: {'启用' if self.enable_authentication else '禁用'}")
                print(f"登录超时: {self.logined_timeout} 分钟")
            elif choice == '1':  # 启动服务
                if self.running:
                    print("服务器已在运行中")
                else:
                    self.start()
                    print("服务器已启动")
                    
            elif choice == '2':  # 停止服务
                if self.running:
                    self.stop()
                    print("服务器已停止")
                else:
                    print("服务器未运行")
                    
            elif choice == '3':  # 重启服务
                if self.running:
                    self.restart()
                    print("服务器已重启")
                else:
                    print("服务器未运行，无法重启")
                    
            elif choice == '4':  # 更改用户名和密码
                username = input(f"请输入新用户名(当前用户名：{self.auth_username}): ").strip()
                password = input("请输入新密码: ").strip()
                
                if not username:
                    username=self.auth_username
                
                if not password:
                    print("密码不能为空")
                else:
                    self.set_auth_credentials(username, password)
                    print(f"用户名和密码已更新为: {username}:{password}")
            elif choice == '5':  # 添加虚拟目录
                virtual_path = input("请输入虚拟路径 (例如: /docs;输入0返回上级菜单): ").strip()
                if virtual_path == '0':
                    continue                
                if not virtual_path:
                    print("虚拟路径不能为空")
                    continue
                    
                if not virtual_path.startswith('/'):
                    virtual_path = '/' + virtual_path
                    
                if virtual_path == '/':
                    print("根目录已存在，不能添加")
                    continue
                    
                physical_path = input("请输入物理路径 (绝对路径): ").strip()
                if not physical_path:
                    print("物理路径不能为空")
                    continue
                    
                if not os.path.exists(physical_path):
                    print(f"物理路径不存在: {physical_path}")
                    continue
                    
                allow_anonymous = input("允许匿名访问? (y/n): ").strip().lower() == 'y'
                self.add_virtual_directory(virtual_path, os.path.abspath(physical_path), allow_anonymous)
                print(f"已添加虚拟目录: {virtual_path} -> {physical_path} (匿名访问: {'是' if allow_anonymous else '否'})")
                
            elif choice == '6':  # 删除虚拟目录
                if not self.virtual_directories:
                    print("没有可删除的虚拟目录")
                    continue
                    
                print("\n当前虚拟目录列表:")
                print("0. 取消,返回上级菜单")
                for i, (vpath, info) in enumerate(self.virtual_directories.items()):
                    if vpath == '/':  # 跳过根目录
                        continue
                    print(f"{i}. {vpath} -> {info['physical_path']}")
                    
                try:
                    index = int(input("请输入要删除的目录编号: ").strip())
                    vpaths = [p for p in self.virtual_directories.keys() if p != '/']
                    if index == 0:
                        continue
                    if 0 <= index < len(vpaths):
                        vpath = vpaths[index]
                        self.remove_virtual_directory(vpath)
                        print(f"已删除虚拟目录: {vpath}")
                    else:
                        print("无效的目录编号")
                except ValueError:
                    print("请输入有效的数字")
                    
            elif choice == '7':  # 退出程序
                if self.running:
                    self.stop()
                print("程序已退出,ctrl+c退出python进程")
                sys.exit(0)
                
            else:
                print("无效的选择，请输入 0-7 之间的数字")    
    def restart(self):
        """Safely restart the server"""
        if self.running:
            self.log("正在重启服务器...")
            self.stop()
            # Wait for server to fully stop before restarting
            time.sleep(0.5)  # Brief pause to ensure clean shutdown
        self.start()
    def start(self):
        if self.running:
            self.log("服务器已在运行中")
            return
        print("服务器启动中...")
        # 定义基础处理器
        class BaseHandler(FileServerHandler):
            pass
        
        # 将鉴权中间件包裹在 Handler 上
        handler_class = BaseHandler
        #if self.enable_authentication:
            #print(f"[Auth] Enabling authentication with user: {self.auth_username}")
            #handler_class = AuthMiddleware(handler_class, enabled=True, username="admin", password="admin123456")
        #    handler_class = AuthMiddleware(handler_class, auth_enabled=True, server_instance=self)
        #else:
        #    print("[Auth] Disabling authentication")
        #    handler_class = AuthMiddleware(handler_class, auth_enabled=False)

        #print(f"[Auth] start self.virtual_directories:{self.virtual_directories}")
        # 构造带参数的 handler 工厂函数
        #
        #                       in_virtual_dirs=self.virtual_directories,
        #                       server_info={'address': self.listen_address, 'port': self.listen_port, 'auth_enabled': self.enable_authentication},
        #                       log_callback=self.log_callback

        def handler_factory(*args, **kwargs):
            return handler_class(*args,server_instance=self)

        try:
            class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
                daemon_threads = True  # 设置守护线程
                max_threads = 100      # 设置最大线程数
                
            self.server = ThreadedHTTPServer((self.listen_address, self.listen_port), handler_factory)
            self.running = True
            self.log(f"服务器启动(多线程模式): http://{self.listen_address}:{self.listen_port}")
            self.log(f"根目录: {self.root_directory}")

            # 启动服务器线程
            server_thread = threading.Thread(target=self.server.serve_forever)
            check_timeout_thread = threading.Thread(target=self.timeout_check_task, daemon=True)


            server_thread.daemon = True
            server_thread.start()

            check_timeout_thread.start()
            
            if(self.run_interface_cmd_thread):
                interface_cmd_thread = threading.Thread(target=self.interface_cmd_task, daemon=True)
                interface_cmd_thread.start() #无窗口模式下的参数设置窗口


            print("服务器启动完成，运行中...")
        except Exception as e:
            self.log(f"启动服务器出错: {str(e)}")
            self.running = False

    def stop(self):
        if self.running and self.server:
            self.server.shutdown()
            self.server.server_close()
            self.running = False
            print("服务器已停止")
            self.log("服务器已停止")


#此文件脱离界面也可以独立运行
if __name__ == "__main__":
    server = FileServer()
    server.set_root_directory(os.getcwd())
    server.set_log_callback(print)
    server.log("启动file_server服务器")
    server.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()