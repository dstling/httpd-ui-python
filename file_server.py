# file_server.py

import os
import sys
import argparse
import urllib.parse
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
        self.server_version="V15"
        self.server_by="dstling Email:xingxing5914@163.com"

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
        self.log_callback = None #日志变量

        self.default_password = "admin123456" #用于没有json文件时生成默认的hash密码
        self.auth_username = "admin"
        self.auth_password = None  #hash密码 不是密码本身
        if os.path.exists(self.config_file):
            self.load_config()
        else:
            self.save_config()

        self.root_directory = self.get_root_directory()

    def set_log_callback(self, callback):
        self.log_callback = callback

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
            'auth_password': self.auth_password
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

    def remove_virtual_directory(self, virtual_path):
        print(f"remove_virtual_directory {virtual_path}")
        if virtual_path in self.virtual_directories:
            print(f"remove_virtual_directory2 {virtual_path}")
            del self.virtual_directories[virtual_path]
            self.save_config()
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
            server_thread.daemon = True
            server_thread.start()
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