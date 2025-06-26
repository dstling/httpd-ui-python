# auth_middleware.py

import base64
from http.server import BaseHTTPRequestHandler
import os
import urllib.parse
import threading

class AuthMiddleware:
    def __init__(self, handler_class, auth_enabled=False, server_instance=None):
        """
        初始化鉴权中间件
        
        :param log_callback: log日志输出
        :param handler_class: 原始请求处理器类
        :param auth_enabled: 是否启用鉴权
        :param username: 认证用户名
        :param password: 认证密码
        """

        self.handler_class = handler_class
        self.auth_enabled = auth_enabled
        self.server_instance = server_instance  # 保存上级实例 

        # 从服务器实例获取凭据
        if server_instance:
            self.username = server_instance.auth_username
            self.password = server_instance.auth_password
            self.log_callback = server_instance.log_callback
        else:
            # 默认值（仅用于测试）
            self.log_callback=None
            print("[Auth] bug!!! Using default credentials")

        self.cookie_name = 'sessionid'
        self.valid_sessions = set()  # 模拟的会话存储
        self.session_lock = threading.Lock()  # 添加线程锁
    def log(self, message):
        if self.log_callback:
            self.log_callback(message)
        else:
            print("file_server.py self.log_callback=none")

    def __call__(self, *args, **kwargs):
        class AuthRequestHandler(self.handler_class):
            def do_GET(inner_self):
                try:
                    print(f"[DEBUG] do_GET() called from AuthMiddleware, now req path is: {inner_self.path}")
                    
                    # 处理退出登录请求（不要求认证）
                    if inner_self.path.startswith('/logout'):
                        print("[Auth] Handling logout request")
                        inner_self.handle_logout()
                        return
                        
                    # 处理登录页面请求
                    if inner_self.path == '/login' and self.auth_enabled:
                        print("[Auth] Serving login page")
                        inner_self.serve_login_page()
                        return
                        
                    # 处理认证请求
                    if self.auth_enabled:
                        # 检查当前路径是否允许匿名访问
                        if inner_self.is_path_allow_anonymous(inner_self.path):
                            print(f"[Auth] Path {inner_self.path} allows anonymous access, skipping auth check")
                            # 允许匿名访问，继续处理请求
                        else:
                            # 检查认证状态
                            if not inner_self.check_auth():
                                # 未认证则重定向到登录页面
                                print("[Auth] User not authenticated, redirecting to login")
                                inner_self.send_response(302)
                                inner_self.send_header('Location', '/login')
                                inner_self.end_headers()
                                return

                    # 处理其他GET请求
                    print("[DEBUG] do_GET() called from AuthMiddleware, now to super().do_GET()")
                    super().do_GET()

                except Exception as e:
                    print(f"[ERROR] GET {inner_self.path}: {str(e)}")
                    inner_self.send_error(500, f"Internal server error: {str(e)}")   
            
            def handle_upload(self):
                """专门处理上传请求"""
                print("[UPLOAD] Handling file upload request")
                try:
                    # 调用上传处理器
                    from upload import FileUploadHandler
                    FileUploadHandler.do_POST(self)
                except Exception as e:
                    error_msg = f"Upload processing failed: {str(e)}"
                    print(f"[UPLOAD ERROR] {error_msg}")
                    self.send_error(500, error_msg)
            def do_POST(inner_self):
                try:
                    print(f"[DEBUG] do_POST() called from AuthMiddleware, path: {inner_self.path}")
                    
                    # 处理登录表单提交
                    if inner_self.path == '/login' and self.auth_enabled:
                        print("[Auth] Handling login POST request")
                        inner_self.handle_login()
                        return
                    
                    # 处理上传请求 添加 /upload 处理
                    if inner_self.path == '/upload' :
                        print("[Auth] Handling upload POST request")
                        # 检查用户认证状态
                        if self.auth_enabled and not inner_self.check_auth():
                            inner_self.send_login_redirect()
                            return
                        # 调用上传处理器
                        inner_self.handle_upload()
                        return        
                                    
                    # 处理认证请求
                    if self.auth_enabled:
                        # 检查认证状态
                        if not inner_self.check_auth():
                            inner_self.send_response(302)
                            inner_self.send_header('Location', '/login')
                            inner_self.end_headers()
                            return
         
                    # 处理其他POST请求
                    super().do_POST()
                except Exception as e:
                    print(f"[ERROR] POST {inner_self.path}: {str(e)}")
                    inner_self.send_error(500, f"Internal server error: {str(e)}")
            def is_path_allow_anonymous(inner_self, path):
                """检查路径是否允许匿名访问"""
                # 通过中间件实例获取虚拟目录配置
                if not self.server_instance:
                    print("[Auth] Warning: server_instance not available, default to not allow anonymous")
                    return False
                
                # 获取虚拟目录配置
                virtual_dirs = self.server_instance.virtual_dirs_chan if hasattr(self.server_instance, 'virtual_dirs_chan') else {}
                if not virtual_dirs:
                    return False
                
                # 解析路径
                parsed_path = urllib.parse.urlparse(path)
                path = parsed_path.path
                path = urllib.parse.unquote(path)
                
                # 检查是否匹配虚拟目录
                for virtual_path, dir_info in sorted(virtual_dirs.items(), key=lambda x: -len(x[0])):
                    # 确保虚拟路径以斜杠开头
                    if not virtual_path.startswith('/'):
                        virtual_path = '/' + virtual_path
                    if path.startswith(virtual_path):
                        return dir_info.get('allow_anonymous', False)
                
                # 检查根目录配置
                root_info = virtual_dirs.get('/', {})
                return root_info.get('allow_anonymous', False)
            def check_auth(inner_self):
                """检查用户是否已认证"""
                cookie_header = inner_self.headers.get('Cookie')
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(';'):
                        item = item.strip()
                        if '=' in item:
                            key, value = item.split('=', 1)
                            cookies[key] = value

                session_id = cookies.get(self.cookie_name)
                #print(f"[Auth] Cookies: {cookies}")
                # 使用线程锁确保会话检查的原子性
                with self.session_lock:
                    if session_id and session_id in self.valid_sessions:
                        print(f"[Auth] Session valid: {session_id}")
                        return True

                print("[Auth] Auth failed")
                return False
            
            def serve_login_page(inner_self):
                try:
                    #server_address = inner_self.server_info.get('address', '0.0.0.0')
                    #server_port = inner_self.server_info.get('port', 8000)
                    #server_url = f"http://{server_address}:{server_port}"

                    host_header = inner_self.headers.get('Host', '')
                    if host_header:
                        server_url = f"http://{host_header}"
                    else:
                        server_address = inner_self.server_info.get('address', '0.0.0.0')
                        server_port = inner_self.server_info.get('port', 8000)
                        server_url = f"http://{server_address}:{server_port}"                    
                    
                    print(f"[Auth] serve_login_page:Serving login page for {server_url}")
                    login_page = f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta charset="utf-8">
                        <title>登录</title>
                        <style>
                            body {{ 
                                font-family: Arial, sans-serif; 
                                background-color: #f5f5f5; 
                                margin: 0; 
                                padding: 20px; 
                            }}
                            .login-container {{ 
                                max-width: 400px; 
                                margin: 50px auto; 
                                padding: 30px; 
                                background: white; 
                                border-radius: 8px; 
                                box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
                            }}
                            h2 {{ 
                                text-align: center; 
                                color: #333; 
                                margin-top: 0; 
                            }}
                            .form-group {{ 
                                margin-bottom: 20px; 
                            }}
                            label {{ 
                                display: block; 
                                margin-bottom: 8px; 
                                font-weight: bold; 
                                color: #555; 
                            }}
                            input[type="text"], 
                            input[type="password"] {{ 
                                width: 100%; 
                                padding: 12px; 
                                border: 1px solid #ddd; 
                                border-radius: 4px; 
                                font-size: 16px; 
                                box-sizing: border-box; 
                            }}
                            button {{ 
                                width: 100%; 
                                padding: 12px; 
                                background-color: #007bff; 
                                color: white; 
                                border: none; 
                                border-radius: 4px; 
                                cursor: pointer; 
                                font-size: 16px; 
                                transition: background-color 0.3s; 
                            }}
                            button:hover {{ 
                                background-color: #0056b3; 
                            }}
                            .error {{ 
                                color: #d9534f; 
                                text-align: center; 
                                margin-top: 15px; 
                                font-weight: bold; 
                            }}
                            .server-info {{ 
                                text-align: center; 
                                margin-bottom: 20px; 
                                color: #666; 
                            }}
                            .debug-info {{ 
                                font-size: 12px; 
                                color: #999; 
                                margin-top: 20px; 
                                text-align: center; 
                            }}
                        </style>
                        <script>
                            // 更健壮的验证函数
                            function validateForm() {{
                                try {{
                                    const username = document.getElementById('username').value.trim();
                                    const password = document.getElementById('password').value.trim();
                                    
                                    if (!username) {{
                                        alert('请输入用户名');
                                        return false;
                                    }}
                                    if (!password) {{
                                        alert('请输入密码');
                                        return false;
                                    }}
                                    return true;
                                }} catch (e) {{
                                    console.error('验证错误:', e);
                                    alert('表单验证出错，请检查控制台');
                                    return false;
                                }}
                            }}
                        </script>
                    </head>
                    <body>
                        <div class="login-container">
                            <div class="server-info">文件服务器登录</div>
                            <h2>用户登录</h2>
                            <form action="/login" method="post" enctype="application/x-www-form-urlencoded" onsubmit="return validateForm()">
                                <div class="form-group">
                                    <label for="username">用户名:</label>
                                    <input type="text" id="username" name="username" required autofocus>
                                </div>
                                <div class="form-group">
                                    <label for="password">密码:</label>
                                    <input type="password" id="password" name="password" required>
                                </div>
                                <button type="submit">登录</button>
                            </form>
                            <div class="debug-info">
                                服务器: {server_url}<br>
                                路径: {inner_self.path}
                            </div>
                        </div>
                        
                        <script>
                            // 添加额外的调试信息
                            document.addEventListener('DOMContentLoaded', function() {{
                                console.log('DOM 加载完成');
                                document.querySelector('form').addEventListener('submit', function(e) {{
                                    console.log('表单提交事件触发');
                                }});
                            }});
                        </script>
                    </body>
                    </html>
                    """
                    
                    inner_self.send_response(200)
                    inner_self.send_header("Content-type", "text/html; charset=utf-8")

                    inner_self.send_header("Connection", "close") #好像只加这句就不需要二次或者多次点击登录，就能快速的登录上，
                    inner_self.send_header("Vary", "Accept-Encoding")
                    inner_self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                    inner_self.send_header("Pragma", "no-cache")
                    inner_self.send_header("Expires", "0")

                    inner_self.end_headers()

                    inner_self.wfile.write(login_page.encode('utf-8'))   
                except ConnectionAbortedError:
                    print("[WARN] Client aborted connection during login page load")     
            def handle_login(inner_self):
                """处理登录表单提交"""
                try:
                    #print("[Auth] Handling login request")
                    # 获取内容长度
                    content_length = int(inner_self.headers.get('Content-Length', 0))
                    print(f"[Auth] Content-Length: {content_length}")
                    
                    # 读取请求体
                    post_data = inner_self.rfile.read(content_length)
                    #print(f"[Auth] Raw POST data: {post_data.decode()}")
                    #post_data应该输出:[Auth] Raw POST data: username=xxxx&password=xxx

                    # 解析表单数据用户名密码
                    params = urllib.parse.parse_qs(post_data.decode('utf-8'))
                    username = params.get('username', [''])[0]
                    password = params.get('password', [''])[0]
                    #print(f"[Auth] Login attempt - Username: {username}, Password: {password}")

                    #if username == self.username and password == self.password:
                    # 使用文件服务器的验证方法检查密码hash
                    if (self.server_instance._verify_username_password(username,password)):
                        # 验证成功，创建新会话
                        session_id = os.urandom(16).hex()
                        with self.session_lock:
                            self.valid_sessions.add(session_id)
                        
                        # 设置 Cookie 并重定向到首页 发送给客户端浏览器
                        inner_self.send_response(302)
                        inner_self.send_header('Location', '/')
                        inner_self.send_header('Set-Cookie', f'{self.cookie_name}={session_id}; Path=/; HttpOnly; SameSite=Lax')
                        # 添加 Connection: close 头部
                        inner_self.send_header('Connection', 'close')
                        inner_self.end_headers()
                        
                        print(f"[Auth] Login successful, session created: {session_id}")
                        self.log(f"用户认证成功，用户名{username},session:{session_id}")
                        return  # 发送响应后直接返回
                    else:
                        print(f"[Auth] Login failed, invalid credentials")
                        self.log(f"用户认证失败，登录用户名{username}")

                        # 登录失败，显示错误信息
                        error_page = """
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <meta charset="utf-8">
                            <title>登录失败</title>
                            <style>
                                body { font-family: Arial, sans-serif; background-color: #f5ff5; margin: 0; padding: 20px; }
                                .error-container { max-width: 400px; margin: 50px auto; padding: 30px; background: white; 
                                                 border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
                                h2 { color: #d9534f; margin-top: 0; }
                                p { margin: 15px 0; }
                                a { color: #007bff; text-decoration: none; }
                                a:hover { text-decoration: underline; }
                            </style>
                        </head>
                        <body>
                            <div class="error-container">
                                <h2>登录失败</h2>
                                <p>用户名或密码不正确</p>
                                <p><a href="/login">重新登录</a></p>
                            </div>
                        </body>
                        </html>
                        """
                        
                        inner_self.send_response(200)
                        inner_self.send_header("Content-type", "text/html; charset=utf-8")

                        inner_self.send_header("Connection", "close")
                        inner_self.send_header("Vary", "Accept-Encoding")
                        inner_self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                        inner_self.send_header("Pragma", "no-cache")
                        inner_self.send_header("Expires", "0")


                        inner_self.end_headers()
                        inner_self.wfile.write(error_page.encode('utf-8'))
                        print(f"[Auth] Login failed for username: {username}")
                except Exception as e:
                    print(f"[ERROR] handle_login: {str(e)}")
                    inner_self.send_error(500, f"Internal server error: {str(e)}")

            def handle_logout(inner_self):
                print("[Auth] Handling logout")
                
                # 获取当前会话 ID 并从有效会话中移除
                cookie_header = inner_self.headers.get('Cookie')
                if cookie_header:
                    cookies = {}
                    for item in cookie_header.split(';'):
                        item = item.strip()
                        if '=' in item:
                            key, value = item.split('=', 1)
                            cookies[key] = value
                    
                    session_id = cookies.get(self.cookie_name)
                    # 使用线程锁确保会话移除的原子性
                    with self.session_lock:                    
                        if session_id and session_id in self.valid_sessions:
                            self.valid_sessions.remove(session_id)
                            print(f"[Auth] Removed session: {session_id}")
                            #self.log(f"用户{inner_self.username}退出登录,Removed session: {session_id}")
                            self.log(f"用户退出登录,Removed session: {session_id}")
                
                # 发送重定向到登录页面
                inner_self.send_response(302)
                inner_self.send_header('Location', '/login')
                
                # 确保清除 Cookie
                inner_self.send_header('Set-Cookie',f'{self.cookie_name}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly')
                
                inner_self.end_headers()

            def send_error(self, code, message):
                try:
                    # Force UTF-8 encoding for error messages
                    self.send_response(code)
                    self.send_header("Content-type", "text/html; charset=utf-8")
                    self.end_headers()
                    error_content = f"<html><body><h1>Error {code}</h1><p>{message}</p></body></html>"
                    self.wfile.write(error_content.encode('utf-8'))
                except Exception:
                    # Fallback if UTF-8 fails
                    super().send_error(code, "Internal Server Error")

        return AuthRequestHandler(*args, **kwargs)