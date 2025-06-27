import os
import urllib.parse
import time
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler

class FileServerHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    
    # 登录状态管理
    is_logged_in = False
    #login_lock = threading.Lock()# 添加线程锁

    def __init__(self, *args, server_instance=None, **kwargs):#in_virtual_dirs=None, server_info=None, log_callback=None,
        self.server_instance = server_instance  # 保存上级实例 
        
        # 从服务器实例获取凭据
        if server_instance:
            self.server_name = server_instance.server_name
            self.server_version = server_instance.server_version
            self.server_by = server_instance.server_by

            self.username = server_instance.auth_username
            self.password = server_instance.auth_password
            self.log_callback = server_instance.log_callback
            self.virtual_dirs_chan = server_instance.virtual_directories   #in_virtual_dirs or {}
            #self.server_info = server_info or {}
            self.server_address = server_instance.listen_address
            self.server_port = server_instance.listen_port
        else:
            # 默认值（仅用于测试）
            self.log_callback=None
            print("[Auth] bug!!! Using default credentials")

        self.cookie_name = 'sessionid'
        self.valid_sessions = server_instance.valid_sessions#set()  # 模拟的会话存储
        self.session_lock = threading.Lock()  # 添加线程锁


        # 直接从虚拟目录字典中获取根目录信息
        root_info = self.virtual_dirs_chan.get('/', {})
        self.base_directory = root_info.get('physical_path', os.getcwd())
        print(f"[DEBUG] Base directory: {self.base_directory}")

        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        """自定义日志输出"""
        if self.log_callback:
            self.log_callback(f"{self.address_string()}:{self.client_address[1]}- {format % args}")
        else:
            super().log_message(format, *args)
    
    def check_login(self):
        """检查用户是否已认证"""
        cookie_header = self.headers.get('Cookie')
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

        print("[DEBUG] Check_login failed")
        return False

    def handle_login(self):
        """处理登录表单提交"""
        try:
            #print("[Auth] Handling login request")
            # 获取内容长度
            content_length = int(self.headers.get('Content-Length', 0))
            print(f"[Auth] Content-Length: {content_length}")
            
            # 读取请求体
            post_data = self.rfile.read(content_length)
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
                self.send_response(302)
                self.send_header('Location', '/')
                self.send_header('Set-Cookie', f'{self.cookie_name}={session_id}; Path=/; HttpOnly; SameSite=Lax')
                # 添加 Connection: close 头部
                self.send_header('Connection', 'close')
                self.end_headers()
                
                print(f"[Auth] Login successful, session created: {session_id}")
                self.log_message(f"用户认证成功，用户名{username},session:{session_id}")
                return  # 发送响应后直接返回
            else:
                print(f"[Auth] Login failed, invalid credentials")
                self.log_message(f"用户认证失败，登录用户名{username}")

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
                
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")

                self.send_header("Connection", "close")
                self.send_header("Vary", "Accept-Encoding")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")


                self.end_headers()
                self.wfile.write(error_page.encode('utf-8'))
                print(f"[Auth] Login failed for username: {username}")
        except Exception as e:
            print(f"[ERROR] handle_login: {str(e)}")
            self.send_error(500, f"Internal server error: {str(e)}")

    def handle_logout(self):
        print("[DEBUG] handle_logout logout")
        
        # 获取当前会话 ID 并从有效会话中移除
        cookie_header = self.headers.get('Cookie')
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
                    #self.log(f"用户{self.username}退出登录,Removed session: {session_id}")
                    self.log_message(f"用户退出登录,Removed session: {session_id}")
        
        # 发送重定向到登录页面
        self.send_response(302)
        self.send_header('Location', '/')
        # 确保清除 Cookie
        self.send_header('Set-Cookie',f'{self.cookie_name}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly')
        self.end_headers()

    def serve_login_page(self):
        try:
            host_header = self.headers.get('Host', '')
            if host_header:
                server_url = f"http://{host_header}"
            else:
                server_address = self.server_address #inner_self.server_info.get('address', '0.0.0.0')
                server_port = self.server_port #inner_self.server_info.get('port', 8000)
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
                        路径: {self.path}
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
            
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")

            self.send_header("Connection", "close") #好像只加这句就不需要二次或者多次点击登录，就能快速的登录上，
            self.send_header("Vary", "Accept-Encoding")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")

            self.end_headers()

            self.wfile.write(login_page.encode('utf-8'))   
        except ConnectionAbortedError:
            print("[WARN] Client aborted connection during login page load")  

    def send_login_redirect(self):
        # 未认证则重定向到登录页面
        print("[Auth] redirecting to login")
        self.send_response(302)
        self.send_header('Location', '/login')
        self.end_headers()
        return
    # 添加进度报告方法（与类名一致）
    def _report_progress(self, current, total):
        """报告上传进度"""
        percent = int((current / total) * 100)
        print(f"[UPLOAD PROGRESS] {percent}%")
        return percent
    def handle_upload(self):
        """专门处理上传请求"""
        print("[UPLOAD] Handling file upload request")
        try:
            # 创建 FileUploadHandler 实例并调用其 do_POST 方法
            # 调用上传处理器
            from upload import FileUploadHandler
            FileUploadHandler.do_POST(self)
        except Exception as e:
            # 捕获特定异常
            if isinstance(e, (ConnectionAbortedError, ConnectionResetError)):
                print(f"[UPLOAD] Client disconnected: {str(e)}")
            else:
                error_msg = f"Upload processing failed: {str(e)}"
                print(f"[UPLOAD ERROR] {error_msg}")
            
            # 发送纯英文错误消息避免编码问题
            self.send_error(500, "Internal server error during upload")

    def do_POST(self):
        try:
            if self.path == '/login':
                print("[do_POST] Handling login POST request")
                self.handle_login()
                return

            # 处理上传请求 添加 /upload 处理
            if self.path == '/upload' :
                print("[do_POST] Handling upload POST request")
                # 检查用户认证状态
                if not self.check_login():
                    self.send_login_redirect()
                    return
                # 调用上传处理器
                self.handle_upload()
                return    
                
            # 处理其他POST请求（如上传）
            super().do_POST()
            
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")
    def do_GET(self):
        try:
            print(f"[DEBUG] do_GET() called, Req Path: {self.path}")

            if self.path == '/favicon.ico':
                self.serve_default_favicon()
                return

            # 处理特殊路径
            if self.path == '/login':
                self.serve_login_page()
                return
                
            if self.path == '/logout':
                self.handle_logout()
                #self.send_response(302)
                #self.send_header('Location', '/')
                #self.end_headers()
                return

            # 解析请求路径转化为实际路径
            physical_path = self.translate_path(self.path)

            # 验证路径在允许的目录内
            if not self.is_valid_path(physical_path):
                self.send_error(403, "Access denied: Invalid path")
                return

            # 检查是否存在
            if not os.path.exists(physical_path):
                self.send_error(404, "File not found")
                return

            physical_path = os.path.normpath(physical_path) 
            #virt_dir='/'.join(physical_path.split('/', 2)[:2])
            #print(f"[DEBUG] virt_dir:{virt_dir}")
            physical_path_dir=physical_path
            # 处理目录或文件 有可能是文件
            if os.path.isfile(physical_path):
                physical_path_dir=os.path.dirname(physical_path) #截取目录，需要对目录是否允许匿名访问单独判断

            print(f"[DEBUG] physical_path:{physical_path}, physical_path_dir:{physical_path_dir}")
                
            if os.path.isdir(physical_path_dir):
                allow_anonymous = self.get_path_allow_anonymous(self.path)
                #print(f"[GET] Client req Listing directory: {physical_path} allow_anonymous:{allow_anonymous}")
                
                if self.check_login():#登录了，直接该干啥干啥
                    print("[GET] Client check_login true")
                    self.serve_dir_file(physical_path)
                else:  #匿名访问
                    print(f"[GET] Client anonymous request:{self.path}")
                    # 显示仅允许匿名访问的页面
                    if(self.path == '/'):#显示匿名主页
                        self.show_anonymous_only_page()
                        return
                    if(not self.path == '/' and allow_anonymous):#允许匿名访问的页面
                        self.serve_dir_file(physical_path)
                    else:#非法访问 登录
                        print(f"[DEBUG] 路径:{physical_path} 匿名访问无权限，需要登录")
                        self.send_login_redirect()
            else :
                print("[DEBUG] Bug,this is file??")
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")

    def serve_default_favicon(self):
        """返回默认的favicon图标"""
        try:
            favicon = (
                b'\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x08\x00h\x05\x00\x00'
                b'\x16\x00\x00\x00(\x00\x00\x00\x10\x00\x00\x00 \x00\x00\x00\x01\x00'
                b'\x08\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x01\x00\x00\x00\x01') + b'\x00'*1072
            
            self.send_response(200)
            self.send_header("Content-type", "image/x-icon")
            self.send_header("Content-Length", str(len(favicon)))
            self.end_headers()
            self.wfile.write(favicon)
        except Exception as e:
            self.send_error(500, f"Error serving favicon: {str(e)}")
    
    def is_valid_path(self, path):
        """检查路径是否在允许的目录内（基础目录或虚拟目录）"""
        abs_path = os.path.abspath(path)
        allowed_paths = []
        
        # 添加基础目录
        allowed_paths.append(os.path.abspath(self.base_directory))
        
        # 添加虚拟目录的物理路径
        for dir_info in self.virtual_dirs_chan.values():
            physical_path = dir_info.get('physical_path', '')
            if physical_path:
                allowed_paths.append(os.path.abspath(physical_path))
        
        # 检查路径是否在任何允许的目录内
        for allowed_path in allowed_paths:
            if abs_path.startswith(allowed_path):
                return True
        return False
    
    def translate_path(self, path):
        """将URL路径转换为文件系统路径，支持虚拟目录"""
        parsed_path = urllib.parse.urlparse(path)
        path = parsed_path.path
        path = urllib.parse.unquote(path)
        
        for virtual_path, dir_info in sorted(self.virtual_dirs_chan.items(), key=lambda x: -len(x[0])):
            if not virtual_path.startswith('/'):
                virtual_path = '/' + virtual_path
                
            if path.startswith(virtual_path):
                physical_path = dir_info.get('physical_path', '')
                rel_path = path[len(virtual_path):]
                full_path = os.path.join(physical_path, rel_path.lstrip('/'))
                print(f"[DEBUG] Translated path: {path} to {full_path}")
                return os.path.normpath(full_path)
        return None
    
    def get_path_allow_anonymous(self, path):
        """检查路径是否允许匿名访问"""
        parsed_path = urllib.parse.urlparse(path)
        path = parsed_path.path
        path = urllib.parse.unquote(path)
        #print(f"[DEBUG] get_path_allow_anonymous path:{path}")
        
        for virtual_path, dir_info in sorted(self.virtual_dirs_chan.items(), key=lambda x: -len(x[0])):
            if not virtual_path.startswith('/'):
                virtual_path = '/' + virtual_path
            #print(f"[DEBUG] get_path_allow_anonymous dir_info:{dir_info} virtual_path:{virtual_path}")    
            if path.startswith(virtual_path):
                return dir_info.get('allow_anonymous', False)
        return False
    
    def show_anonymous_only_page(self):
        """显示仅包含允许匿名访问的目录页面"""
        try:
            server_address = self.server_address #inner_self.server_info.get('address', '0.0.0.0')
            server_port = self.server_port #inner_self.server_info.get('port', 8000)
            server_url = f"http://{server_address}:{server_port}"                    
            
            title = f"{self.server_name}-{self.server_version} 访问受限 - 仅显示公开目录 --by {self.server_by}"
            content = [
                '<!DOCTYPE html>',
                '<html><head>',
                f'<title>{title}</title>',
                '<meta charset="utf-8">',
                '<style>',
                'body { font-family: Arial, sans-serif; margin: 40px; }',
                '.container { max-width: 800px; margin: 0 auto; }',
                '.message { background-color: #ffebee; padding: 20px; border-radius: 5px; }',
                '.power-by { background-color: #faebee; padding: 10px; border-radius: 5px; }',
                '.bottom-st {font-size: 12px; color: #999;margin-top: 20px; text-align: center; }',
                '.directories { margin-top: 30px; }',
                'ul { list-style-type: none; padding: 0; }',
                'li { margin: 10px 0; }',
                'a { text-decoration: none; color: #1a73e8; }',
                '.login-link { display: inline-block; margin-top: 15px; padding: 8px 16px; ',
                '            background: #e3f2fd; border-radius: 4px; }',
                '</style>',
                '</head>',
                '<body>',
                '<div class="container">',
                '<h2>访问受限</h2>',
                '<div class="message">',
                '<p>当前目录需要登录权限。以下是可公开访问的目录：</p>',
                f'<a class="login-link" href="/login">登录访问更多内容</a>',
                '</div>',
                '<div class="directories">',
                '<h3>公开目录列表</h3>',
                '<ul>'
            ]
            
            # 添加允许匿名访问的虚拟目录
            for virtual_path, dir_info in self.virtual_dirs_chan.items():
                if dir_info.get('allow_anonymous', False):
                    if not virtual_path.startswith('/'):
                        virtual_path = '/' + virtual_path
                    content.append(f'<li><a href="{virtual_path}">{virtual_path}</a></li>')
            
            content.extend([
                "<br><br><br><br><br><br><br><br>"
                "<div class='bottom-st'>",
                    f"服务器: {self.server_name}<br>",
                    f"Power by: {self.server_by}",
                "</div>"
                '</ul>',
                '</div>',
                '</div>',
                '</body>',
                '</html>'
            ])
            
            response = '\n'.join(content).encode('utf-8')
            
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            
        except Exception as e:
            self.send_error(500, f"Error generating anonymous access page: {str(e)}")

    def list_directory(self, path):
        """生成目录列表页面"""
        try:
            items = []
            for name in os.listdir(path):
                full_path = os.path.join(path, name)
                is_dir = os.path.isdir(full_path)
                try:
                    size = os.path.getsize(full_path) if not is_dir else 0
                    timestamp = os.path.getctime(full_path)
                    create_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                except Exception:
                    size = 0
                    create_time = "N/A"
                items.append((name, is_dir, size, create_time))

            # 排序：文件夹在前
            items.sort(key=lambda x: (not x[1], x[0].lower()))

            server_address = self.server_address #inner_self.server_info.get('address', '0.0.0.0')
            server_port = self.server_port #inner_self.server_info.get('port', 8000)
            server_url = f"http://{server_address}:{server_port}"                    

            print(f"[GET] list_directory: Server URL: {server_url}")
            
            title = f"{self.server_name}-{self.server_version} 文件列表: {self.path}"
            #title = f"{self.server_name}-{self.server_version} 访问受限 - 仅显示公开目录 {self.server_by}"

            encoded_title = title.encode('utf-8', 'xmlcharrefreplace').decode('utf-8')

            content = [
                '<!DOCTYPE html>',
                '<html><head>',
                f'<title>{encoded_title}</title>',
                '<meta charset="utf-8">',
                '<meta name="viewport" content="width=device-width, initial-scale=1">',
                '<style>',
                '* { box-sizing: border-box; }',
                'body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;',
                '        margin: 20px; background-color: #f8f9fa; color: #333; }',
                '.container { max-width: 1200px; margin: 0 auto; background: white; ',
                '            border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 20px; }',
                'h2 { color: #333; border-bottom: 1px solid #eee; padding-bottom: 10px; }',
                'table { border-collapse: collapse; width: 100%; margin-top: 15px; }',
                'th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }',
                'th { background-color: #f1f1f1; font-weight: 600; }',
                'tr:hover { background-color: #f9f9f9; }',
                'a { text-decoration: none; color: #1a73e8; transition: color 0.2s; }',
                'a:hover { text-decoration: underline; color: #0d61bf; }',
                '.dir-link { color: #1e88e5; }',
                '.parent-link { display: inline-block; margin-bottom: 15px; padding: 6px 12px; ',
                '             background: #f1f1f1; border-radius: 4px; }',
                '.file-size { text-align: right; }',
                '.header-info { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }',
                '.server-info { font-size: 0.9em; color: #666; margin-top: 5px; }',
                '.virtual-dir { margin: 15px 0; padding: 10px; background-color: #f8f9fa; border-radius: 4px; }',
                '.virtual-dir h3 { margin-top: 0; color: #0d61bf; }',
                '.virtual-dir ul { list-style-type: none; padding: 0; margin: 0; }',
                '.virtual-dir li { margin-bottom: 8px; }',
                '.server-config { margin: 15px 0; padding: 10px; background-color: #e8f5e9; border-radius: 4px; }',
                '.server-config h3 { margin-top: 0; color: #2e7d32; }',
                '.server-config p { margin: 5px 0; }',
                '.upload-form { margin-top: 20px; }',
                '@media (max-width: 600px) { .container { padding: 10px; } th, td { padding: 8px 10px; } }',
                '</style>',
                '</head>',
                '<body>',
                '<div class="container">',
                f'<div class="header-info"><h2>{encoded_title}</h2><div class="server-info">{self.server_name}-{self.server_version}</div></div>'
            ]

            # 添加登录/退出按钮
            content.append('<div>')  
            if self.check_login():
                content.append('<a href="/logout" style="float:right;">退出登录</a>')
            else:
                content.append('<a href="/login" style="float:right;">登录</a>')
            content.append('</div>')

            # 添加服务器配置信息显示
            content.append(
                '<div class="server-config">'
                '<h3>服务器配置</h3>'
                f'<p>访问地址: <a href="{server_url}" target="_blank">{server_url}</a></p>'
                f"<p>根目录: {self.virtual_dirs_chan.get('/',{}).get('physical_path', os.getcwd())}</p>"
                '</div>'
            )

            # 添加上传表单
            current_path = self.path.rstrip('/') + '/'
            content.append('<div class="upload-container">')
            content.append('<h3>文件上传</h3>')
            content.append(f'<form class="upload-form" action="/upload" method="post" enctype="multipart/form-data">')
            content.append('<input type="hidden" name="target_path" value="' + current_path + '">')
            content.append('<input type="file" name="file">')
            content.append('<input type="submit" value="上传文件">')
            content.append('</form>')
            content.append('</div>')
            
            # 添加上传进度条和JS优化
            # file_server_handler.py 中的 list_directory 方法（替换原进度条部分）
            # 替换现有的进度条JS代码
            content.append('''
            <div id="upload-progress" style="display:none; margin-top:10px;">
                <progress id="progress-bar" value="0" max="100" style="width:100%;"></progress>
                <div id="progress-text">0%</div>
            </div>
            <script>
            document.querySelector('.upload-form').addEventListener('submit', function(e) {
                e.preventDefault(); // 阻止默认表单提交
                
                const form = this;
                const submitBtn = form.querySelector('input[type="submit"]');
                submitBtn.disabled = true;
                submitBtn.value = "上传中...";
                
                const progressDiv = document.getElementById('upload-progress');
                if (progressDiv) {
                    progressDiv.style.display = 'block';
                }
                
                const formData = new FormData(form);
                const xhr = new XMLHttpRequest();
                
                // 监听上传进度事件
                xhr.upload.addEventListener('progress', function(event) {
                    if (event.lengthComputable) {
                        const percent = Math.round((event.loaded / event.total) * 100);
                        document.getElementById('progress-bar').value = percent;
                        document.getElementById('progress-text').textContent = `${percent}%`;
                    }
                });
                
                // 请求完成处理
                xhr.addEventListener('load', function() {
                    if (xhr.status >= 200 && xhr.status < 300) {
                        // 插入服务器返回的响应内容
                        document.body.innerHTML = xhr.responseText;
                        // 执行响应中的脚本
                        const scripts = document.body.getElementsByTagName('script');
                        for (let script of scripts) {
                            eval(script.innerHTML);
                        }
                    } else {
                        alert('上传失败: ' + xhr.statusText);
                        submitBtn.disabled = false;
                        submitBtn.value = "上传文件";
                        progressDiv.style.display = 'none';
                    }
                });
                
                // 错误处理
                xhr.addEventListener('error', function() {
                    alert('网络错误，上传失败');
                    submitBtn.disabled = false;
                    submitBtn.value = "上传文件";
                    progressDiv.style.display = 'none';
                });
                
                xhr.open('POST', '/upload');
                xhr.send(formData);
            });
            </script>
            ''')
            # 添加上级目录链接
            if self.path != "/":
                parent_path = os.path.dirname(self.path.rstrip('/'))
                if not parent_path:
                    parent_path = '/'
                content.append('<div class="virtual-dir"><ul>')
                content.append(f'<a class="parent-link" href="{parent_path}">[返回上级目录]</a>')
                content.append('</ul></div>')
            # 根目录添加虚拟目录链接
            if self.path == "/":
                content.append('<div class="virtual-dir"><h3>虚拟目录</h3><ul>')

                for virtual_path, dir_info in self.virtual_dirs_chan.items():
                    physical_path = dir_info.get('physical_path', '')
                    if not virtual_path.startswith('/'):
                        virtual_path = '/' + virtual_path
                    #content.append(f'<li><a href="{virtual_path}">{virtual_path} → {physical_path}</a></li>')    
                    content.append(f'<li><a href="{virtual_path}">{virtual_path}</a></li>')    

                content.append('</ul></div>')

            # 文件表格
            content.append('<table><tr><th>名称</th><th>类型</th><th>大小</th><th>创建时间</th></tr>')

            if self.path != "/":
                content.append('<tr><td colspan="4"><a href="../">[返回上级目录]</a></td></tr>')

            for name, is_dir, size, create_time in items:
                full_url = urllib.parse.urljoin(self.path + '/', name)
                display_name = name + '/' if is_dir else name

                # 修改文件大小显示为MB单位
                if is_dir:
                    size_display = "文件夹"
                else:
                    size_mb = size / (1024 * 1024)
                    size_display = f"{size_mb:.2f} MB"

                content.append(
                    f'<tr><td><a href="{full_url}" class="{"dir-link" if is_dir else ""}">'
                    f'{display_name}</a></td><td>{"文件夹" if is_dir else "文件"}</td>'
                    f'<td class="file-size">{size_display}</td><td>{create_time}</td></tr>'
                )

            content.append('</table></div></body></html>')
            response = '\n'.join(content).encode('utf-8')

            # 发送响应
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("Connection", "close")
            self.send_header("Vary", "Accept-Encoding")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()

            try:
                self.wfile.write(response)
            except ConnectionAbortedError as e:
                print(f"[ERROR] Client disconnected: {e}")
            except BrokenPipeError as e:
                print(f"[ERROR] Broken pipe: {e}")
            except Exception as e:
                print(f"[ERROR] Response error: {e}")
                self.send_error(500, f"Internal server error: {str(e)}")

            print(f"[DEBUG] Response sent, length: {len(response)}")

        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")

    def serve_dir_file2(self, physical_path):
        """发送文件内容给客户端"""
        try:
            if os.path.isdir(physical_path): #目录
                self.list_directory(physical_path)
            else: #文件
                print(f"[GET] downloading path:{physical_path}")
                self.log_message(f"downloading path:{physical_path}")
                #nner_self.serve_file(physical_path)

                with open(physical_path, 'rb') as file:
                    file_content = file.read()

                mime_type, _ = mimetypes.guess_type(physical_path)
                if not mime_type:
                    mime_type = 'application/octet-stream'

                self.send_response(200)
                self.send_header("Content-type", mime_type)
                self.send_header("Content-Length", str(len(file_content)))
                self.end_headers()
                self.wfile.write(file_content)

        except Exception as e:
            self.send_error(500, f"Error reading file: {str(e)}")

    def serve_dir_file3(self, physical_path):
        """发送文件内容给客户端"""
        try:
            if os.path.isdir(physical_path): #目录
                self.list_directory(physical_path)
            else: #文件
                print(f"[GET] downloading path:{physical_path}")
                self.log_message(f"downloading path:{physical_path}")

                mime_type, _ = mimetypes.guess_type(physical_path)
                if not mime_type:
                    mime_type = 'application/octet-stream'

                # Linux零拷贝优化
                if os.name == 'posix':
                    file_size = os.path.getsize(physical_path)
                    self.send_response(200)
                    self.send_header("Content-type", mime_type)
                    self.send_header("Content-Length", str(file_size))
                    self.end_headers()
                    
                    with open(physical_path, 'rb') as file:
                        os.sendfile(self.wfile.fileno(), file.fileno(), 0, file_size)
                    return

                # 通用分块传输方案
                self.send_response(200)
                self.send_header("Content-type", mime_type)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()

                buffer_size = 8192*1024  # 8KB缓冲区
                with open(physical_path, 'rb') as file:
                    while True:
                        chunk = file.read(buffer_size)
                        if not chunk:
                            break
                        self.wfile.write(f"{len(chunk):X}\r\n".encode())
                        self.wfile.write(chunk)
                        self.wfile.write(b"\r\n")
                self.wfile.write(b"0\r\n\r\n")

        except Exception as e:
            self.send_error(500, f"Error reading file: {str(e)}")            

    def serve_dir_file(self, physical_path):
        """发送文件内容给客户端，支持Range请求优化多线程下载"""
        try:
            if os.path.isdir(physical_path):
                self.list_directory(physical_path)
                return
                
            
            # 获取文件信息
            file_size = os.path.getsize(physical_path)
            mime_type, _ = mimetypes.guess_type(physical_path) or 'application/octet-stream'
            print(f"[GET] downloading path:{physical_path} file_size:{file_size}")
            self.log_message(f"downloading path:{physical_path}")
            
            # 处理Range请求 (支持多线程下载)
            range_header = self.headers.get('Range')
            if range_header:
                # 解析Range头部 (示例: "bytes=0-100,200-300")
                print("[GET] Range header:", range_header)
                ranges = []
                for r in range_header.replace('bytes=', '').split(','):
                    start_end = r.split('-')
                    if len(start_end) == 2:
                        start = int(start_end[0]) if start_end[0] else 0
                        end = int(start_end[1]) if start_end[1] else file_size - 1
                        print(f"Range: {start}-{end}")
                        ranges.append((start, end))
                
                # 发送206 Partial Content响应
                self.send_response(206)
                self.send_header("Content-type", mime_type)
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Range", f"bytes {ranges[0][0]}-{ranges[0][1]}/{file_size}")
                self.send_header("Content-Length", str(ranges[0][1] - ranges[0][0] + 1))
                self.end_headers()
                
                # 只处理第一个范围（迅雷等多线程工具会发送多个独立请求）
                start, end = ranges[0]
                with open(physical_path, 'rb') as file:
                    file.seek(start)
                    remaining = end - start + 1
                    buffer_size = 1024 * 1024 *1 # 8MB缓冲区
                    
                    while remaining > 0:
                        chunk_size = min(buffer_size, remaining)
                        chunk = file.read(chunk_size)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
                    print(f"一个数据块已发送结束 start: {start} end: {end}")
                return

            # 无Range请求的完整文件处理
            # Linux零拷贝优化
            if os.name == 'posix':
                print("in linux")
                self.send_response(200)
                self.send_header("Content-type", mime_type)
                self.send_header("Content-Length", str(file_size))
                self.send_header("Accept-Ranges", "bytes")  # 声明支持Range
                self.end_headers()
                with open(physical_path, 'rb') as file:
                    os.sendfile(self.wfile.fileno(), file.fileno(), 0, file_size)
                return

            # 通用完整文件传输
            self.send_response(200)
            self.send_header("Content-type", mime_type)
            self.send_header("Content-Length", str(file_size))
            self.send_header("Accept-Ranges", "bytes")  # 声明支持Range
            self.end_headers()
            
            buffer_size = 8192 * 1024  # 8MB缓冲区
            with open(physical_path, 'rb') as file:
                while True:
                    chunk = file.read(buffer_size)
                    print(f"chunk size:", len(chunk))
                    if not chunk:
                        break
                    self.wfile.write(chunk)

        except Exception as e:
            self.send_error(500, f"Error reading file: {str(e)}")            