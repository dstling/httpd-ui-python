import os
import http.server
import urllib.parse
from http import HTTPStatus
import time
from email import policy
from email.parser import BytesParser

class FileUploadHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, directory=None, virtual_dirs=None, server_info=None, **kwargs):
        self.base_directory = os.path.abspath(directory) if directory else os.getcwd()
        self.virtual_directories = virtual_dirs or {}
        self.server_info = server_info or {}
        super().__init__(*args, **kwargs)

    def translate_path(self, path):
        path = urllib.parse.urlparse(path).path
        path = urllib.parse.unquote(path)
        
        for virtual_path, physical_path in sorted(self.virtual_directories.items(), key=lambda x: -len(x[0])):
            if not virtual_path.startswith('/'):
                virtual_path = '/' + virtual_path
            if path.startswith(virtual_path):
                rel_path = path[len(virtual_path):]
                full_path = os.path.join(physical_path, rel_path.lstrip('/'))
                return os.path.normpath(full_path)
                
        if path == "/":
            return self.base_directory
            
        return os.path.normpath(os.path.join(self.base_directory, path.lstrip('/')))
    
    def do_POST(self):
        self.request.settimeout(300)  # 5 minutes timeout

        print(f"[DEBUG] do_POST() called from upload.py")
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            content_type = self.headers.get('Content-Type')
            
            # 读取原始二进制数据
            post_data = self.rfile.read(content_length)
            
            # 解析消息
            msg = BytesParser(policy=policy.default).parsebytes(
                b'Content-Type: ' + content_type.encode() + b'\r\n\r\n' + post_data
            )
            
            # 获取目标路径
            target_path = '/'
            for part in msg.walk():
                cd = part.get('Content-Disposition', '')
                if 'form-data' in cd and part.get_param('name') == 'target_path':
                    target_path = part.get_content()
                    break
            
            # 准备上传目录
            upload_dir = self.translate_path(target_path)
            print(f"[UPLOAD] Target directory: {upload_dir}")
            
            # 查找文件部分
            file_item = None
            for part in msg.walk():
                cd = part.get('Content-Disposition', '')
                if 'form-data' in cd and 'filename' in cd:
                    file_item = part
                    break
            
            if file_item:
                filename = file_item.get_filename()
                if filename:
                    dest_path = os.path.join(upload_dir, os.path.basename(filename))
                    
                    # 获取二进制内容
                    file_content = file_item.get_payload(decode=True)
                    
                    start_time = time.time()
                    total_size = 0
                    chunk_size = 64 * 1024  # 64KB 分块
                    
                    # 写入文件
                    with open(dest_path, 'wb') as dest_file:
                        # 分块处理二进制数据
                        for i in range(0, len(file_content), chunk_size):
                            chunk = file_content[i:i+chunk_size]
                            dest_file.write(chunk)
                            total_size += len(chunk)
                            
                            # 计算进度
                            progress = (total_size / len(file_content)) * 100
                            elapsed = time.time() - start_time
                            speed = total_size / (1024 * 1024 * elapsed) if elapsed > 0 else 0
                            print(f"[UPLOAD PROGRESS] {filename}: {progress:.1f}% | "
                                  f"Speed: {speed:.2f} MB/s | "
                                  f"Size: {total_size/(1024*1024):.2f}/{len(file_content)/(1024*1024):.2f} MB")

                    # 成功响应 - 重定向到文件目录
                    # 计算重定向路径（当前请求路径的父目录）
                    redirect_path = target_path  #os.path.dirname(self.path)
                    if not redirect_path.endswith('/'):
                        redirect_path += '/'
                        
                    response_content = f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta charset="utf-8">
                        <script>
                            // 创建并显示自定义提示框
                            function showNotification() {{
                                const notification = document.createElement('div');
                                notification.innerHTML = `
                                    <div style="
                                        position: fixed;
                                        top: 50%;
                                        left: 50%;
                                        transform: translate(-50%, -50%);
                                        background: white;
                                        padding: 20px;
                                        border-radius: 8px;
                                        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                                        text-align: center;
                                        z-index: 10000;
                                    ">
                                        <p>文件上传成功 ({total_size/(1024*1024):.2f}MB)</p>
                                        <button onclick="closeNotification()" style="
                                            padding: 8px 16px;
                                            background: #007bff;
                                            color: white;
                                            border: none;
                                            border-radius: 4px;
                                            cursor: pointer;
                                        ">确定</button>
                                    </div>
                                `;
                                document.body.appendChild(notification);
                            }}
                            
                            function closeNotification() {{
                                document.querySelector('div[style*="position: fixed"]').remove();
                                window.location.href = '{redirect_path}';
                            }}
                            
                            // 自动重定向
                            setTimeout(() => {{
                                window.location.href = '{redirect_path}';
                            }}, 2000);  // 2秒后自动重定向
                            
                            window.onload = showNotification;
                        </script>
                    </head>
                    <body></body>
                    </html>
                    """
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-type", "text/html; charset=utf-8")

                    self.send_header("Connection", "close")
                    self.send_header("Vary", "Accept-Encoding")
                    self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                    self.send_header("Pragma", "no-cache")
                    self.send_header("Expires", "0")

                    self.end_headers()
                    self.wfile.write(response_content.encode('utf-8'))
                    print(f"[UPLOAD] File uploaded: {filename} . success. Redirecting to: {redirect_path}" )
                    return
                
            # 无文件字段处理
            self.send_error(HTTPStatus.BAD_REQUEST, "No file selected")

        except ConnectionAbortedError:
            print("[UPLOAD] Client disconnected during upload")
            return    
        except Exception as e:
            error_msg = f"Upload failed: {str(e)}"
            print(f"[UPLOAD ERROR] {error_msg}")
            
            # 错误响应 - 同样重定向到文件目录
            redirect_path = target_path #os.path.dirname(self.path)
            if not redirect_path.endswith('/'):
                redirect_path += '/'
                
            response_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <script>
                    function showErrorNotification() {{
                        const notification = document.createElement('div');
                        notification.innerHTML = `
                            <div style="
                                position: fixed;
                                top: 50%;
                                left: 50%;
                                transform: translate(-50%, -50%);
                                background: white;
                                padding: 20px;
                                border-radius: 8px;
                                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                                text-align: center;
                                z-index: 10000;
                                color: #d9534f;
                            ">
                                <p>上传错误: {error_msg}</p>
                                <button onclick="closeNotification()" style="
                                    padding: 8px 16px;
                                    background: #d9534f;
                                    color: white;
                                    border: none;
                                    border-radius: 4px;
                                    cursor: pointer;
                                ">确定</button>
                            </div>
                        `;
                        document.body.appendChild(notification);
                    }}
                    
                    function closeNotification() {{
                        document.querySelector('div[style*="position: fixed"]').remove();
                        window.location.href = '{redirect_path}';
                    }}
                    
                    setTimeout(() => {{
                        window.location.href = '{redirect_path}';
                    }}, 3000);  // 3秒后自动重定向
                    
                    window.onload = showErrorNotification;
                </script>
            </head>
            <body></body>
            </html>
            """
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.send_header("Content-type", "text/html; charset=utf-8")

            self.send_header("Connection", "close")
            self.send_header("Vary", "Accept-Encoding")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            
            self.end_headers()
            self.wfile.write(response_content.encode('utf-8'))