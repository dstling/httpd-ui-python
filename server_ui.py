# server_ui.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import os
import platform
import threading
import socket
from datetime import datetime
from file_server import FileServer  # 导入服务模块

class ServerManagerApp:
    def __init__(self, root):
        self.root = root
        # 初始化文件服务器实例
        self.file_server = FileServer() #从这里开始初始化
        self.file_server.set_log_callback(self.log)  #设置日志回调 file_server可以使用日志输出到界面
        self.file_server.set_interface_cmd_thread(False)

        #self.root.title(f"文件服务器管理（支持虚拟目录）")
        self.root.title(f"{self.file_server.server_name}-{self.file_server.server_version} powered by:{self.file_server.server_by}")
        self.root.geometry("700x850")
        self.root.resizable(True, True)

        # 设置主窗口图标
        self.set_window_icon()  # 新增：设置窗口图标        

        # Create log directory if not exists
        self.log_dir = os.path.join(os.getcwd(), "log")
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        # Generate log filename with current timestamp
        self.filename = datetime.now().strftime("%Y%m%d%H%M%S") + ".log"
        self.log_path = os.path.join(self.log_dir, self.filename)

        # 设置中文字体
        self.setup_fonts()

        # 虚拟目录配置
        self.virtual_dirs = {}

        # 鉴权变量必须在这里初始化
        self.auth_var = tk.BooleanVar(value=self.file_server.enable_authentication)

        # 创建UI组件
        self.create_widgets()

        # 从配置加载数据至界面
        self.load_config_data()

        self.tray_thread=None
        self.setup_tray_icon()  # 新增初始化
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)  # 修改为新的关闭处理方法

    def set_window_icon(self):
        """设置主窗口图标"""
        try:
            # 获取当前脚本所在目录
            base_dir = os.path.dirname(os.path.abspath(__file__))
            system = platform.system()
            
            if system == "Windows":
                icon_path = os.path.join(base_dir, "icon.ico")
                print(f"正在设置主窗口图标: {icon_path}")
                
                if os.path.exists(icon_path):
                    self.root.iconbitmap(icon_path)  # 设置窗口图标
                    print(f"已设置主窗口图标: {icon_path}")
                else:
                    print(f"警告: 主窗口图标文件不存在: {icon_path}")
            else:  # Linux系统
                # 尝试使用PNG格式图标
                icon_path = os.path.join(base_dir, "icon.png")
                print(f"尝试使用PNG图标: {icon_path}")
                
                if os.path.exists(icon_path):
                    try:
                        # 使用PIL加载PNG图像
                        from PIL import Image, ImageTk
                        img = Image.open(icon_path)
                        icon = ImageTk.PhotoImage(img)
                        self.root.tk.call('wm', 'iconphoto', self.root._w, icon)
                        print(f"已设置PNG格式主窗口图标: {icon_path}")
                    except ImportError:
                        print("警告: 缺少PIL库，无法加载PNG图标")
                    except Exception as e:
                        print(f"设置PNG图标时出错: {str(e)}")
                else:
                    print(f"警告: Linux图标文件不存在: {icon_path}")
        except Exception as e:
            print(f"设置主窗口图标时出错: {str(e)}")

    def setup_tray_icon(self):
        """初始化系统托盘图标"""
        system = platform.system()
        
        if system == "Windows":
            self.setup_windows_tray()
        else:  # Linux
            self.setup_linux_tray()

    def setup_windows_tray(self):
        """Windows 托盘实现（使用pystray）"""
        try:
            import pystray
            from PIL import Image
            
            # 获取当前脚本所在目录
            base_dir = os.path.dirname(os.path.abspath(__file__))
            icon_path = os.path.join(base_dir, "icon.ico")
            
            if not os.path.exists(icon_path):
                self.log(f"警告: 托盘图标文件不存在: {icon_path}")
                print("警告: 托盘图标文件不存在:", icon_path)
                # 创建临时空白图标
                image = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
            else:
                image = Image.open(icon_path)
            
            menu = pystray.Menu(
                pystray.MenuItem("显示窗口", self.show_window),
                pystray.MenuItem("隐藏至托盘区", self.hide_to_tray),
                pystray.MenuItem("退出程序", self.quit_app)
            )
            
            self.tray = pystray.Icon("FileServer", image, menu=menu)
            
            # 启动托盘线程（非守护线程）
            self.tray_thread = threading.Thread(target=self.tray.run)
            self.tray_thread.daemon = True  # 主线程退出时不会强制结束
            self.tray_thread.start()
            
            self.log("Windows托盘图标已启动")
            
        except ImportError:
            self.log("警告：未安装pystray，无法使用系统托盘")
        except Exception as e:
            self.log(f"托盘初始化失败: {str(e)}")
    def show_tray_menu(self, event):
        """显示托盘菜单"""
        self.tray_menu.post(event.x_root, event.y_root)

    def setup_linux_tray(self):
        """Linux 托盘实现"""
        try:
            import pystray
            from PIL import Image
            
            image = Image.open("icon.png")
            menu = pystray.Menu(
                pystray.MenuItem("显示窗口", self.show_window),
                pystray.MenuItem("退出", self.quit_app)
            )
            self.tray = pystray.Icon("FileServer", image, menu=menu)
            threading.Thread(target=self.tray.run).start()
        except ImportError:
            self.log("警告：未安装pystray，无法使用系统托盘")

    def show_tray_notification(self, title, message):
        """显示托盘通知"""
        if hasattr(self, 'tray_notification'):
            try:
                self.tray_notification.update(title=title, msg=message)
                self.tray_notification.show()
            except Exception as e:
                self.log(f"通知发送失败: {str(e)}")
    def show_window(self):
        """从托盘恢复窗口"""
        self.root.deiconify()
        self.root.lift()

    def hide_to_tray(self):
        """隐藏到托盘"""
        self.root.withdraw()
        
    # 添加新的关闭处理方法
    def on_close(self):
        """处理窗口关闭事件"""
        choice = messagebox.askyesnocancel(
            "关闭程序",
            "请选择操作：\n\n"
            "• '是': 隐藏到托盘\n"
            "• '否': 退出程序\n"
            "• '取消': 返回程序",
            icon='question'
        )
        
        if choice is None:  # 用户点击"取消"
            return
        elif choice:  # 用户点击"是" - 隐藏到托盘
            self.hide_to_tray()
        else:  # 用户点击"否" - 退出程序
            self.quit_app()        
    def quit_app(self):
        """退出程序"""
        # 添加退出确认
        #if not messagebox.askyesno("确认退出", "确定要退出文件服务器吗？"):
        #    return
        
        # 添加日志记录
        self.log("开始退出程序...")
        
        # 停止服务器
        self.stop_server()
        
        # 停止托盘图标（Windows/Linux）
        if hasattr(self, 'tray'):
            try:
                self.log("正在停止托盘图标...")
                self.tray.stop()  # 停止托盘图标
                self.log("托盘图标已停止")
            except Exception as e:
                self.log(f"停止托盘时出错: {str(e)}")

        # 销毁主窗口
        if self.root:
            try:
                self.log("正在关闭主窗口...")
                self.root.quit()  # 停止主事件循环
                self.root.destroy()  # 销毁主窗口
            except Exception as e:
                print(f"关闭主窗口时出错: {str(e)}")
        
        # 强制退出程序（确保完全退出）
        print("程序完全退出")
        os._exit(0)  # 强制终止进程

    def load_config_data(self):
        """从配置加载数据到UI"""
        # 加载监听地址和端口
        self.address_var.set(self.file_server.get_listen_address())
        self.port_var.set(self.file_server.get_listen_port())

        # 加载虚拟目录
        self.virtual_dirs = self.file_server.get_virtual_directories()
        self.update_virtual_dir_list()

        # 设置鉴权开关状态
        self.auth_var.set(self.file_server.enable_authentication)

        self.username_var.set(self.file_server.auth_username)
        #self.password_var.set(self.file_server.auth_password)
        self.password_var.set("")  # Clear password field
        self.logined_timeout_var.set(self.file_server.logined_timeout)  # Clear password field

        self.log(f"已从配置加载: {len(self.virtual_dirs)} 个虚拟目录")

    def setup_fonts(self):
        """设置适用于不同平台的中文字体"""
        import platform
        system = platform.system()
        if system == "Windows":
            self.default_font = ("Microsoft YaHei UI", 10)
        else:  # Linux 和其他系统
            self.default_font = ("WenQuanYi Micro Hei", 10)

    def create_widgets(self):
        """创建UI界面组件（添加虚拟目录管理）"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 配置区域 - 基础设置
        config_frame = ttk.LabelFrame(main_frame, text="服务器配置", padding="10")
        config_frame.pack(fill=tk.X, pady=5)

        # 地址和端口设置
        addr_frame = ttk.Frame(config_frame)
        addr_frame.pack(fill=tk.X, pady=5)

        ttk.Label(addr_frame, text="监听地址:", font=self.default_font).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.address_var = tk.StringVar()
        ttk.Entry(addr_frame, textvariable=self.address_var, width=15, font=self.default_font).grid(row=0, column=1, sticky=tk.W, padx=5)

        ttk.Label(addr_frame, text="端口号:", font=self.default_font).grid(row=0, column=2, sticky=tk.W, padx=5)
        self.port_var = tk.IntVar()
        ttk.Entry(addr_frame, textvariable=self.port_var, width=8, font=self.default_font).grid(row=0, column=3, sticky=tk.W, padx=5)

        ttk.Button(addr_frame, text="自动查找端口", command=self.find_available_port, width=12).grid(row=0, column=4, sticky=tk.W, padx=5)
        ttk.Button(addr_frame, text="保存IP:Port", command=self.save_ip_port, width=12).grid(row=0, column=5, sticky=tk.W, padx=5)

        # 用户名设置
        user_frame = ttk.Frame(config_frame)
        user_frame.pack(fill=tk.X, pady=5)
        ttk.Label(user_frame, text="用户名称:", font=self.default_font).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.username_var = tk.StringVar()
        ttk.Entry(user_frame, textvariable=self.username_var, width=15, font=self.default_font).grid(row=0, column=1, sticky=tk.W, padx=5)
        # 密码设置
        ttk.Label(user_frame, text="密   码:", font=self.default_font).grid(row=0, column=2, sticky=tk.W, padx=5)
        self.password_var = tk.StringVar()
        ttk.Entry(user_frame, textvariable=self.password_var, width=20, font=self.default_font, show="*").grid(row=0, column=3, sticky=tk.W, padx=5)

        timeout_clear_frame = ttk.Frame(config_frame)
        timeout_clear_frame.pack(fill=tk.X, pady=5)
        ttk.Label(timeout_clear_frame, text="超时清理:", font=self.default_font).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.logined_timeout_var = tk.StringVar()
        ttk.Entry(timeout_clear_frame, textvariable=self.logined_timeout_var, width=5, font=self.default_font).grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Label(timeout_clear_frame, text="分钟", font=self.default_font).grid(row=0, column=2, sticky=tk.W, padx=5)

        # 启用访问鉴权选择
        auth_button_frame = ttk.Frame(config_frame)
        auth_button_frame.pack(fill=tk.X, pady=5)
        self.auth_checkbtn = ttk.Checkbutton(auth_button_frame, text="启用访问鉴权(当前版本无需设置)", variable=self.auth_var).grid(row=0, column=0, sticky=tk.W, padx=5)
        ttk.Button(auth_button_frame, text="保存设置", command=self.save_server_settings, width=15).grid(row=0, column=1, sticky=tk.W, padx=5)

        # 状态区域
        status_frame = ttk.LabelFrame(main_frame, text="服务器状态", padding="10")
        status_frame.pack(fill=tk.X, pady=5)

        btn_frame = ttk.Frame(status_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        self.start_btn = ttk.Button(btn_frame, text="启动服务器", command=self.start_server, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(btn_frame, text="停止服务器", command=self.stop_server, width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)        
        self.query_logined_btn = ttk.Button(btn_frame, text="查询登录用户", command=self.query_logined, width=15)
        self.query_logined_btn.pack(side=tk.LEFT, padx=5)

    
        # +++ 添加隐藏到托盘按钮 +++
        self.hide_btn = ttk.Button(btn_frame, text="隐藏到托盘", command=self.hide_to_tray, width=15)
        self.hide_btn.pack(side=tk.LEFT, padx=5)

        status_info_frame = ttk.Frame(status_frame)
        status_info_frame.pack(fill=tk.X)
        ttk.Label(status_info_frame, text="当前状态:", font=self.default_font).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.status_var = tk.StringVar(value="未运行")
        self.status_label = ttk.Label(status_info_frame, textvariable=self.status_var,font=("Arial", 10, "bold"), foreground="red")
        self.status_label.grid(row=0, column=1, sticky=tk.W, padx=5)

        ttk.Label(status_info_frame, text="访问地址:", font=self.default_font).grid(row=0, column=2, sticky=tk.W, padx=10)
        self.access_var = tk.StringVar(value="")
        ttk.Label(status_info_frame, textvariable=self.access_var, font=self.default_font).grid(row=0, column=3, sticky=tk.W, padx=5)

        # 目录配置区域
        vdir_frame = ttk.LabelFrame(main_frame, text="目录配置", padding="10")
        vdir_frame.pack(fill=tk.X, pady=5)

        # 虚拟目录列表
        vdir_list_frame = ttk.Frame(vdir_frame)
        vdir_list_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        columns = ("virtual_path", "physical_path", "allow_anonymous")
        self.vdir_tree = ttk.Treeview(vdir_list_frame, columns=columns, show="headings", height=5)
        self.vdir_tree.heading("virtual_path", text="虚拟路径")
        self.vdir_tree.heading("physical_path", text="物理路径")
        self.vdir_tree.heading("allow_anonymous", text="允许匿名访问")
        self.vdir_tree.column("virtual_path", width=100)
        self.vdir_tree.column("physical_path", width=350)
        self.vdir_tree.column("allow_anonymous", width=100)
        self.vdir_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.vdir_tree.bind("<Double-1>", self.on_vdir_double_click) # 双击事件处理

        scrollbar = ttk.Scrollbar(vdir_list_frame, orient=tk.VERTICAL, command=self.vdir_tree.yview)
        self.vdir_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 虚拟目录操作按钮
        vdir_btn_frame = ttk.Frame(vdir_frame)
        vdir_btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(vdir_btn_frame, text="添加虚拟目录", command=self.add_virtual_directory, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(vdir_btn_frame, text="删除虚拟目录", command=self.remove_virtual_directory, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(vdir_btn_frame, text="浏览...", command=self.browse_directory, width=10).pack(side=tk.LEFT, padx=5)

        # 日志区域
        log_frame = ttk.LabelFrame(main_frame, text="服务器日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=70, height=15, font=self.default_font)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)

        self.setup_log_copy()
        
        self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray) 

    def setup_log_copy(self):
        """设置日志文本框的复制功能"""
        self.log_menu = tk.Menu(self.root, tearoff=0)
        self.log_menu.add_command(label="复制", command=self.copy_log)
        self.log_text.bind("<Button-3>", self.show_log_menu)
        self.root.bind("<Control-c>", self.copy_log)
        self.root.bind("<Control-C>", self.copy_log)

    def show_log_menu(self, event):
        self.log_menu.post(event.x_root, event.y_root)

    def copy_log(self, event=None):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.event_generate("<<Copy>>")
        self.log_text.config(state=tk.DISABLED)

    def find_available_port(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('localhost', 0))
        port = sock.getsockname()[1]
        sock.close()
        self.port_var.set(port)
        self.log(f"找到可用端口: {port}")
    def save_ip_port(self):
        ipTmp = self.address_var.get()
        portTmp = self.port_var.get()
        self.file_server.set_ip_port(ipTmp, portTmp)
        self.log(f"ip地址: {ipTmp} port: {portTmp} 保存成功")
        self.file_server.restart()
        self.access_var.set(f"http://{self.address_var.get()}:{self.port_var.get()}")
    
    def browse_directory(self):
        directory = filedialog.askdirectory(title="选择目录")
        if directory:
            self.file_server.set_virtual_directory('/', directory, allow_anonymous=False)
            self.update_virtual_dir_list()
            self.log(f"设置根目录为: {directory}")

    def add_virtual_directory(self):
        virtual_path = tk.simpledialog.askstring("添加虚拟目录", "输入虚拟路径 (例如: /docs):")

        if virtual_path == '/':
            messagebox.showinfo("提示", "根目录已自动管理，不可添加？")
            return

        if virtual_path:
            if not virtual_path.startswith('/'):
                virtual_path = '/' + virtual_path
            physical_path = filedialog.askdirectory(title="选择物理路径")
            if physical_path:
                # 询问是否允许匿名访问
                ret_allow_anonymous = messagebox.askyesno("匿名访问设置", 
                                                    "是否允许匿名访问此目录?\n(无需用户名密码即可访问)",
                                                    parent=self.root)
                
                self.virtual_dirs[virtual_path] = physical_path
                self.file_server.add_virtual_directory(virtual_path, physical_path, allow_anonymous=ret_allow_anonymous)
                self.update_virtual_dir_list()
                self.log(f"添加虚拟目录: {virtual_path} -> {physical_path} (匿名访问: {'是' if ret_allow_anonymous else '否'})")

    def remove_virtual_directory(self):
        selected = self.vdir_tree.selection()
        if not selected:
            messagebox.showwarning("警告", "请先选择一个虚拟目录")
            return
        item = self.vdir_tree.item(selected[0])
        virtual_path = item['values'][0]
        if virtual_path in self.virtual_dirs:
            #del self.virtual_dirs[virtual_path] #在remove_virtual_directory里面执行del操作
            self.file_server.remove_virtual_directory(virtual_path)
            self.update_virtual_dir_list()
            self.log(f"移除虚拟目录: {virtual_path}")
    def update_virtual_dir_list(self):
        for item in self.vdir_tree.get_children(): #先清空
            self.vdir_tree.delete(item)

        for virtual, dir_info in self.virtual_dirs.items():
            # 处理新旧格式兼容
            if isinstance(dir_info, dict):
                physical_path = dir_info.get('physical_path', '')
                allow_anonymous = dir_info.get('allow_anonymous', False)
            else:
                physical_path = dir_info
                allow_anonymous = False
                
            if virtual == '/':
                self.vdir_tree.insert("", "end", values=("(根目录)", physical_path, "是" if allow_anonymous else "否"), tags=('root',))
            else:
                self.vdir_tree.insert("", "end", values=(virtual, physical_path, "是" if allow_anonymous else "否"))
                
        self.vdir_tree.tag_configure('root', background="#e6a9a9")
    def save_server_settings(self):
        """保存鉴权设置到文件服务器"""
        username = self.username_var.get()
        password = self.password_var.get()
        logined_timeout = self.logined_timeout_var.get()
        enable_authentication = self.auth_var.get()
        if not logined_timeout:
            logined_timeout = 1
        self.file_server.set_logined_timeout(logined_timeout)

        if not username:
            messagebox.showwarning("输入错误", "用户名不能为空")
            return
        if False:
            if not password:#仅保存是否启用鉴权功能
                self.file_server.set_authentication(enable_authentication)
                print(f"鉴权设置已更新 enable_authentication:{enable_authentication}")
                self.log(f"鉴权设置已更新 enable_authentication:{enable_authentication}")
                return
        if username and password:    
            self.file_server.set_auth_credentials(username, password)
            self.file_server.set_authentication(enable_authentication)
            print(f"鉴权设置已更新 用户名={username} enable_authentication:{enable_authentication}")
            self.log(f"鉴权设置已更新 用户名={username} enable_authentication:{enable_authentication}")

    # 添加新的方法：双击事件处理
    def on_vdir_double_click(self, event):
        """处理虚拟目录条目的双击事件"""
        region = self.vdir_tree.identify("region", event.x, event.y)
        if region == "cell":
            item = self.vdir_tree.selection()[0]
            values = self.vdir_tree.item(item, "values")
            tags = self.vdir_tree.item(item, "tags")
            
            is_root = False
            if tags and 'root' in tags:
                is_root = True
                virtual_path = '/'
            else:
                virtual_path = values[0]
                
            physical_path = values[1]
            print(f"双击的虚拟目录: {virtual_path} -> {physical_path}")
            
            # 创建编辑对话框
            self.edit_virtual_directory(virtual_path, physical_path, is_root)

    # 添加新的方法：编辑虚拟目录
    def edit_virtual_directory(self, virtual_path, physical_path, is_root=False):
        """编辑虚拟目录对话框"""
        # 获取当前目录的匿名访问设置
        current_dir = self.virtual_dirs.get(virtual_path, {})
        current_allow_anonymous = current_dir.get('allow_anonymous', False) if isinstance(current_dir, dict) else False
        
        dialog = tk.Toplevel(self.root)
        dialog.title("编辑虚拟目录" if not is_root else "编辑根目录")
        dialog.geometry("600x200")
        dialog.transient(self.root)  # 设置为模态对话框
        dialog.update_idletasks()  # 确保窗口布局完成
        dialog.wait_visibility()   # 等待窗口可见
        dialog.grab_set()  # 获取焦点
        
        # 虚拟路径设置
        ttk.Label(dialog, text="虚拟路径:", font=self.default_font).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        virtual_var = tk.StringVar(value=virtual_path)
        virtual_entry = ttk.Entry(dialog, textvariable=virtual_var, width=30, font=self.default_font)
        virtual_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        if is_root:
            virtual_entry.config(state=tk.DISABLED)  # 根目录的虚拟路径不可修改
            ttk.Label(dialog, text="(根目录路径固定为'/'不可修改)").grid(row=0, column=2, padx=5, sticky=tk.W)
        
        # 物理路径设置
        ttk.Label(dialog, text="物理路径:", font=self.default_font).grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        physical_var = tk.StringVar(value=physical_path)
        physical_entry = ttk.Entry(dialog, textvariable=physical_var, width=30, font=self.default_font)
        physical_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # 浏览按钮
        def browse_physical():
            path = filedialog.askdirectory(title="选择物理路径", initialdir=physical_var.get())
            if path:
                physical_var.set(path)
        
        # 创建浏览按钮（修正位置）
        browse_btn = ttk.Button(dialog, text="浏览...", command=browse_physical, width=10)
        browse_btn.grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)

        if True:
            # 匿名访问设置（根目录不可设置）
            #if not is_root:
                ttk.Label(dialog, text="允许匿名访问:", font=self.default_font).grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
                allow_anonymous_var = tk.BooleanVar(value=current_allow_anonymous)
                allow_anonymous_check = ttk.Checkbutton(dialog, text="无需认证即可访问", variable=allow_anonymous_var)
                allow_anonymous_check.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
            #else:
                #allow_anonymous_var = None


            
        # 按钮框架（移至正确位置）
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10, sticky=tk.EW)
        
        # 保存按钮
        def save_changes():
            new_virtual = virtual_var.get().strip()
            new_physical = physical_var.get().strip()
            
            # 验证输入
            if not new_virtual or not new_physical:
                messagebox.showerror("输入错误", "虚拟路径和物理路径都不能为空")
                return
                
            if not is_root:
                if not new_virtual.startswith('/'):
                    new_virtual = '/' + new_virtual
                    
                # 检查新虚拟路径是否已存在
                if new_virtual != virtual_path and new_virtual in self.virtual_dirs:
                    messagebox.showerror("路径冲突", f"虚拟路径 '{new_virtual}' 已存在")
                    return

            new_allow_anonymous = allow_anonymous_var.get() if allow_anonymous_var else False
            print(f"[DEBUG] new_allow_anonymous:{new_allow_anonymous}")

            # 更新文件服务器配置
            if is_root:
                # 根目录的特殊处理
                #self.file_server.set_virtual_directory('/', new_physical, allow_anonymous=new_allow_anonymous)
                self.file_server.set_virtual_directory('/', new_physical, allow_anonymous=False)
                self.log(f"更新根目录物理路径: {new_physical}")
            else:
                # 获取匿名访问设置
                
                # 如果虚拟路径改变，需要先删除旧的
                if new_virtual != virtual_path:
                    self.file_server.remove_virtual_directory(virtual_path)
                    self.log(f"删除虚拟目录: {virtual_path}")
                
                # 添加新的虚拟目录
                self.file_server.add_virtual_directory(new_virtual, new_physical, allow_anonymous=new_allow_anonymous)
                self.log(f"添加/更新虚拟目录: {new_virtual} -> {new_physical} (匿名访问: {'是' if new_allow_anonymous else '否'})")
            
            # 更新UI显示
            self.virtual_dirs = self.file_server.get_virtual_directories()
            self.update_virtual_dir_list()
            dialog.destroy()
        
        # 创建保存和取消按钮（修正位置）
        ttk.Button(button_frame, text="保存", command=save_changes, width=10).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="取消", command=dialog.destroy, width=10).pack(side=tk.LEFT, padx=10)

    def query_logined(self):
        """查询并显示所有登录用户"""
        # 创建新窗口
        login_window = tk.Toplevel(self.root)
        login_window.title("登录用户管理")
        login_window.geometry("800x400")
        
        login_window.transient(self.root)
        login_window.update_idletasks()  # 确保窗口布局完成
        login_window.wait_visibility()   # 等待窗口可见
        #login_window.grab_set()
        
        # 创建框架
        main_frame = ttk.Frame(login_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 添加操作按钮（移到Treeview上方）
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10, side=tk.TOP)  # 修改为顶部布局
        
        ttk.Button(
            btn_frame, 
            text="刷新列表", 
            command=lambda: self.update_login_list(login_window),
            width=15
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="强制下线", 
            command=lambda: self.force_logout(login_window),
            width=15
        ).pack(side=tk.LEFT, padx=5)
        
        # 创建Treeview显示登录用户（放在按钮下方）
        columns = ("id", "username", "ip", "session_id", "login_time")
        self.login_tree = ttk.Treeview(
            main_frame, 
            columns=columns, 
            show="headings",
            selectmode="browse"
        )
        
        # 设置列标题
        self.login_tree.heading("id", text="ID")
        self.login_tree.heading("username", text="用户名")
        self.login_tree.heading("ip", text="IP地址")
        self.login_tree.heading("session_id", text="会话ID")
        self.login_tree.heading("login_time", text="登录时间")
        
        # 设置列宽
        self.login_tree.column("id", width=25, anchor=tk.CENTER)
        self.login_tree.column("username", width=80, anchor=tk.CENTER)
        self.login_tree.column("ip", width=120, anchor=tk.CENTER)
        self.login_tree.column("session_id", width=240)
        self.login_tree.column("login_time", width=150, anchor=tk.CENTER)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.login_tree.yview)
        self.login_tree.configure(yscroll=scrollbar.set)
        
        # 布局（Treeview放在按钮下方）
        self.login_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 初始加载数据
        self.update_login_list(login_window)
        
    def update_login_list(self, window):
        """更新登录用户列表"""
        # 清空现有数据
        for item in self.login_tree.get_children():
            self.login_tree.delete(item)
        
        # 获取最新登录数据
        users = self.file_server.get_all_logined_users()
        
        # 添加数据到Treeview
        for user in users:
            self.login_tree.insert("", "end", values=(
                user['id'],
                user['username'],
                user['ip'],
                user['session_id'],
                user['login_time']
            ))
        
        # 更新窗口标题显示用户数量
        window.title(f"登录用户管理 (共 {len(users)} 个用户)")
        
    def force_logout(self, window):
        """强制选中的用户下线"""
        selected = self.login_tree.selection()
        if not selected:
            messagebox.showwarning("操作提示", "请先选择一个用户")
            return
            
        item = self.login_tree.item(selected[0])
        values = item['values']
        session_id = values[3]  # session_id在第四列
        
        if self.file_server.remove_session(session_id):
            self.log(f"已强制下线用户: {values[1]} (ID: {values[0]})")
            self.update_login_list(window)
            messagebox.showinfo("操作成功", f"用户 {values[1]} 已被强制下线")
        else:
            messagebox.showerror("操作失败", "未能找到该用户的会话信息")

    def start_server(self):
        try:
            if False: # 测试用  系统默认初始的时候应该都加载了参数
                self.file_server.set_base_directory(self.directory_var.get())
                self.file_server.set_listen_address(self.address_var.get())
                self.file_server.set_listen_port(self.port_var.get())
                self.file_server.set_virtual_directories(self.virtual_dirs)
                # 设置鉴权状态
                self.file_server.enable_authentication = self.auth_var.get()
                self.file_server.save_config() 

            threading.Thread(target=self.file_server.start, daemon=True).start()

            self.status_var.set("运行中")
            self.status_label.configure(foreground="green")
            self.access_var.set(f"http://{self.address_var.get()}:{self.port_var.get()}")
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.log(f"服务器已启动: http://{self.address_var.get()}:{self.port_var.get()}")
            
            self.show_tray_notification("服务器已启动", f"访问地址: http://{self.address_var.get()}:{self.port_var.get()}")
    
        except Exception as e:
            messagebox.showerror("启动错误", f"无法启动服务器: {str(e)}")
            self.log(f"启动失败: {str(e)}")

    def stop_server(self):
        try:
            self.file_server.stop()
            self.status_var.set("未运行")
            self.status_label.configure(foreground="red")
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.log("服务器已停止")
            self.show_tray_notification("服务器已停止", "文件服务器已关闭")

        except Exception as e:
            messagebox.showerror("停止错误", f"无法停止服务器: {str(e)}")
            self.log(f"停止失败: {str(e)}")
    def log(self, message):
        # Add timestamp to log message
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"{timestamp}> {message}"
        
        # Update UI log
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"{formatted_message}\n")  # Removed extra colon
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
        # Append to log file
        try:
            with open(self.log_path, 'a', encoding='utf-8') as log_file:
                log_file.write(formatted_message + '\n')
        except Exception as e:
            # Fallback to UI logging if file write fails
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, f"!!! Log file write failed: {str(e)}\n")
            self.log_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerManagerApp(root) #创建开始管理界面
    root.mainloop()