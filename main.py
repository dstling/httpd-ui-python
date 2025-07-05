import sys
import subprocess
import os
import importlib.util
import argparse
import platform

def get_required_modules(file_path):
    """解析 Python 文件，获取所有导入的非标准库模块"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 获取所有导入语句
        imports = []
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('import ') or line.startswith('from '):
                # 提取模块名
                parts = line.split()
                if parts[0] == 'import':
                    module = parts[1].split('.')[0]
                elif parts[0] == 'from':
                    module = parts[1].split('.')[0]
                else:
                    continue
                
                # 排除标准库和本地模块
                if not is_standard_lib(module) and not is_local_module(module, file_path):
                    imports.append(module)
        
        return list(set(imports))  # 去重
    
    except Exception as e:
        print(f"解析文件错误: {e}")
        return []
def install_dependencies(modules):
    """安装缺失的依赖（按平台过滤）"""
    if not modules:
        print("没有需要安装的依赖")
        return True
    
    current_platform = platform.system()
    print(f"当前平台: {current_platform}")
    
    # 平台特定依赖映射
    platform_modules = {
        'Windows': ['pystray', 'PIL'],  # 修改为pystray
        'Darwin': ['rumps', 'PIL'],
        'Linux': ['pystray', 'PIL']
    }
    
    # 过滤出当前平台需要的依赖
    filtered_modules = [m for m in modules if m in platform_modules.get(current_platform, [])]
    
    if not filtered_modules:
        print("当前平台无需额外依赖")
        return True
        
    print(f"需要安装的依赖: {', '.join(filtered_modules)}")
    try:
        pip_cmd = [sys.executable, "-m", "pip", "install"]
        module_map = {
            'bs4': 'beautifulsoup4',
            'PIL': 'pillow',
            'sklearn': 'scikit-learn',
            'cv2': 'opencv-python',
            'yaml': 'pyyaml',
            'MySQLdb': 'mysqlclient'
        }
        
        packages = [module_map.get(module, module) for module in filtered_modules]
        
        result = subprocess.run(pip_cmd + packages, check=True)
        if result.returncode == 0:
            print("所有依赖安装成功")
            return True
    except subprocess.CalledProcessError as e:
        print(f"依赖安装失败: {e}")
    except Exception as e:
        print(f"安装过程中发生错误: {e}")
    
    return False

def is_standard_lib(module):
    """检查模块是否是 Python 标准库"""
    try:
        spec = importlib.util.find_spec(module)
        if spec and 'site-packages' not in spec.origin:
            return True
    except:
        pass
    return False

def is_local_module(module, file_path):
    """检查模块是否是本地文件"""
    script_dir = os.path.dirname(os.path.abspath(file_path))
    possible_paths = [
        os.path.join(script_dir, f"{module}.py"),
        os.path.join(script_dir, module, "__init__.py")
    ]
    return any(os.path.exists(path) for path in possible_paths)

def install_dependencies2(modules):
    """安装缺失的依赖"""
    if not modules:
        print("没有需要安装的依赖")
        return True
    
    print(f"需要安装的依赖: {', '.join(modules)}")
    try:
        # 使用当前 Python 解释器的 pip
        pip_cmd = [sys.executable, "-m", "pip", "install"]
        
        # 添加映射关系（模块名 -> PyPI 包名）
        module_map = {
            'bs4': 'beautifulsoup4',
            'PIL': 'pillow',
            'sklearn': 'scikit-learn',
            'cv2': 'opencv-python',
            'yaml': 'pyyaml',
            'MySQLdb': 'mysqlclient'
        }
        
        # 转换模块名为包名
        packages = [module_map.get(module, module) for module in modules]
        
        # 执行安装
        result = subprocess.run(pip_cmd + packages, check=True)
        if result.returncode == 0:
            print("所有依赖安装成功")
            return True
    except subprocess.CalledProcessError as e:
        print(f"依赖安装失败: {e}")
    except Exception as e:
        print(f"安装过程中发生错误: {e}")
    
    return False

def run_target_script(target_script, args):
    """运行目标脚本"""
    cmd = [sys.executable, target_script] + args
    try:
        print(f"\n运行目标脚本: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"脚本执行失败，退出码: {e.returncode}")
    except Exception as e:
        print(f"执行过程中发生错误: {e}")

def scan_project_dependencies(project_dir):
    """扫描项目目录中所有Python文件的依赖"""
    all_modules = set()
    
    for root, _, files in os.walk(project_dir):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                modules = get_required_modules(file_path)
                all_modules.update(modules)
    
    return list(all_modules)

def check_run_required(run_main="server_ui.py"):
    # 获取项目根目录（当前脚本所在目录）
    project_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"扫描项目目录: {project_dir}")
    
    # 1. 扫描所有依赖
    required_modules = scan_project_dependencies(project_dir)
    
    if required_modules:
        print(f"检测到项目依赖: {', '.join(required_modules)}")
        print("开始安装依赖...")
        success = install_dependencies(required_modules)
        if not success:
            print("依赖安装失败，无法继续执行")
            return
    
    # 2. 运行主程序
    main_script = os.path.join(project_dir, run_main)
    print(f"\n启动主程序: {main_script}")
    run_target_script(main_script, [])

if __name__ == "__main__":
    check_run_required("server_ui.py")