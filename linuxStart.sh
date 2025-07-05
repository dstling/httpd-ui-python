#!/bin/bash

# 获取脚本所在目录
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# 后台运行主程序并重定向输出到日志文件
nohup python3 "$SCRIPT_DIR/main.py" > "$SCRIPT_DIR/appRun-linux.log" 2>&1 &

# 显示简短启动信息
echo "服务器已在后台启动"
echo "查看程序运行日志请打开log文件夹,按每次打开程序的日期自动生成"
echo "查看程序调试日志: tail -f $SCRIPT_DIR/appRun-linux.log"
echo "停止服务: pkill -f 'python3 main.py'"