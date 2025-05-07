#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon
from src.gui.main_window import MainWindow
from src.utils.config_manager import ConfigManager

def main():
    """应用程序主入口"""
    # 确保配置目录存在
    config_dir = os.path.join(os.path.expanduser("~"), ".ai_log_analyzer")
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
    
    # 初始化配置管理器
    config_manager = ConfigManager()
    
    # 创建Qt应用
    app = QApplication(sys.argv)
    app.setApplicationName("AI安全日志分析工具")
    
    # 设置应用图标（如果有的话）
    # app.setWindowIcon(QIcon("icon.png"))
    
    # 创建并显示主窗口
    main_window = MainWindow(config_manager)
    main_window.show()
    
    # 启动应用程序事件循环
    sys.exit(app.exec())

if __name__ == "__main__":
    main() 