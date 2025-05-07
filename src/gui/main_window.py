#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import threading
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QPushButton, QTextEdit, QFileDialog, QComboBox, QTableView,
    QTabWidget, QGroupBox, QSplitter, QMessageBox, QSpinBox,
    QCheckBox, QDialog, QLineEdit, QStatusBar, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QMenu, QInputDialog,
    QFormLayout, QDialogButtonBox
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, QThread, QSortFilterProxyModel, QAbstractTableModel
from PyQt6.QtGui import QIcon, QFont

from src.gui.settings_dialog import SettingsDialog
from src.utils.ip_masker import IPMasker
from src.utils.log_parser import LogParser
from src.ai.ai_service import AIServiceFactory

class MainWindow(QMainWindow):
    """主窗口"""
    
    def __init__(self, config_manager):
        """初始化主窗口
        
        Args:
            config_manager: 配置管理器实例
        """
        super().__init__()
        
        self.config_manager = config_manager
        self.log_parser = LogParser()
        self.ip_masker = IPMasker(self.config_manager.config_dir)
        
        self.current_file = None
        self.log_data = None
        self.current_prompt = "default"  # 当前使用的提示词
        self.is_updating_provider = False  # 添加标志，防止循环调用
        
        self.init_ui()
        self.load_ai_providers()
    
    def init_ui(self):
        """初始化用户界面"""
        # 设置窗口标题和大小
        self.setWindowTitle("AI安全日志分析工具")
        self.resize(1200, 800)
        
        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 创建主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 创建顶部工具栏
        toolbar_layout = QHBoxLayout()
        main_layout.addLayout(toolbar_layout)
        
        # 添加文件选择按钮
        self.load_file_btn = QPushButton("加载日志文件")
        self.load_file_btn.clicked.connect(self.load_file)
        toolbar_layout.addWidget(self.load_file_btn)
        
        # 添加清除按钮
        self.clear_btn = QPushButton("清除数据")
        self.clear_btn.clicked.connect(self.clear_data)
        self.clear_btn.setToolTip("清除当前加载的日志文件和告警信息")
        toolbar_layout.addWidget(self.clear_btn)
        
        # 显示当前文件路径
        self.current_file_label = QLabel("未加载文件")
        toolbar_layout.addWidget(self.current_file_label)
        toolbar_layout.addStretch()
        
        # 添加AI提供商选择
        toolbar_layout.addWidget(QLabel("AI服务商:"))
        self.ai_provider_combo = QComboBox()
        self.ai_provider_combo.addItems(["DeepSeek", "豆包", "本地AI模型", "其他AI模型"])
        toolbar_layout.addWidget(self.ai_provider_combo)
        
        # 添加设置按钮
        self.settings_btn = QPushButton("设置")
        self.settings_btn.clicked.connect(self.show_settings)
        toolbar_layout.addWidget(self.settings_btn)
        
        # 创建主分割器
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(main_splitter, 1)
        
        # 创建左侧主要内容区域
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        # 创建IP映射表区域
        self.ip_mapping_group = QGroupBox("IP映射表")
        ip_mapping_layout = QVBoxLayout(self.ip_mapping_group)
        
        self.ip_mapping_table = QTableWidget()
        self.ip_mapping_table.setColumnCount(2)
        self.ip_mapping_table.setHorizontalHeaderLabels(["脱敏IP", "原始IP"])
        self.ip_mapping_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        ip_mapping_layout.addWidget(self.ip_mapping_table)
        
        # 是否显示IP映射表由配置决定
        self.ip_mapping_group.setVisible(self.config_manager.get("show_ip_mapping", False))
        
        left_layout.addWidget(self.ip_mapping_group)
        
        # 创建内容分割器
        content_splitter = QSplitter(Qt.Orientation.Vertical)
        left_layout.addWidget(content_splitter, 1)
        
        # 创建日志查看区域
        log_group = QGroupBox("日志内容")
        log_layout = QVBoxLayout(log_group)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        log_layout.addWidget(self.log_view)
        content_splitter.addWidget(log_group)
        
        # 创建分析区域
        analysis_group = QGroupBox("安全分析")
        analysis_layout = QVBoxLayout(analysis_group)
        
        # 创建水平分割的分析区
        analysis_splitter = QSplitter(Qt.Orientation.Horizontal)
        analysis_layout.addWidget(analysis_splitter)
        
        # 创建告警输入区
        alert_group = QGroupBox("告警信息")
        alert_layout = QVBoxLayout(alert_group)
        self.alert_edit = QTextEdit()
        self.alert_edit.setAcceptRichText(False)  # 使用纯文本模式，支持中文更好
        alert_layout.addWidget(self.alert_edit)
        
        analyze_btn_layout = QHBoxLayout()
        self.analyze_btn = QPushButton("分析")
        self.analyze_btn.clicked.connect(self.analyze_logs)
        analyze_btn_layout.addWidget(self.analyze_btn)
        
        # 添加提示词选择按钮
        self.prompt_btn = QPushButton("提示词")
        self.prompt_btn.setToolTip("选择或编辑分析提示词")
        self.prompt_btn.clicked.connect(self.show_prompt_menu)
        analyze_btn_layout.addWidget(self.prompt_btn)
        
        self.mask_ip_checkbox = QCheckBox("脱敏IP")
        self.mask_ip_checkbox.setChecked(self.config_manager.get("ip_mask_enabled", True))
        self.mask_ip_checkbox.toggled.connect(self.update_ip_masking)
        analyze_btn_layout.addWidget(self.mask_ip_checkbox)
        
        alert_layout.addLayout(analyze_btn_layout)
        analysis_splitter.addWidget(alert_group)
        
        # 创建AI分析结果区
        result_group = QGroupBox("分析结果")
        result_layout = QVBoxLayout(result_group)
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        result_layout.addWidget(self.result_text)
        analysis_splitter.addWidget(result_group)
        
        # 设置分割比例
        analysis_splitter.setSizes([400, 600])
        
        content_splitter.addWidget(analysis_group)
        
        # 设置分割比例
        content_splitter.setSizes([500, 300])
        
        # 添加左侧内容区到主分割器
        main_splitter.addWidget(left_widget)
        
        # 设置主分割器的比例
        main_splitter.setSizes([1200])
        
        # 创建状态栏
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.status_label = QLabel("就绪")
        self.statusBar.addWidget(self.status_label)
        
        # 创建进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximum(0)  # 无限进度条
        self.progress_bar.setMinimum(0)
        self.statusBar.addPermanentWidget(self.progress_bar)
        
        # 默认启用分析按钮，允许用户只输入告警信息进行分析
        self.analyze_btn.setEnabled(True)
    
    def load_ai_providers(self):
        """加载AI服务商到下拉菜单"""
        self.ai_provider_combo.clear()
        self.ai_provider_combo.addItems(["DeepSeek", "豆包", "本地AI模型", "其他AI模型"])
        
        # 添加自定义API服务商
        custom_apis = self.config_manager.get("custom_apis", {})
        for key, info in custom_apis.items():
            if "name" in info:
                self.ai_provider_combo.addItem(info["name"])
        
        # 设置当前选择的服务商
        provider = self.config_manager.get("ai_provider", "deepseek")
        provider_name = self.config_manager.get_provider_name(provider)
        
        # 查找并设置当前项
        index = self.ai_provider_combo.findText(provider_name)
        if index >= 0:
            self.ai_provider_combo.setCurrentIndex(index)
        
        # 当用户选择"其他AI模型"时，显示配置对话框
        self.ai_provider_combo.currentTextChanged.connect(self.provider_changed)
    
    def provider_changed(self, text):
        """处理AI服务商变更事件"""
        # 如果是程序自动设置的，不处理
        if self.is_updating_provider:
            return
            
        if text == "本地AI模型":
            # 弹出对话框让用户配置本地AI模型
            dialog = QDialog(self)
            dialog.setWindowTitle("配置本地AI模型")
            layout = QVBoxLayout(dialog)
            
            # 添加常见本地模型选择
            model_selector_layout = QHBoxLayout()
            model_selector_layout.addWidget(QLabel("常见本地模型:"))
            model_selector = QComboBox()
            model_selector.addItems(["自定义", "LM Studio", "LocalAI", "Ollama", "LLaMA.cpp"])
            model_selector_layout.addWidget(model_selector)
            layout.addLayout(model_selector_layout)
            
            form_layout = QFormLayout()
            url_input = QLineEdit()
            url_input.setPlaceholderText("例如: http://localhost:1234/v1/chat/completions")
            
            # 加载之前保存的URL
            saved_url = self.config_manager.get("api_urls", {}).get("local", "http://localhost:1234/v1/chat/completions")
            if saved_url:
                url_input.setText(saved_url)
                
            form_layout.addRow("API URL:", url_input)
            
            key_input = QLineEdit()
            key_input.setEchoMode(QLineEdit.EchoMode.Password)
            key_input.setPlaceholderText("(选填) 部分本地模型可能需要API密钥")
            
            # 加载之前保存的API密钥
            saved_key = self.config_manager.get_api_key("local")
            if saved_key:
                key_input.setText(saved_key)
                
            form_layout.addRow("API 密钥:", key_input)
            
            timeout_spinbox = QSpinBox()
            timeout_spinbox.setRange(10, 600)
            
            # 加载之前保存的超时设置
            saved_timeout = self.config_manager.get("api_timeout", {}).get("local", 180)
            timeout_spinbox.setValue(saved_timeout)
            
            timeout_spinbox.setSuffix(" 秒")
            form_layout.addRow("超时时间:", timeout_spinbox)
            
            layout.addLayout(form_layout)
            
            # 为常用本地模型设置预设URL
            def update_url_for_model(index):
                model_name = model_selector.currentText()
                if model_name == "LM Studio":
                    url_input.setText("http://localhost:1234/api/chat")
                    info_label.setText("LM Studio的默认API端点是 /api/chat 而不是标准的OpenAI格式。如果仍然出现错误，请在LM Studio设置中确认正确的端点。")
                elif model_name == "LocalAI":
                    url_input.setText("http://localhost:8080/v1/chat/completions")
                    info_label.setText("LocalAI默认使用8080端口和标准OpenAI格式的API端点。")
                elif model_name == "Ollama":
                    url_input.setText("http://localhost:11434/api/chat")
                    info_label.setText("Ollama使用11434端口和自定义API端点结构。")
                elif model_name == "LLaMA.cpp":
                    url_input.setText("http://localhost:8080/v1/chat/completions")
                    info_label.setText("LLaMA.cpp服务器通常使用8080端口和OpenAI兼容格式。")
            
            model_selector.currentIndexChanged.connect(update_url_for_model)
            
            # 添加提示信息
            info_label = QLabel("不同的本地AI模型可能需要不同的URL格式。请参考模型文档进行设置。")
            info_label.setWordWrap(True)
            layout.addWidget(info_label)
            
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addWidget(buttons)
            
            # 显示对话框
            if dialog.exec():
                # 用户点击了确定
                api_url = url_input.text().strip()
                api_key = key_input.text().strip()
                timeout = timeout_spinbox.value()
                
                if not api_url:
                    QMessageBox.warning(self, "警告", "请输入API URL")
                    # 恢复之前的选择
                    self.is_updating_provider = True
                    self.load_ai_providers()
                    self.is_updating_provider = False
                    return
                
                # 保存设置
                api_urls = self.config_manager.get("api_urls", {})
                api_urls["local"] = api_url
                self.config_manager.set("api_urls", api_urls)
                
                if api_key:
                    self.config_manager.set_api_key("local", api_key)
                
                # 保存超时设置
                api_timeout = self.config_manager.get("api_timeout", {})
                api_timeout["local"] = timeout
                self.config_manager.set("api_timeout", api_timeout)
                
                # 设置为当前服务商
                self.config_manager.set("ai_provider", "local")
            else:
                # 用户取消了，恢复之前的选择
                self.is_updating_provider = True
                self.load_ai_providers()
                self.is_updating_provider = False
            
        elif text == "其他AI模型":
            # 弹出对话框让用户输入URL和KEY
            dialog = QDialog(self)
            dialog.setWindowTitle("配置其他AI模型")
            layout = QVBoxLayout(dialog)
            
            form_layout = QFormLayout()
            url_input = QLineEdit()
            url_input.setPlaceholderText("例如: https://api.example.com/v1/chat/completions")
            
            # 加载之前保存的URL
            saved_url = self.config_manager.get("api_urls", {}).get("other", "")
            if saved_url:
                url_input.setText(saved_url)
                
            form_layout.addRow("API URL:", url_input)
            
            key_input = QLineEdit()
            key_input.setEchoMode(QLineEdit.EchoMode.Password)
            key_input.setPlaceholderText("(选填) 如果需要的话")
            
            # 加载之前保存的API密钥
            saved_key = self.config_manager.get_api_key("other")
            if saved_key:
                key_input.setText(saved_key)
                
            form_layout.addRow("API 密钥:", key_input)
            
            timeout_spinbox = QSpinBox()
            timeout_spinbox.setRange(10, 600)
            
            # 加载之前保存的超时设置
            saved_timeout = self.config_manager.get("api_timeout", {}).get("other", 60)
            timeout_spinbox.setValue(saved_timeout)
            
            timeout_spinbox.setSuffix(" 秒")
            form_layout.addRow("超时时间:", timeout_spinbox)
            
            layout.addLayout(form_layout)
            
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addWidget(buttons)
            
            # 显示对话框
            if dialog.exec():
                # 用户点击了确定
                api_url = url_input.text().strip()
                api_key = key_input.text().strip()
                timeout = timeout_spinbox.value()
                
                if not api_url:
                    QMessageBox.warning(self, "警告", "请输入API URL")
                    # 恢复之前的选择
                    self.is_updating_provider = True
                    self.load_ai_providers()
                    self.is_updating_provider = False
                    return
                
                # 保存设置
                api_urls = self.config_manager.get("api_urls", {})
                api_urls["other"] = api_url
                self.config_manager.set("api_urls", api_urls)
                
                if api_key:
                    self.config_manager.set_api_key("other", api_key)
                
                # 保存超时设置
                api_timeout = self.config_manager.get("api_timeout", {})
                api_timeout["other"] = timeout
                self.config_manager.set("api_timeout", api_timeout)
                
                # 设置为当前服务商
                self.config_manager.set("ai_provider", "other")
            else:
                # 用户取消了，恢复之前的选择
                self.is_updating_provider = True
                self.load_ai_providers()
                self.is_updating_provider = False
    
    def update_ip_mapping_table(self):
        """更新IP映射表"""
        # 只有当表格可见时才更新
        if not self.ip_mapping_group.isVisible():
            return
            
        # 清空表格
        self.ip_mapping_table.setRowCount(0)
        
        # 获取IP映射
        mapping = self.ip_masker.get_mapping()
        
        # 填充表格
        for masked_ip, original_ip in mapping.items():
            row = self.ip_mapping_table.rowCount()
            self.ip_mapping_table.insertRow(row)
            self.ip_mapping_table.setItem(row, 0, QTableWidgetItem(masked_ip))
            self.ip_mapping_table.setItem(row, 1, QTableWidgetItem(original_ip))
        
        # 如果没有映射，显示提示行
        if self.ip_mapping_table.rowCount() == 0:
            self.ip_mapping_table.insertRow(0)
            self.ip_mapping_table.setItem(0, 0, QTableWidgetItem("(无IP映射)"))
            self.ip_mapping_table.setItem(0, 1, QTableWidgetItem(""))
    
    def update_ip_masking(self, checked):
        """切换IP掩码时更新显示"""
        # 保存配置
        self.config_manager.set("ip_mask_enabled", checked)
        
        # 如果有日志数据，重新加载预览
        if self.log_data is not None:
            self._update_log_preview()
    
    def _update_log_preview(self):
        """更新日志预览内容"""
        if self.log_data is None:
            return
            
        # 准备预览文本
        if 'raw_log' in self.log_data.columns:
            preview_text = ''.join(self.log_data['raw_log'].head(100).tolist())
        else:
            preview_rows = self.log_data.head(100)
            preview_text = preview_rows.to_string()
        
        # 如果启用了IP掩码，在UI中显示原始IP
        if self.mask_ip_checkbox.isChecked():
            # 先脱敏再显示原始，确保映射表更新
            masked_text = self.ip_masker.mask_text(preview_text)
            preview_text = self.ip_masker.unmask_text(masked_text)
        
        self.log_view.setText(preview_text)
        
        # 更新IP映射表
        self.update_ip_mapping_table()
    
    def load_file(self):
        """加载日志文件"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self, 
            "选择日志文件", 
            "", 
            "日志文件 (*.log *.txt *.csv);;所有文件 (*)"
        )
        
        if file_path:
            try:
                self.status_label.setText(f"正在加载文件: {os.path.basename(file_path)}")
                self.progress_bar.setVisible(True)
                
                # 使用线程加载大文件，避免UI卡顿
                self.load_thread = LoadFileThread(file_path, self.log_parser)
                self.load_thread.finished.connect(self._file_loaded)
                self.load_thread.error.connect(self._file_load_error)
                self.load_thread.start()
                
            except Exception as e:
                QMessageBox.critical(self, "错误", f"加载文件失败: {str(e)}")
                self.status_label.setText("加载失败")
                self.progress_bar.setVisible(False)
    
    def _file_loaded(self, file_path, log_data):
        """文件加载完成的回调"""
        self.current_file = file_path
        self.log_data = log_data
        
        # 更新UI
        self.current_file_label.setText(os.path.basename(file_path))
        
        # 更新日志预览
        self._update_log_preview()
        
        # 启用分析按钮
        self.analyze_btn.setEnabled(True)
        
        # 更新状态
        self.status_label.setText(f"已加载文件: {os.path.basename(file_path)}")
        self.progress_bar.setVisible(False)
        
        # 保存到最近文件列表
        recent_files = self.config_manager.get("recent_files", [])
        if file_path in recent_files:
            recent_files.remove(file_path)
        recent_files.insert(0, file_path)
        # 只保留最近的10个文件
        self.config_manager.set("recent_files", recent_files[:10])
    
    def _file_load_error(self, error_msg):
        """文件加载错误的回调"""
        QMessageBox.critical(self, "错误", f"加载文件失败: {error_msg}")
        self.status_label.setText("加载失败")
        self.progress_bar.setVisible(False)
    
    def analyze_logs(self):
        """分析日志"""
        # 获取告警内容
        alert_content = self.alert_edit.toPlainText().strip()
        
        # 检查是否有日志文件或告警信息
        if not self.current_file and not alert_content:
            QMessageBox.warning(self, "警告", "请先加载日志文件或输入告警信息")
            return
        
        # 提取上下文日志
        log_content = ""
        if self.log_data is not None and self.current_file:
            if 'raw_log' in self.log_data.columns:
                log_content = ''.join(self.log_data['raw_log'].head(100).tolist())
            else:
                log_content = self.log_data.head(100).to_string()
        
        # 是否需要脱敏
        if self.mask_ip_checkbox.isChecked():
            # 对发送给AI的内容进行脱敏
            if alert_content:
                alert_content = self.ip_masker.mask_text(alert_content)
            if log_content:
                log_content = self.ip_masker.mask_text(log_content)
            
            # 更新IP映射表
            self.update_ip_mapping_table()
        
        # 获取自定义提示词
        custom_prompt = None
        if self.current_prompt != "default":
            custom_prompt = self.config_manager.get_custom_prompt(self.current_prompt)
        
        # 获取AI提供商
        provider_name = self.ai_provider_combo.currentText()
        
        # 转换为内部标识符
        provider = ""
        if provider_name == "DeepSeek":
            provider = "deepseek"
        elif provider_name == "豆包":
            provider = "doubao"
        elif provider_name == "本地AI模型":
            provider = "local"
        elif provider_name == "其他AI模型":
            provider = "other"
        else:
            # 查找自定义API
            custom_apis = self.config_manager.get("custom_apis", {})
            for key, info in custom_apis.items():
                if info.get("name") == provider_name:
                    provider = key
                    break
        
        if not provider:
            QMessageBox.warning(self, "警告", f"无法识别的AI服务商: {provider_name}")
            return
        
        # 获取API密钥（对于本地AI，可以没有API密钥）
        api_key = self.config_manager.get_api_key(provider) if provider != "local" else ""
        
        if not api_key and provider != "local":
            QMessageBox.warning(
                self, 
                "API密钥未配置", 
                f"请在设置中配置{provider_name}的API密钥"
            )
            self.show_settings()
            return
        
        # 显示进度条
        self.status_label.setText("正在分析中...")
        self.progress_bar.setVisible(True)
        self.analyze_btn.setEnabled(False)
        
        # 在后台线程中执行分析
        self.analyze_thread = AnalyzeThread(provider, api_key, log_content, alert_content, self.config_manager, custom_prompt)
        self.analyze_thread.finished.connect(self._analysis_finished)
        self.analyze_thread.error.connect(self._analysis_error)
        self.analyze_thread.start()
    
    def _analysis_finished(self, result):
        """分析完成的回调"""
        # 恢复UI状态
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.status_label.setText("分析完成")
        
        # 格式化显示结果
        is_threat = result.get("is_threat", False)
        confidence = result.get("confidence", 0)
        analysis = result.get("analysis", "")
        recommendations = result.get("recommendations", "")
        
        # 是否需要转换IP显示
        if self.mask_ip_checkbox.isChecked():
            analysis = self.ip_masker.unmask_text(analysis)
            recommendations = self.ip_masker.unmask_text(recommendations)
        
        result_text = f"""
        <h2>安全分析结果</h2>
        <p><b>威胁评估:</b> {"<span style='color:red'>真实威胁</span>" if is_threat else "<span style='color:green'>未检测到威胁/误报</span>"}</p>
        <p><b>置信度:</b> {confidence}%</p>
        <h3>分析说明:</h3>
        <p>{analysis}</p>
        <h3>建议措施:</h3>
        <p>{recommendations}</p>
        """
        
        self.result_text.setHtml(result_text)
    
    def _analysis_error(self, error_msg):
        """分析错误的回调"""
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.status_label.setText("分析失败")
        QMessageBox.critical(self, "分析失败", f"分析过程发生错误: {error_msg}")
    
    def show_settings(self):
        """显示设置对话框"""
        dialog = SettingsDialog(self.config_manager)
        if dialog.exec():
            # 如果设置被保存，更新UI
            show_mapping = self.config_manager.get("show_ip_mapping", False)
            self.ip_mapping_group.setVisible(show_mapping)
            
            # 重新加载AI提供商
            self.load_ai_providers()
            
            # 更新IP掩码设置
            self.mask_ip_checkbox.setChecked(self.config_manager.get("ip_mask_enabled", True))
            
            # 如果有日志，更新预览
            if self.log_data is not None:
                self._update_log_preview()
    
    def show_prompt_menu(self):
        """显示提示词选择菜单"""
        menu = QMenu(self)
        
        # 获取所有提示词
        prompt_names = ["default"] + self.config_manager.get_all_custom_prompts()
        
        # 添加提示词选项
        for name in prompt_names:
            if name == "default":
                display_name = "默认提示词"
            else:
                display_name = name
                
            action = menu.addAction(display_name)
            action.setCheckable(True)
            action.setChecked(name == self.current_prompt)
            
            # 使用lambda防止循环变量问题
            action.triggered.connect(lambda checked, n=name: self.select_prompt(n))
        
        menu.addSeparator()
        
        # 添加管理提示词菜单项
        manage_action = menu.addAction("管理提示词...")
        manage_action.triggered.connect(self.manage_prompts)
        
        # 显示菜单
        menu.exec(self.prompt_btn.mapToGlobal(self.prompt_btn.rect().bottomLeft()))
    
    def select_prompt(self, name):
        """选择提示词
        
        Args:
            name: 提示词名称
        """
        self.current_prompt = name
        self.config_manager.set("selected_prompt", name)
        
        # 更新按钮文本
        if name == "default":
            self.prompt_btn.setText("提示词")
        else:
            self.prompt_btn.setText(f"提示词: {name}")
    
    def manage_prompts(self):
        """打开提示词管理对话框"""
        dialog = SettingsDialog(self.config_manager)
        # 切换到提示词设置选项卡
        dialog.tabWidget = dialog.findChild(QTabWidget)
        if dialog.tabWidget:
            for i in range(dialog.tabWidget.count()):
                if dialog.tabWidget.tabText(i) == "提示词设置":
                    dialog.tabWidget.setCurrentIndex(i)
                    break
        
        if dialog.exec():
            # 重新加载提示词
            self.current_prompt = self.config_manager.get("selected_prompt", "default")
            # 更新按钮文本
            if self.current_prompt == "default":
                self.prompt_btn.setText("提示词")
            else:
                self.prompt_btn.setText(f"提示词: {self.current_prompt}")
    
    def clear_data(self):
        """清除当前加载的日志文件和告警信息"""
        if not self.current_file and not self.alert_edit.toPlainText().strip() and self.log_data is None:
            # 如果没有数据需要清除，直接返回
            return
            
        # 清除当前文件信息
        self.current_file = None
        self.current_file_label.setText("未加载文件")
        
        # 清除日志数据
        self.log_data = None
        self.log_view.clear()
        
        # 清除告警信息
        self.alert_edit.clear()
        
        # 清除分析结果
        self.result_text.clear()
        
        # 保持分析按钮启用，允许用户只输入告警信息进行分析
        self.analyze_btn.setEnabled(True)
        
        # 清除IP映射表
        self.ip_mapping_table.setRowCount(0)
        
        # 更新状态
        self.status_label.setText("数据已清除")
        
        # 显示成功消息
        QMessageBox.information(self, "已清除", "所有日志文件和告警信息已清除")


class LoadFileThread(QThread):
    """文件加载线程"""
    
    finished = pyqtSignal(str, object)  # 成功信号: 文件路径, 日志数据
    error = pyqtSignal(str)             # 错误信号: 错误消息
    
    def __init__(self, file_path, log_parser):
        super().__init__()
        self.file_path = file_path
        self.log_parser = log_parser
    
    def run(self):
        try:
            log_data = self.log_parser.parse_file(self.file_path)
            self.finished.emit(self.file_path, log_data)
        except Exception as e:
            self.error.emit(str(e))


class AnalyzeThread(QThread):
    """日志分析线程"""
    
    finished = pyqtSignal(dict)  # 成功信号: 分析结果
    error = pyqtSignal(str)      # 错误信号: 错误消息
    
    def __init__(self, provider, api_key, log_content, alert_content=None, config_manager=None, custom_prompt=None):
        super().__init__()
        self.provider = provider
        self.api_key = api_key
        self.log_content = log_content
        self.alert_content = alert_content
        self.config_manager = config_manager
        self.custom_prompt = custom_prompt
    
    def run(self):
        try:
            # 创建AI服务
            ai_service = AIServiceFactory.create_service(self.provider, self.api_key, self.config_manager)
            
            # 分析日志
            result = ai_service.analyze_log(self.log_content, self.alert_content, self.custom_prompt)
            
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e)) 