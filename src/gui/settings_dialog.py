#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QCheckBox, QTabWidget, QWidget, QGroupBox,
    QFormLayout, QSpinBox, QComboBox, QDialogButtonBox,
    QFileDialog, QMessageBox, QScrollArea, QTextEdit,
    QListWidget, QListWidgetItem, QInputDialog, QAbstractItemView
)
from PyQt6.QtCore import Qt, QSettings

class APIServiceWidget(QWidget):
    """API服务配置小部件"""
    
    def __init__(self, name, parent=None):
        super().__init__(parent)
        self.name = name
        
        layout = QFormLayout(self)
        
        self.url_input = QLineEdit()
        layout.addRow("API URL:", self.url_input)
        
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("API 密钥:", self.key_input)
        
        self.timeout_spinbox = QSpinBox()
        self.timeout_spinbox.setRange(10, 600)  # 10秒到10分钟
        self.timeout_spinbox.setValue(60)       # 默认60秒
        self.timeout_spinbox.setSuffix(" 秒")
        layout.addRow("超时时间:", self.timeout_spinbox)

class SettingsDialog(QDialog):
    """设置对话框"""
    
    def __init__(self, config_manager, parent=None):
        """初始化设置对话框
        
        Args:
            config_manager: 配置管理器实例
            parent: 父窗口
        """
        super().__init__(parent)
        
        self.config_manager = config_manager
        self.api_services = {}  # 存储API服务小部件
        
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        """初始化用户界面"""
        # 设置窗口标题和大小
        self.setWindowTitle("设置")
        self.resize(600, 500)
        
        # 创建主布局
        main_layout = QVBoxLayout(self)
        
        # 创建选项卡
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)
        
        # 创建通用设置选项卡
        general_tab = QWidget()
        tab_widget.addTab(general_tab, "通用设置")
        
        # 通用设置布局
        general_layout = QVBoxLayout(general_tab)
        
        # 通用选项组
        general_group = QGroupBox("基本选项")
        general_form = QFormLayout(general_group)
        
        # AI服务商选择
        self.ai_provider_combo = QComboBox()
        self.ai_provider_combo.addItems(["DeepSeek", "豆包", "本地AI模型", "其他AI模型", "自定义"])
        general_form.addRow("默认AI服务商:", self.ai_provider_combo)
        
        # 主题选择
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["系统", "亮色", "暗色"])
        general_form.addRow("主题:", self.theme_combo)
        
        # 最大日志大小
        self.max_log_size_spinbox = QSpinBox()
        self.max_log_size_spinbox.setRange(1, 100)
        self.max_log_size_spinbox.setSuffix(" MB")
        general_form.addRow("最大日志大小:", self.max_log_size_spinbox)
        
        # IP掩码设置
        ip_mask_section = QGroupBox("IP掩码设置")
        ip_mask_layout = QVBoxLayout(ip_mask_section)
        
        # IP掩码启用选项
        self.ip_mask_checkbox = QCheckBox("启用IP掩码")
        self.ip_mask_checkbox.setChecked(self.config_manager.get("ip_mask_enabled", True))
        ip_mask_layout.addWidget(self.ip_mask_checkbox)
        
        # 显示IP映射表选项
        self.show_mapping_checkbox = QCheckBox("在界面中显示IP映射表")
        self.show_mapping_checkbox.setChecked(self.config_manager.get("show_ip_mapping", False))
        ip_mask_layout.addWidget(self.show_mapping_checkbox)
        
        # 最大IP映射数量设置
        max_mapping_layout = QHBoxLayout()
        max_mapping_layout.addWidget(QLabel("最大IP映射数量:"))
        self.max_ip_mappings_spinbox = QSpinBox()
        self.max_ip_mappings_spinbox.setRange(100, 10000)
        self.max_ip_mappings_spinbox.setSingleStep(100)
        self.max_ip_mappings_spinbox.setValue(self.config_manager.get("max_ip_mappings", 500))
        self.max_ip_mappings_spinbox.setToolTip("设置IP映射表的最大条目数，超过此数量将删除最旧的映射")
        max_mapping_layout.addWidget(self.max_ip_mappings_spinbox)
        ip_mask_layout.addLayout(max_mapping_layout)
        
        # 添加说明
        ip_explanation = QLabel("IP掩码功能可以保护日志中的IP地址，在分析时自动替换为私有IP地址。")
        ip_explanation.setWordWrap(True)
        ip_mask_layout.addWidget(ip_explanation)
        
        general_layout.addWidget(ip_mask_section)
        
        general_layout.addWidget(general_group)
        
        # API设置选项卡
        api_tab = QScrollArea()
        api_tab.setWidgetResizable(True)
        tab_widget.addTab(api_tab, "API设置")
        
        # API设置布局
        api_content = QWidget()
        api_layout = QVBoxLayout(api_content)
        api_tab.setWidget(api_content)
        
        # 预定义的API服务
        # DeepSeek API设置
        self.add_api_service("deepseek", "DeepSeek API设置", api_layout)
        
        # 豆包API设置
        self.add_api_service("doubao", "豆包 API设置", api_layout)
        
        # 本地AI模型设置
        self.add_api_service("local", "本地AI模型设置", api_layout)
        
        # 其他AI模型设置
        self.add_api_service("other", "其他AI模型设置", api_layout)
        
        # 添加自定义API按钮
        add_custom_api_layout = QHBoxLayout()
        self.custom_api_name = QLineEdit()
        self.custom_api_name.setPlaceholderText("自定义API名称")
        add_custom_api_layout.addWidget(self.custom_api_name)
        
        add_api_btn = QPushButton("添加")
        add_api_btn.clicked.connect(self.add_custom_api)
        add_custom_api_layout.addWidget(add_api_btn)
        
        api_layout.addLayout(add_custom_api_layout)
        
        # 自定义API服务组
        self.custom_api_group = QGroupBox("自定义API服务")
        self.custom_api_layout = QVBoxLayout(self.custom_api_group)
        api_layout.addWidget(self.custom_api_group)
        
        # 加载已保存的自定义API
        self.load_custom_apis()
        
        # 添加一个弹性空间
        api_layout.addStretch()
        
        # 提示词设置选项卡
        prompt_tab = QWidget()
        tab_widget.addTab(prompt_tab, "提示词设置")
        
        # 提示词设置布局
        prompt_layout = QVBoxLayout(prompt_tab)
        
        # 提示词管理组
        prompt_manage_group = QGroupBox("提示词管理")
        prompt_manage_layout = QHBoxLayout(prompt_manage_group)
        
        # 左侧提示词列表
        prompt_list_layout = QVBoxLayout()
        prompt_list_label = QLabel("提示词列表:")
        prompt_list_layout.addWidget(prompt_list_label)
        
        self.prompt_list = QListWidget()
        self.prompt_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.prompt_list.currentRowChanged.connect(self.prompt_selected)
        prompt_list_layout.addWidget(self.prompt_list)
        
        prompt_btn_layout = QHBoxLayout()
        
        add_prompt_btn = QPushButton("添加")
        add_prompt_btn.clicked.connect(self.add_prompt)
        prompt_btn_layout.addWidget(add_prompt_btn)
        
        rename_prompt_btn = QPushButton("重命名")
        rename_prompt_btn.clicked.connect(self.rename_prompt)
        prompt_btn_layout.addWidget(rename_prompt_btn)
        
        delete_prompt_btn = QPushButton("删除")
        delete_prompt_btn.clicked.connect(self.delete_prompt)
        prompt_btn_layout.addWidget(delete_prompt_btn)
        
        prompt_list_layout.addLayout(prompt_btn_layout)
        prompt_manage_layout.addLayout(prompt_list_layout)
        
        # 右侧提示词编辑
        prompt_edit_layout = QVBoxLayout()
        prompt_edit_label = QLabel("提示词内容:")
        prompt_edit_layout.addWidget(prompt_edit_label)
        
        self.prompt_edit = QTextEdit()
        self.prompt_edit.setPlaceholderText("""在此编辑提示词内容，可以使用以下占位符：
{log_content} - 日志内容
{alert_content} - 告警内容（如果有）""")
        prompt_edit_layout.addWidget(self.prompt_edit)
        
        save_prompt_btn = QPushButton("保存")
        save_prompt_btn.clicked.connect(self.save_prompt)
        prompt_edit_layout.addWidget(save_prompt_btn)
        
        prompt_manage_layout.addLayout(prompt_edit_layout)
        
        prompt_layout.addWidget(prompt_manage_group)
        
        # 关于选项卡
        about_tab = QWidget()
        tab_widget.addTab(about_tab, "关于")
        
        # 关于布局
        about_layout = QVBoxLayout(about_tab)
        
        about_text = """
        <h2>AI安全日志分析工具</h2>
        <p>版本: 1.0.0</p>
        <p>这是一个使用AI技术分析网络安全日志的跨平台应用程序。</p>
        <p>支持多种日志格式，提供安全告警评估和置信度分析。</p>
        <p>&copy; 2025 sx</p>
        """
        
        about_label = QLabel(about_text)
        about_label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)
        about_layout.addWidget(about_label)
        
        # 按钮区域
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.save_settings)
        button_box.rejected.connect(self.reject)
        main_layout.addWidget(button_box)
    
    def add_api_service(self, key, title, parent_layout):
        """添加API服务配置区域"""
        group = QGroupBox(title)
        form = QFormLayout(group)
        
        url_input = QLineEdit()
        form.addRow("API URL:", url_input)
        
        key_input = QLineEdit()
        key_input.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("API 密钥:", key_input)
        
        # 超时设置
        timeout_spinbox = QSpinBox()
        timeout_spinbox.setRange(10, 600)  # 10秒到10分钟
        timeout_spinbox.setValue(60)       # 默认60秒
        timeout_spinbox.setSuffix(" 秒")
        form.addRow("超时时间:", timeout_spinbox)
        
        # 对于本地AI模型，添加提示但不禁用API密钥
        if key == "local":
            key_input.setPlaceholderText("(选填) 本地模型可能需要API密钥")
            url_input.setPlaceholderText("请输入完整URL，包括端口号，例如: http://localhost:1234/v1/chat/completions")
            timeout_spinbox.setValue(180)  # 本地模型默认180秒
        elif key == "other":
            url_input.setPlaceholderText("请输入完整URL，包括端口号，例如: http://api.example.com:8080/v1/chat/completions")
        
        parent_layout.addWidget(group)
        
        self.api_services[key] = {
            "group": group,
            "url": url_input,
            "key": key_input,
            "timeout": timeout_spinbox
        }
    
    def add_custom_api(self):
        """添加自定义API服务"""
        name = self.custom_api_name.text().strip()
        if not name:
            QMessageBox.warning(self, "警告", "请输入API名称")
            return
        
        # 生成一个唯一的键
        key = f"custom_{name.lower().replace(' ', '_')}"
        
        if key in self.api_services:
            QMessageBox.warning(self, "警告", f"API '{name}' 已存在")
            return
        
        # 创建API服务小部件
        api_widget = APIServiceWidget(name)
        self.custom_api_layout.addWidget(api_widget)
        
        # 保存到服务列表
        self.api_services[key] = {
            "widget": api_widget,
            "url": api_widget.url_input,
            "key": api_widget.key_input,
            "timeout": api_widget.timeout_spinbox,
            "custom": True,
            "name": name
        }
        
        # 更新AI提供商下拉列表
        current_items = [self.ai_provider_combo.itemText(i) for i in range(self.ai_provider_combo.count())]
        if name not in current_items:
            self.ai_provider_combo.addItem(name)
        
        # 清空输入框
        self.custom_api_name.clear()
    
    def load_custom_apis(self):
        """加载已保存的自定义API"""
        custom_apis = self.config_manager.get("custom_apis", {})
        
        for key, info in custom_apis.items():
            api_widget = APIServiceWidget(info["name"])
            api_widget.url_input.setText(info.get("url", ""))
            
            # 设置超时时间
            timeout = self.config_manager.get("api_timeout", {}).get(key, 60)
            api_widget.timeout_spinbox.setValue(timeout)
            
            self.custom_api_layout.addWidget(api_widget)
            
            self.api_services[key] = {
                "widget": api_widget,
                "url": api_widget.url_input,
                "key": api_widget.key_input,
                "timeout": api_widget.timeout_spinbox,
                "custom": True,
                "name": info["name"]
            }
            
            # 更新AI提供商下拉列表
            self.ai_provider_combo.addItem(info["name"])
    
    def load_settings(self):
        """从配置管理器加载设置"""
        # 通用设置
        provider = self.config_manager.get("ai_provider", "deepseek")
        
        # 支持自定义提供商
        custom_apis = self.config_manager.get("custom_apis", {})
        
        if provider == "deepseek":
            self.ai_provider_combo.setCurrentText("DeepSeek")
        elif provider == "doubao":
            self.ai_provider_combo.setCurrentText("豆包")
        elif provider == "local":
            self.ai_provider_combo.setCurrentText("本地AI模型")
        elif provider == "other":
            self.ai_provider_combo.setCurrentText("其他AI模型")
        elif provider.startswith("custom_") and provider in custom_apis:
            self.ai_provider_combo.setCurrentText(custom_apis[provider]["name"])
        
        theme = self.config_manager.get("theme", "system")
        if theme == "system":
            self.theme_combo.setCurrentText("系统")
        elif theme == "light":
            self.theme_combo.setCurrentText("亮色")
        else:
            self.theme_combo.setCurrentText("暗色")
        
        self.max_log_size_spinbox.setValue(self.config_manager.get("max_log_size", 10))
        self.ip_mask_checkbox.setChecked(self.config_manager.get("ip_mask_enabled", True))
        self.show_mapping_checkbox.setChecked(self.config_manager.get("show_ip_mapping", False))
        self.max_ip_mappings_spinbox.setValue(self.config_manager.get("max_ip_mappings", 500))
        
        # API设置
        if "deepseek" in self.api_services:
            self.api_services["deepseek"]["url"].setText(
                self.config_manager.get("api_urls", {}).get("deepseek", "https://api.deepseek.com/v1/chat/completions")
            )
            self.api_services["deepseek"]["key"].setText(self.config_manager.get_api_key("deepseek"))
            self.api_services["deepseek"]["timeout"].setValue(self.config_manager.get("api_timeout", {}).get("deepseek", 60))
        
        if "doubao" in self.api_services:
            self.api_services["doubao"]["url"].setText(
                self.config_manager.get("api_urls", {}).get("doubao", "https://api.doubao.com/v1/chat/completions")
            )
            self.api_services["doubao"]["key"].setText(self.config_manager.get_api_key("doubao"))
            self.api_services["doubao"]["timeout"].setValue(self.config_manager.get("api_timeout", {}).get("doubao", 60))
        
        if "local" in self.api_services:
            self.api_services["local"]["url"].setText(
                self.config_manager.get("api_urls", {}).get("local", "http://localhost:1234/v1/chat/completions")
            )
            self.api_services["local"]["timeout"].setValue(self.config_manager.get("api_timeout", {}).get("local", 180))
        
        if "other" in self.api_services:
            self.api_services["other"]["url"].setText(
                self.config_manager.get("api_urls", {}).get("other", "")
            )
            self.api_services["other"]["key"].setText(self.config_manager.get_api_key("other"))
            self.api_services["other"]["timeout"].setValue(self.config_manager.get("api_timeout", {}).get("other", 60))
        
        # 加载自定义API的key
        for key in self.api_services:
            if key.startswith("custom_") and "key" in self.api_services[key]:
                self.api_services[key]["key"].setText(self.config_manager.get_api_key(key))
                if "timeout" in self.api_services[key]:
                    self.api_services[key]["timeout"].setValue(self.config_manager.get("api_timeout", {}).get(key, 60))
        
        # 加载提示词列表
        self.load_prompts()
    
    def save_settings(self):
        """保存设置到配置管理器"""
        # 通用设置
        provider_text = self.ai_provider_combo.currentText()
        
        if provider_text == "DeepSeek":
            provider = "deepseek"
        elif provider_text == "豆包":
            provider = "doubao"
        elif provider_text == "本地AI模型":
            provider = "local"
        elif provider_text == "其他AI模型":
            provider = "other"
        else:
            # 查找自定义API
            for key, info in self.api_services.items():
                if key.startswith("custom_") and info.get("name") == provider_text:
                    provider = key
                    break
            else:
                provider = "deepseek"  # 默认
        
        self.config_manager.set("ai_provider", provider)
        
        theme_text = self.theme_combo.currentText()
        if theme_text == "系统":
            self.config_manager.set("theme", "system")
        elif theme_text == "亮色":
            self.config_manager.set("theme", "light")
        else:
            self.config_manager.set("theme", "dark")
        
        # 保存一般设置
        self.config_manager.set("max_log_size", self.max_log_size_spinbox.value())
        self.config_manager.set("ip_mask_enabled", self.ip_mask_checkbox.isChecked())
        self.config_manager.set("show_ip_mapping", self.show_mapping_checkbox.isChecked())
        self.config_manager.set("max_ip_mappings", self.max_ip_mappings_spinbox.value())
        
        # API设置
        api_urls = self.config_manager.get("api_urls", {})
        api_timeout = self.config_manager.get("api_timeout", {})
        custom_apis = {}
        
        # 保存API服务设置
        for key, info in self.api_services.items():
            # 保存URL和超时设置
            if not key.startswith("custom_"):
                api_urls[key] = info["url"].text()
                api_timeout[key] = info["timeout"].value()
                
                # 本地模型不需要API密钥
                if key != "local":
                    self.config_manager.set_api_key(key, info["key"].text())
            elif key.startswith("custom_") and info.get("custom"):
                custom_apis[key] = {
                    "name": info["name"],
                    "url": info["url"].text()
                }
                api_urls[key] = info["url"].text()
                api_timeout[key] = info["timeout"].value()
                self.config_manager.set_api_key(key, info["key"].text())
        
        self.config_manager.set("api_urls", api_urls)
        self.config_manager.set("api_timeout", api_timeout)
        self.config_manager.set("custom_apis", custom_apis)
        
        # 关闭对话框
        self.accept()
    
    def load_prompts(self):
        """加载提示词列表"""
        self.prompt_list.clear()
        
        # 添加默认提示词
        self.prompt_list.addItem("default (默认)")
        
        # 获取所有自定义提示词
        prompt_names = self.config_manager.get_all_custom_prompts()
        for name in prompt_names:
            if name != "default":  # 跳过默认提示词
                self.prompt_list.addItem(name)
        
        # 选择当前使用的提示词
        selected_prompt = self.config_manager.get("selected_prompt", "default")
        for i in range(self.prompt_list.count()):
            item_text = self.prompt_list.item(i).text()
            if item_text.startswith(selected_prompt):
                self.prompt_list.setCurrentRow(i)
                break
    
    def prompt_selected(self, row):
        """当选择提示词时的处理"""
        if row < 0:
            return
            
        item_text = self.prompt_list.item(row).text()
        prompt_name = item_text.split(" ")[0]  # 获取提示词名称
        
        # 加载提示词内容
        prompt_content = self.config_manager.get_custom_prompt(prompt_name)
        if prompt_content:
            self.prompt_edit.setText(prompt_content)
        else:
            # 默认提示词模板
            if prompt_name == "default":
                default_prompt = """你是一位网络安全分析专家，请仔细分析以下安全日志和告警信息，并给出专业评估：

## 安全告警内容：
{alert_content}

## 相关日志内容：
{log_content}

请基于以上信息，评估这是真实威胁还是误报，并给出置信度评分（0-100分）和详细分析。
如果是误报，请详细说明判断理由。
如果是真实威胁，请说明威胁类型和建议的处理措施。

回复必须使用JSON格式：
{"is_threat": true/false, "confidence": 0-100, "analysis": "分析说明", "recommendations": "建议措施"}"""
                self.prompt_edit.setText(default_prompt)
            else:
                self.prompt_edit.clear()
    
    def add_prompt(self):
        """添加新提示词"""
        name, ok = QInputDialog.getText(self, "添加提示词", "请输入提示词名称:")
        if ok and name:
            # 检查是否已存在
            for i in range(self.prompt_list.count()):
                if self.prompt_list.item(i).text().startswith(name):
                    QMessageBox.warning(self, "警告", f"提示词 '{name}' 已存在")
                    return
            
            # 添加到列表
            self.prompt_list.addItem(name)
            self.prompt_list.setCurrentRow(self.prompt_list.count() - 1)
            
            # 创建默认内容
            default_content = """你是一位网络安全分析专家，请仔细分析以下日志，并给出专业评估：

## 日志内容：
{log_content}

请基于以上信息，评估这是否包含安全威胁，并给出置信度评分（0-100分）和详细分析。
如果没有威胁，请详细说明判断理由。
如果存在威胁，请说明威胁类型和建议的处理措施。

回复必须使用JSON格式：
{"is_threat": true/false, "confidence": 0-100, "analysis": "分析说明", "recommendations": "建议措施"}"""
            
            self.prompt_edit.setText(default_content)
            self.save_prompt()
    
    def rename_prompt(self):
        """重命名提示词"""
        current_row = self.prompt_list.currentRow()
        if current_row < 0:
            return
            
        # 不允许重命名默认提示词
        item_text = self.prompt_list.item(current_row).text()
        if item_text.startswith("default"):
            QMessageBox.warning(self, "警告", "不能重命名默认提示词")
            return
        
        old_name = item_text.split(" ")[0]
        new_name, ok = QInputDialog.getText(self, "重命名提示词", "请输入新名称:", text=old_name)
        
        if ok and new_name and new_name != old_name:
            # 检查是否已存在
            for i in range(self.prompt_list.count()):
                if i != current_row and self.prompt_list.item(i).text().startswith(new_name):
                    QMessageBox.warning(self, "警告", f"提示词 '{new_name}' 已存在")
                    return
            
            # 保存当前内容到新名称
            content = self.prompt_edit.toPlainText()
            self.config_manager.save_custom_prompt(new_name, content)
            
            # 删除旧提示词
            custom_prompts = self.config_manager.get("custom_prompts", {})
            if old_name in custom_prompts:
                del custom_prompts[old_name]
                self.config_manager.set("custom_prompts", custom_prompts)
            
            # 更新列表
            self.prompt_list.item(current_row).setText(new_name)
            
            # 如果当前选中的是被重命名的提示词，更新选择
            if self.config_manager.get("selected_prompt") == old_name:
                self.config_manager.set("selected_prompt", new_name)
    
    def delete_prompt(self):
        """删除提示词"""
        current_row = self.prompt_list.currentRow()
        if current_row < 0:
            return
            
        # 不允许删除默认提示词
        item_text = self.prompt_list.item(current_row).text()
        if item_text.startswith("default"):
            QMessageBox.warning(self, "警告", "不能删除默认提示词")
            return
        
        prompt_name = item_text.split(" ")[0]
        reply = QMessageBox.question(self, "确认删除", f"确定要删除提示词 '{prompt_name}' 吗？",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            # 从配置中删除
            custom_prompts = self.config_manager.get("custom_prompts", {})
            if prompt_name in custom_prompts:
                del custom_prompts[prompt_name]
                self.config_manager.set("custom_prompts", custom_prompts)
            
            # 尝试删除文件
            import os
            prompt_file = os.path.join(self.config_manager.prompt_dir, f"{prompt_name}.txt")
            if os.path.exists(prompt_file):
                try:
                    os.remove(prompt_file)
                except Exception as e:
                    print(f"删除提示词文件失败: {e}")
            
            # 从列表中删除
            self.prompt_list.takeItem(current_row)
            
            # 如果当前选中的是被删除的提示词，切换到默认提示词
            if self.config_manager.get("selected_prompt") == prompt_name:
                self.config_manager.set("selected_prompt", "default")
                # 选择默认提示词
                for i in range(self.prompt_list.count()):
                    if self.prompt_list.item(i).text().startswith("default"):
                        self.prompt_list.setCurrentRow(i)
                        break
    
    def save_prompt(self):
        """保存当前编辑的提示词"""
        current_row = self.prompt_list.currentRow()
        if current_row < 0:
            return
            
        item_text = self.prompt_list.item(current_row).text()
        prompt_name = item_text.split(" ")[0]
        content = self.prompt_edit.toPlainText()
        
        # 保存提示词
        self.config_manager.save_custom_prompt(prompt_name, content)
        
        QMessageBox.information(self, "保存成功", f"提示词 '{prompt_name}' 已保存") 