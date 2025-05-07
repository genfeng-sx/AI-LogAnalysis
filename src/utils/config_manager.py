#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import dotenv
from pathlib import Path
import socket

class ConfigManager:
    """配置管理器，负责存储和加载用户配置"""
    
    def __init__(self):
        """初始化配置管理器"""
        self.config_dir = os.path.join(os.path.expanduser("~"), ".ai_log_analyzer")
        self.config_file = os.path.join(self.config_dir, "config.json")
        self.env_file = os.path.join(self.config_dir, ".env")
        self.prompt_dir = os.path.join(self.config_dir, "prompts")
        
        # 确保配置目录和提示词目录存在
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
            
        if not os.path.exists(self.prompt_dir):
            os.makedirs(self.prompt_dir)
        
        # 加载配置
        self.config = self.load_config()
        
        # 加载环境变量（API密钥等）
        if os.path.exists(self.env_file):
            dotenv.load_dotenv(self.env_file, override=True)
    
    def load_config(self):
        """加载配置文件"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"加载配置文件失败: {e}")
                return self.get_default_config()
        else:
            return self.get_default_config()
    
    def save_config(self):
        """保存配置到文件"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"保存配置文件失败: {e}")
            return False
    
    def get_default_config(self):
        """获取默认配置"""
        # 检查常用的本地AI模型端口是否可访问
        def is_port_open(port):
            """检查指定端口是否开放"""
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                s.connect(('127.0.0.1', port))
                s.close()
                return True
            except:
                return False
        
        # 检测本地模型并设置默认URL
        local_ai_url = "http://localhost:1234/v1/chat/completions"  # 默认OpenAI格式
        
        # 检查LM Studio（默认端口1234）
        if is_port_open(1234):
            try:
                import requests
                # 尝试连接LM Studio API
                response = requests.get("http://localhost:1234/", timeout=1)
                if response.status_code == 200 and "LM Studio" in response.text:
                    local_ai_url = "http://localhost:1234/api/chat"  # LM Studio使用/api/chat
                    print("检测到LM Studio，已自动配置为LM Studio API格式。")
            except Exception as e:
                # 端口开放但不一定是LM Studio
                print(f"检测到端口1234开放，但未能确认是否为LM Studio: {str(e)}")
        
        # 构建默认配置
        return {
            "ai_provider": "deepseek",  # 默认AI服务商
            "theme": "system",          # 系统主题（跟随系统）
            "max_log_size": 10,         # 最大日志大小（MB）
            "recent_files": [],         # 最近打开的文件
            "ip_mask_enabled": True,    # IP掩码功能默认开启
            "show_ip_mapping": False,   # 是否在界面显示IP映射表
            "api_urls": {               # API URL配置
                "deepseek": "https://api.deepseek.com/v1/chat/completions",
                "doubao": "https://api.doubao.com/v1/chat/completions",
                "local": local_ai_url   # 自动检测的本地模型URL
            },
            "api_timeout": {            # API超时配置（秒）
                "deepseek": 60,
                "doubao": 60,
                "local": 180            # 本地模型默认更长的超时时间
            },
            "custom_apis": {},          # 自定义API配置
            "custom_prompts": {},       # 自定义提示词配置
            "selected_prompt": "default" # 当前选择的提示词
        }
    
    def set_api_key(self, provider, api_key):
        """设置API密钥"""
        # 使用环境变量文件存储敏感信息
        env_vars = {}
        if os.path.exists(self.env_file):
            try:
                with open(self.env_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            env_vars[key] = value
            except Exception as e:
                print(f"读取环境变量文件失败: {e}")
        
        env_key = f"{provider.upper()}_API_KEY"
        env_vars[env_key] = api_key
        
        try:
            with open(self.env_file, 'w', encoding='utf-8') as f:
                for key, value in env_vars.items():
                    f.write(f"{key}={value}\n")
            
            # 立即将API密钥设置到环境中，确保当前会话可用
            os.environ[env_key] = api_key
            
        except Exception as e:
            print(f"保存环境变量文件失败: {e}")
    
    def get_api_key(self, provider):
        """获取指定服务商的API密钥"""
        env_key = f"{provider.upper()}_API_KEY"
        
        # 首先尝试从当前环境中获取
        api_key = os.environ.get(env_key, "")
        
        # 如果当前环境中没有，尝试重新加载.env文件
        if not api_key and os.path.exists(self.env_file):
            dotenv.load_dotenv(self.env_file, override=True)
            api_key = os.environ.get(env_key, "")
            
        return api_key
    
    def get_api_url(self, provider):
        """获取指定服务商的API URL"""
        api_urls = self.get("api_urls", {})
        return api_urls.get(provider, "")
    
    def get_api_timeout(self, provider):
        """获取指定服务商的API超时时间"""
        api_timeout = self.get("api_timeout", {})
        if provider == "local":
            return api_timeout.get(provider, 180)  # 本地模型默认180秒
        return api_timeout.get(provider, 60)  # 其他默认60秒
    
    def get_provider_name(self, provider):
        """获取服务商显示名称"""
        if provider == "deepseek":
            return "DeepSeek"
        elif provider == "doubao":
            return "豆包"
        elif provider == "local":
            return "本地AI模型"
        elif provider == "other":
            return "其他AI模型"
        elif provider.startswith("custom_"):
            custom_apis = self.get("custom_apis", {})
            if provider in custom_apis:
                return custom_apis[provider].get("name", provider)
        return provider
    
    def get_custom_prompt(self, name="default"):
        """获取自定义提示词
        
        Args:
            name: 提示词名称
            
        Returns:
            提示词内容
        """
        custom_prompts = self.get("custom_prompts", {})
        if name in custom_prompts:
            return custom_prompts[name]
        
        # 尝试从文件读取
        prompt_file = os.path.join(self.prompt_dir, f"{name}.txt")
        if os.path.exists(prompt_file):
            try:
                with open(prompt_file, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                print(f"读取提示词文件失败: {e}")
        
        # 返回空值
        return None
    
    def save_custom_prompt(self, name, content):
        """保存自定义提示词
        
        Args:
            name: 提示词名称
            content: 提示词内容
            
        Returns:
            是否保存成功
        """
        # 将提示词保存到配置
        custom_prompts = self.get("custom_prompts", {})
        custom_prompts[name] = content
        self.set("custom_prompts", custom_prompts)
        
        # 同时保存到文件
        prompt_file = os.path.join(self.prompt_dir, f"{name}.txt")
        try:
            with open(prompt_file, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"保存提示词文件失败: {e}")
            return False
    
    def get_all_custom_prompts(self):
        """获取所有自定义提示词
        
        Returns:
            提示词名称列表
        """
        # 从配置获取
        custom_prompts = self.get("custom_prompts", {})
        prompt_names = list(custom_prompts.keys())
        
        # 从文件获取
        for file in os.listdir(self.prompt_dir):
            if file.endswith(".txt"):
                name = file[:-4]  # 去掉.txt后缀
                if name not in prompt_names:
                    prompt_names.append(name)
        
        return prompt_names
    
    def get(self, key, default=None):
        """获取配置项"""
        return self.config.get(key, default)
    
    def set(self, key, value):
        """设置配置项"""
        self.config[key] = value
        self.save_config() 