#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import requests
import re
from abc import ABC, abstractmethod

class AIServiceBase(ABC):
    """AI服务基类"""
    
    @abstractmethod
    def analyze_log(self, log_content, alert_content=None, custom_prompt=None):
        """分析日志内容
        
        Args:
            log_content: 日志内容
            alert_content: 告警内容（可选）
            custom_prompt: 自定义提示词（可选）
            
        Returns:
            分析结果字典，包含以下字段：
            - is_threat: 是否为真实威胁
            - confidence: 置信度（0-100）
            - analysis: 分析说明
            - recommendations: 建议措施
        """
        pass

class GenericAIService(AIServiceBase):
    """通用AI服务"""
    
    def __init__(self, api_key, api_url, timeout=60):
        """初始化通用AI服务
        
        Args:
            api_key: API密钥
            api_url: API URL
            timeout: 超时时间（秒）
        """
        self.api_key = api_key
        self.api_url = api_url
        self.timeout = timeout
    
    def _build_prompt(self, log_content, alert_content=None, custom_prompt=None):
        """构建提示信息
        
        Args:
            log_content: 日志内容
            alert_content: 告警内容（可选）
            custom_prompt: 自定义提示词（可选）
            
        Returns:
            提示信息
        """
        if custom_prompt:
            # 使用自定义提示词，替换占位符
            prompt = custom_prompt.replace("{log_content}", log_content or "")
            if alert_content:
                prompt = prompt.replace("{alert_content}", alert_content)
            return prompt
        
        # 使用默认提示词
        if alert_content and log_content:
            # 同时有告警内容和日志内容
            return f"""
            你是一位网络安全分析专家，请仔细分析以下安全日志和告警信息，并给出专业评估：
            
            ## 安全告警内容：
            {alert_content}
            
            ## 相关日志内容：
            {log_content}
            
            请基于以上信息，评估这是真实威胁还是误报，并给出置信度评分（0-100分）和详细分析。
            如果是误报，请详细说明判断理由。
            如果是真实威胁，请说明威胁类型和建议的处理措施。
            
            回复必须使用JSON格式：
            {{"is_threat": true/false, "confidence": 0-100, "analysis": "分析说明", "recommendations": "建议措施"}}
            """
        elif alert_content:
            # 只有告警内容，没有日志内容
            return f"""
            你是一位网络安全分析专家，请仔细分析以下安全告警信息，并给出专业评估：
            
            ## 安全告警内容：
            {alert_content}
            
            请基于告警信息，评估这是真实威胁还是误报，并给出置信度评分（0-100分）和详细分析。
            如果是误报，请详细说明判断理由。
            如果是真实威胁，请说明威胁类型和建议的处理措施。
            如果需要更多日志来确认，请在建议中说明需要查看哪些类型的日志。
            
            回复必须使用JSON格式：
            {{"is_threat": true/false, "confidence": 0-100, "analysis": "分析说明", "recommendations": "建议措施"}}
            """
        else:
            # 只有日志内容，没有告警内容
            return f"""
            你是一位网络安全分析专家，请仔细分析以下安全日志，并给出专业评估：
            
            ## 日志内容：
            {log_content}
            
            请基于以上信息，评估这是否包含安全威胁，并给出置信度评分（0-100分）和详细分析。
            如果没有威胁，请详细说明判断理由。
            如果存在威胁，请说明威胁类型和建议的处理措施。
            
            回复必须使用JSON格式：
            {{"is_threat": true/false, "confidence": 0-100, "analysis": "分析说明", "recommendations": "建议措施"}}
            """
    
    def analyze_log(self, log_content, alert_content=None, custom_prompt=None):
        """使用AI分析日志内容
        
        Args:
            log_content: 日志内容
            alert_content: 告警内容（可选）
            custom_prompt: 自定义提示词（可选）
            
        Returns:
            分析结果字典
        """
        # 构建提示信息
        prompt = self._build_prompt(log_content, alert_content, custom_prompt)
        
        # 调用API
        try:
            headers = {
                "Content-Type": "application/json"
            }
            
            # 只有当API密钥存在时才添加认证头
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            payload = {
                "model": "default-model",  # 使用默认模型，子类可以覆盖
                "messages": [
                    {"role": "system", "content": "你是一位专业的网络安全分析专家，擅长分析安全日志和检测威胁。"},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.1  # 低温度以获得更确定性的回答
            }
            
            print(f"调用API: {self.api_url}")
            print(f"请求头: {headers}")
            print(f"请求负载: {json.dumps(payload, ensure_ascii=False)[:200]}...")
            
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=self.timeout)
            
            # 输出详细信息以便调试
            print(f"响应状态码: {response.status_code}")
            print(f"响应头: {response.headers}")
            print(f"响应内容: {response.text[:500]}...")  # 只打印前500个字符
            
            response.raise_for_status()
            
            result = response.json()
            
            # 提取返回内容
            content = ""
            if "choices" in result and len(result["choices"]) > 0:
                if "message" in result["choices"][0] and "content" in result["choices"][0]["message"]:
                    content = result["choices"][0]["message"]["content"]
            
            if not content:
                return {
                    "is_threat": False,
                    "confidence": 0,
                    "analysis": "API返回内容为空",
                    "recommendations": "请检查API配置和响应格式"
                }
            
            # 解析返回的JSON
            try:
                analysis_result = json.loads(content)
                return analysis_result
            except json.JSONDecodeError:
                # 如果返回内容不是有效的JSON，尝试提取可能的JSON部分
                json_match = re.search(r'{.*}', content, re.DOTALL)
                if json_match:
                    try:
                        analysis_result = json.loads(json_match.group(0))
                        return analysis_result
                    except:
                        pass
                
                # 如果仍无法解析，返回错误信息
                return {
                    "is_threat": False,
                    "confidence": 0,
                    "analysis": "无法解析AI返回的内容",
                    "recommendations": "请重试或联系支持团队"
                }
                
        except Exception as e:
            # 发生API调用错误
            return {
                "is_threat": False,
                "confidence": 0,
                "analysis": f"API调用失败: {str(e)}",
                "recommendations": "请检查API配置和网络连接"
            }

class DeepSeekService(GenericAIService):
    """DeepSeek AI服务"""
    
    def __init__(self, api_key, api_url=None, timeout=60):
        """初始化DeepSeek服务
        
        Args:
            api_key: DeepSeek API密钥
            api_url: DeepSeek API URL(可选)
            timeout: 超时时间（秒）
        """
        super().__init__(
            api_key, 
            api_url or "https://api.deepseek.com/v1/chat/completions",
            timeout
        )
    
    def analyze_log(self, log_content, alert_content=None, custom_prompt=None):
        """使用DeepSeek分析日志内容，覆盖父类方法以使用DeepSeek特定的请求格式
        
        Args:
            log_content: 日志内容
            alert_content: 告警内容（可选）
            custom_prompt: 自定义提示词（可选）
            
        Returns:
            分析结果字典
        """
        # 构建提示信息
        prompt = self._build_prompt(log_content, alert_content, custom_prompt)
        
        # 调用API - DeepSeek特定的请求
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            # DeepSeek特定模型名称
            payload = {
                "model": "deepseek-chat",  # DeepSeek模型名称
                "messages": [
                    {"role": "system", "content": "你是一位专业的网络安全分析专家，擅长分析安全日志和检测威胁。"},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.1,
                "max_tokens": 2000
            }
            
            print(f"调用DeepSeek API: {self.api_url}")
            print(f"请求负载: {json.dumps(payload, ensure_ascii=False)[:200]}...")
            
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=self.timeout)
            
            # 输出详细信息以便调试
            print(f"响应状态码: {response.status_code}")
            
            response.raise_for_status()
            
            result = response.json()
            
            # 提取返回内容
            content = ""
            if "choices" in result and len(result["choices"]) > 0:
                if "message" in result["choices"][0] and "content" in result["choices"][0]["message"]:
                    content = result["choices"][0]["message"]["content"]
            
            if not content:
                return {
                    "is_threat": False,
                    "confidence": 0,
                    "analysis": "DeepSeek API返回内容为空",
                    "recommendations": "请检查API配置和响应格式"
                }
            
            # 解析返回的JSON
            try:
                analysis_result = json.loads(content)
                return analysis_result
            except json.JSONDecodeError:
                # 如果返回内容不是有效的JSON，尝试提取可能的JSON部分
                json_match = re.search(r'{.*}', content, re.DOTALL)
                if json_match:
                    try:
                        analysis_result = json.loads(json_match.group(0))
                        return analysis_result
                    except:
                        pass
                
                # 如果仍无法解析，直接返回内容
                return {
                    "is_threat": False,
                    "confidence": 0,
                    "analysis": f"无法解析DeepSeek返回的内容: {content[:200]}...",
                    "recommendations": "请尝试使用其他AI服务或联系支持团队"
                }
                
        except Exception as e:
            # 发生API调用错误
            return {
                "is_threat": False,
                "confidence": 0,
                "analysis": f"DeepSeek API调用失败: {str(e)}",
                "recommendations": "请检查API密钥和网络连接"
            }

class DouBaoService(GenericAIService):
    """豆包AI服务"""
    
    def __init__(self, api_key, api_url=None, timeout=60):
        """初始化豆包服务
        
        Args:
            api_key: 豆包 API密钥
            api_url: 豆包 API URL(可选)
            timeout: 超时时间（秒）
        """
        super().__init__(
            api_key, 
            api_url or "https://api.doubao.com/v1/chat/completions",
            timeout
        )

class LocalAIService(GenericAIService):
    """本地AI服务"""
    
    def __init__(self, api_url, timeout=180):
        """初始化本地AI服务
        
        Args:
            api_url: 本地AI服务URL
            timeout: 超时时间（秒），本地模型通常较慢，默认设置更长超时
        """
        super().__init__(None, api_url, timeout)  # 本地AI不需要API密钥
    
    def analyze_log(self, log_content, alert_content=None, custom_prompt=None):
        """使用本地AI模型分析日志内容，添加特定错误处理
        
        Args:
            log_content: 日志内容
            alert_content: 告警内容（可选）
            custom_prompt: 自定义提示词（可选）
            
        Returns:
            分析结果字典
        """
        try:
            # 调用父类的方法
            result = super().analyze_log(log_content, alert_content, custom_prompt)
            
            # 检查特定的错误模式
            if "analysis" in result and "API调用失败" in result["analysis"]:
                # 处理常见的本地模型错误
                error_msg = result["analysis"]
                
                if "Unexpected endpoint or method" in error_msg:
                    # LM Studio API端点错误
                    current_url = self.api_url
                    port = "1234"  # 默认LM Studio端口
                    
                    # 尝试从当前URL提取端口号
                    import re
                    port_match = re.search(r':(\d+)/', current_url)
                    if port_match:
                        port = port_match.group(1)
                    
                    # 构建推荐的URL
                    if "localhost" in current_url or "127.0.0.1" in current_url:
                        suggest_url = f"http://localhost:{port}/api/chat"
                    else:
                        host = re.search(r'https?://([^:/]+)', current_url)
                        if host:
                            suggest_url = f"http://{host.group(1)}:{port}/api/chat"
                        else:
                            suggest_url = f"http://localhost:{port}/api/chat"
                    
                    return {
                        "is_threat": False,
                        "confidence": 0,
                        "analysis": "LM Studio API端点错误",
                        "recommendations": f"您正在使用LM Studio，但API端点格式不正确。LM Studio使用 '/api/chat' 而不是 '/v1/chat/completions'。\n\n"
                                          f"请在设置中将API URL修改为: {suggest_url}\n\n"
                                          f"如果问题仍然存在，请查看LM Studio的设置页面，确认正确的API端点格式。"
                    }
                
                # 添加连接被拒绝错误处理
                elif "Connection refused" in error_msg:
                    return {
                        "is_threat": False,
                        "confidence": 0,
                        "analysis": "无法连接到本地AI模型服务",
                        "recommendations": "请确保您的本地AI模型服务（如LM Studio、Ollama或LocalAI）正在运行，并检查端口号是否正确。"
                    }
                
                # 添加超时错误处理
                elif "timed out" in error_msg.lower():
                    return {
                        "is_threat": False,
                        "confidence": 0,
                        "analysis": "连接本地AI模型服务超时",
                        "recommendations": "本地AI模型响应时间过长，这可能是因为模型较大或计算资源不足。您可以尝试:\n"
                                        "1. 在设置中增加超时时间\n"
                                        "2. 使用更小的模型\n"
                                        "3. 减少输入文本长度"
                    }
                    
            return result
            
        except Exception as e:
            # 本地模型特有的异常处理
            return {
                "is_threat": False,
                "confidence": 0,
                "analysis": f"本地AI模型调用失败: {str(e)}",
                "recommendations": "请检查本地AI模型服务是否正在运行，并且API URL配置正确。不同的本地模型可能需要不同的API URL格式。"
            }

class OtherAIService(GenericAIService):
    """其他AI服务，用于处理自定义API服务器"""
    
    def __init__(self, api_key, api_url, timeout=60):
        """初始化其他AI服务
        
        Args:
            api_key: API密钥（可能为空）
            api_url: API URL
            timeout: 超时时间（秒）
        """
        super().__init__(api_key, api_url, timeout)
    
    def analyze_log(self, log_content, alert_content=None, custom_prompt=None):
        """使用其他AI服务分析日志内容，提供更详细的错误信息
        
        Args:
            log_content: 日志内容
            alert_content: 告警内容（可选）
            custom_prompt: 自定义提示词（可选）
            
        Returns:
            分析结果字典
        """
        try:
            # 调用父类的方法
            result = super().analyze_log(log_content, alert_content, custom_prompt)
            
            # 检查常见错误模式
            if "analysis" in result and "API调用失败" in result["analysis"]:
                error_msg = result["analysis"]
                
                if "Connection refused" in error_msg:
                    return {
                        "is_threat": False,
                        "confidence": 0,
                        "analysis": "无法连接到API服务器",
                        "recommendations": "请检查API URL是否正确，以及服务器是否正在运行。"
                    }
                elif "Invalid URL" in error_msg or "No schema supplied" in error_msg:
                    return {
                        "is_threat": False,
                        "confidence": 0,
                        "analysis": "API URL格式错误",
                        "recommendations": "请确保URL格式正确，应包含协议(http://或https://)、主机名和端口号。"
                    }
                elif "Unauthorized" in error_msg or "401" in error_msg:
                    return {
                        "is_threat": False,
                        "confidence": 0,
                        "analysis": "API认证失败",
                        "recommendations": "请检查API密钥是否正确。某些API可能不需要密钥，但格式仍需正确。"
                    }
                    
            return result
            
        except Exception as e:
            # 特有异常处理
            return {
                "is_threat": False,
                "confidence": 0,
                "analysis": f"自定义AI模型调用失败: {str(e)}",
                "recommendations": "请检查API URL、认证设置和网络连接。"
            }

class AIServiceFactory:
    """AI服务工厂，用于创建不同的AI服务实例"""
    
    @staticmethod
    def create_service(provider, api_key, config_manager=None):
        """创建AI服务实例
        
        Args:
            provider: AI服务提供商名称
            api_key: API密钥
            config_manager: 配置管理器(用于获取API URL)
            
        Returns:
            AI服务实例
        """
        # 获取API URL和超时设置
        api_url = None
        timeout = 60  # 默认超时时间
        
        if config_manager:
            api_url = config_manager.get_api_url(provider)
            timeout = config_manager.get("api_timeout", {}).get(provider, 60)
        
        provider = provider.lower()
        
        # 本地AI模型不需要API密钥
        if provider == "local":
            if not api_url:
                api_url = "http://localhost:1234/v1/chat/completions"  # 默认本地API端口为1234
            return LocalAIService(api_url, timeout=timeout)
        
        # 其他AI模型 - 允许空API密钥
        if provider == "other":
            if not api_url:
                raise ValueError("未配置其他AI模型的API URL")
            # 使用专门的其他AI服务类
            return OtherAIService(api_key, api_url, timeout=timeout)
        
        # 其他服务需要API密钥
        if not api_key and provider not in ["local", "other"]:
            raise ValueError(f"未配置{provider}的API密钥")
        
        if provider == "deepseek":
            return DeepSeekService(api_key, api_url, timeout=timeout)
        elif provider == "doubao":
            return DouBaoService(api_key, api_url, timeout=timeout)
        elif provider.startswith("custom_"):
            return GenericAIService(api_key, api_url, timeout=timeout)
        else:
            raise ValueError(f"不支持的AI服务提供商: {provider}") 