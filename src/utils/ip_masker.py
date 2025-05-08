#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class IPMasker:
    """IP地址脱敏处理工具"""
    
    # IP地址匹配的正则表达式
    IP_PATTERN = r'(?<!\d)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?!\d)'
    
    def __init__(self, config_dir, max_mappings=500):
        """初始化IP掩码器
        
        Args:
            config_dir: 配置目录路径
            max_mappings: 最大映射数量，默认500条
        """
        self.config_dir = config_dir
        self.mapping_file = os.path.join(config_dir, "ip_mapping.json")
        self.max_mappings = max_mappings
        self.mapping = self._load_mapping()
        
        # 如果映射表超过最大限制，清理旧映射
        if len(self.mapping) > self.max_mappings:
            self._trim_mappings()
            
        self.reverse_mapping = {v: k for k, v in self.mapping.items()}
        
        # 创建加密密钥（或加载现有密钥）
        self.key_file = os.path.join(config_dir, "mask_key.key")
        self.key = self._get_or_create_key()
        self.cipher_suite = Fernet(self.key)
    
    def _get_or_create_key(self):
        """获取或创建加密密钥"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            # 生成盐值和密钥
            salt = os.urandom(16)
            password = os.urandom(32)  # 使用随机生成的密码
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            # 保存密钥
            with open(self.key_file, 'wb') as f:
                f.write(key)
            
            return key
    
    def _load_mapping(self):
        """加载IP映射"""
        if os.path.exists(self.mapping_file):
            try:
                with open(self.mapping_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}
    
    def _save_mapping(self):
        """保存IP映射"""
        with open(self.mapping_file, 'w', encoding='utf-8') as f:
            json.dump(self.mapping, f, ensure_ascii=False, indent=2)
    
    def _trim_mappings(self):
        """当映射数量超过限制时裁剪映射表"""
        if len(self.mapping) <= self.max_mappings:
            return
            
        # 将映射转换为列表并按添加顺序排序（保留最新添加的）
        items = list(self.mapping.items())
        # 只保留最新的max_mappings条映射
        self.mapping = dict(items[-self.max_mappings:])
        self._save_mapping()
        print(f"IP映射表已裁剪至{self.max_mappings}条记录")
    
    def clear_mappings(self):
        """清空IP映射表"""
        self.mapping = {}
        self.reverse_mapping = {}
        if os.path.exists(self.mapping_file):
            self._save_mapping()
        return True
    
    def get_mapping(self):
        """获取IP映射表
        
        Returns:
            脱敏IP到原始IP的映射字典
        """
        return {mask: ip for ip, mask in self.mapping.items()}
    
    def mask_ip(self, ip):
        """对单个IP地址进行脱敏
        
        Args:
            ip: 原始IP地址
            
        Returns:
            脱敏后的IP地址标识符
        """
        if ip in self.mapping:
            return self.mapping[ip]
        
        # 加密IP地址
        encrypted = self.cipher_suite.encrypt(ip.encode('utf-8'))
        
        # 根据IP类型生成类似IP的掩码
        ip_parts = ip.split('.')
        first_octet = int(ip_parts[0])
        
        # 生成一个看起来像IP地址的掩码
        if first_octet >= 1 and first_octet <= 126:  # A类地址
            masked_ip = f"10.0.{len(self.mapping) % 256}.{(len(self.mapping) // 256) % 256}"
        elif first_octet >= 128 and first_octet <= 191:  # B类地址
            masked_ip = f"172.16.{len(self.mapping) % 256}.{(len(self.mapping) // 256) % 256}"
        elif first_octet >= 192 and first_octet <= 223:  # C类地址
            masked_ip = f"192.168.{len(self.mapping) % 256}.{(len(self.mapping) // 256) % 256}"
        else:  # 特殊IP范围
            masked_ip = f"169.254.{len(self.mapping) % 256}.{(len(self.mapping) // 256) % 256}"
        
        # 保存映射关系
        self.mapping[ip] = masked_ip
        self.reverse_mapping[masked_ip] = ip
        self._save_mapping()
        
        return masked_ip
    
    def unmask_ip(self, masked_ip):
        """恢复脱敏的IP地址
        
        Args:
            masked_ip: 脱敏后的IP标识符
            
        Returns:
            原始IP地址，如果找不到映射则返回原值
        """
        return self.reverse_mapping.get(masked_ip, masked_ip)
    
    def mask_text(self, text):
        """对文本中的所有IP进行脱敏
        
        Args:
            text: 原始文本
            
        Returns:
            脱敏后的文本
        """
        if not text:
            return text
            
        def replace_ip(match):
            ip = match.group(0)
            return self.mask_ip(ip)
        
        return re.sub(self.IP_PATTERN, replace_ip, text)
    
    def unmask_text(self, text):
        """恢复文本中的所有脱敏IP
        
        Args:
            text: 脱敏后的文本
            
        Returns:
            恢复原始IP的文本
        """
        if not text:
            return text
            
        # 创建临时的反向映射表，用于快速查找
        ip_patterns = []
        for masked_ip in self.reverse_mapping.keys():
            # 转义点号，因为在正则表达式中点号是特殊字符
            escaped_ip = masked_ip.replace('.', '\\.')
            ip_patterns.append(escaped_ip)
        
        if not ip_patterns:
            return text
            
        # 创建合并的正则表达式
        combined_pattern = '|'.join(ip_patterns)
        pattern = f"({combined_pattern})"
        
        def replace_mask(match):
            mask = match.group(0)
            return self.unmask_ip(mask)
        
        return re.sub(pattern, replace_mask, text) 