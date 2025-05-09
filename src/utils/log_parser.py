#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import csv
import pandas as pd
import re
from datetime import datetime

class LogParser:
    """日志文件解析器，支持多种日志格式"""
    
    # 常见安全事件相关的正则表达式模式
    ATTACK_PATTERNS = {
        "ssh_failed_login": r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)",
        "ssh_repeated_login": r"repeated login failures from (\d+\.\d+\.\d+\.\d+)",
        "firewall_block": r"blocked (?:from|source) (\d+\.\d+\.\d+\.\d+).*(?:to|dest) (\d+\.\d+\.\d+\.\d+)",
        "port_scan": r"scan from (\d+\.\d+\.\d+\.\d+)",
        "web_attack": r"(SQL injection|XSS|CSRF|directory traversal|file inclusion).*from (\d+\.\d+\.\d+\.\d+)",
        "malware": r"(?:trojan|virus|malware|ransomware|backdoor) .*?(\d+\.\d+\.\d+\.\d+)",
        "dos_attack": r"(DoS|DDoS|flood).*from (\d+\.\d+\.\d+\.\d+)"
    }
    
    # 常见的威胁特征和严重性级别
    THREAT_SIGNATURES = {
        "sql_injection": {
            "pattern": r"(?:SQL injection|SQLMAP|union\s+select|select\s+from|'--|\b(or|and)\s+1=1)",
            "severity": "高",
            "description": "SQL注入攻击尝试"
        },
        "xss": {
            "pattern": r"(?:<script>|javascript:|onerror=|onload=|eval\(|document\.cookie)",
            "severity": "中",
            "description": "跨站脚本攻击(XSS)尝试"
        },
        "command_injection": {
            "pattern": r"(?:;ls\s|;cat\s|;rm\s|;wget\s|\|\s*bash|\|\s*sh)",
            "severity": "高",
            "description": "命令注入攻击尝试"
        },
        "file_inclusion": {
            "pattern": r"(?:\.\.\/|\.\.\%2f|\/etc\/passwd|\/var\/www)",
            "severity": "高",
            "description": "文件包含或路径遍历攻击尝试"
        },
        "bruteforce": {
            "pattern": r"(?:brute force|dictionary attack|password guess|login failure)",
            "severity": "中",
            "description": "暴力破解或密码猜测攻击"
        },
        "privilege_escalation": {
            "pattern": r"(?:sudo|su\s|setuid|setgid|chmod\s+[0-7]*s)",
            "severity": "高",
            "description": "权限提升尝试"
        }
    }
    
    def __init__(self):
        """初始化日志解析器"""
        pass
    
    def parse_file(self, file_path):
        """解析日志文件
        
        Args:
            file_path: 日志文件路径
            
        Returns:
            解析后的日志内容（DataFrame格式）
        """
        file_ext = os.path.splitext(file_path)[1].lower()
        
        try:
            if file_ext == '.csv':
                df = self._parse_csv(file_path)
            elif file_ext == '.log' or file_ext == '.txt':
                df = self._parse_log_or_txt(file_path)
            else:
                # 尝试作为普通文本文件解析
                df = self._parse_log_or_txt(file_path)
                
            # 增强解析：识别安全事件和关系
            df = self._enhance_log_analysis(df)
            return df
        except Exception as e:
            raise ValueError(f"解析文件失败: {str(e)}")
    
    def _parse_csv(self, file_path):
        """解析CSV格式的日志文件
        
        Args:
            file_path: CSV文件路径
            
        Returns:
            解析后的DataFrame
        """
        try:
            # 先尝试直接用pandas读取
            df = pd.read_csv(file_path)
            return df
        except Exception:
            # 如果失败，尝试检测分隔符
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                sample = f.read(4096)  # 读取前4KB样本
            
            # 检测可能的分隔符
            delimiters = [',', ';', '\t', '|']
            best_delimiter = ','  # 默认分隔符
            max_columns = 0
            
            for delimiter in delimiters:
                dialect = csv.Sniffer().sniff(sample, delimiters=delimiter)
                reader = csv.reader(sample.splitlines(), dialect)
                columns = max(len(row) for row in reader)
                if columns > max_columns:
                    max_columns = columns
                    best_delimiter = delimiter
            
            # 使用检测到的最佳分隔符
            df = pd.read_csv(file_path, sep=best_delimiter)
            return df
    
    def _parse_log_or_txt(self, file_path):
        """解析普通日志或文本文件
        
        Args:
            file_path: 日志文件路径
            
        Returns:
            解析后的DataFrame
        """
        # 尝试检测日志格式
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        if not lines:
            return pd.DataFrame({"raw_log": []})
        
        # 检查是否有常见的时间戳格式
        timestamp_patterns = [
            # ISO格式: 2023-01-01T12:34:56
            r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
            # 常见日志格式: 2023-01-01 12:34:56
            r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            # Apache日志格式: [01/Jan/2023:12:34:56 +0000]
            r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[\+\-]\d{4})\]',
            # Syslog格式: Jan 01 12:34:56
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        ]
        
        # 尝试各种模式匹配前10行
        sample = lines[:10]
        detected_pattern = None
        
        for pattern in timestamp_patterns:
            matches = [re.search(pattern, line) for line in sample]
            if all(matches):
                detected_pattern = pattern
                break
        
        data = []
        
        if detected_pattern:
            # 检测到时间戳模式，尝试按时间戳拆分
            current_entry = []
            
            for line in lines:
                if re.search(detected_pattern, line):
                    # 发现新条目的开始
                    if current_entry:
                        data.append({'timestamp': current_entry[0], 'message': ''.join(current_entry[1:])})
                    current_entry = [line]
                else:
                    # 继续当前条目
                    if current_entry:
                        current_entry.append(line)
                    else:
                        current_entry = [line]
            
            # 添加最后一个条目
            if current_entry:
                data.append({'timestamp': current_entry[0], 'message': ''.join(current_entry[1:])})
            
            return pd.DataFrame(data)
        else:
            # 没有检测到特定格式，每行作为一个条目
            return pd.DataFrame({'raw_log': lines})
    
    def _enhance_log_analysis(self, dataframe):
        """增强日志分析，识别攻击者IP、被攻击IP和威胁特征
        
        Args:
            dataframe: 原始日志DataFrame
            
        Returns:
            增强后的DataFrame，添加了安全分析列
        """
        # 创建新的列
        dataframe['attacker_ip'] = None
        dataframe['target_ip'] = None
        dataframe['threat_type'] = None
        dataframe['severity'] = None
        dataframe['threat_description'] = None
        
        # 获取要分析的文本列
        text_column = None
        if 'raw_log' in dataframe.columns:
            text_column = 'raw_log'
        elif 'message' in dataframe.columns:
            text_column = 'message'
        
        if text_column is None:
            return dataframe  # 没有可以分析的文本列
        
        # 逐行分析
        for i, row in dataframe.iterrows():
            log_line = row[text_column]
            if not isinstance(log_line, str):
                continue
                
            # 识别攻击模式和IP地址
            for attack_type, pattern in self.ATTACK_PATTERNS.items():
                match = re.search(pattern, log_line, re.IGNORECASE)
                if match:
                    if attack_type == "firewall_block" and len(match.groups()) >= 2:
                        # 防火墙日志通常包含源IP和目标IP
                        dataframe.at[i, 'attacker_ip'] = match.group(1)
                        dataframe.at[i, 'target_ip'] = match.group(2)
                        dataframe.at[i, 'threat_type'] = "防火墙阻断"
                    elif attack_type == "web_attack" and len(match.groups()) >= 2:
                        # Web攻击日志包含攻击类型和源IP
                        dataframe.at[i, 'attacker_ip'] = match.group(2)
                        dataframe.at[i, 'threat_type'] = match.group(1)
                    else:
                        # 其他类型的攻击日志通常只包含一个IP（攻击者）
                        dataframe.at[i, 'attacker_ip'] = match.group(1)
                        dataframe.at[i, 'threat_type'] = self._get_attack_type_name(attack_type)
                    
                    break  # 找到一种攻击模式后不再继续
            
            # 识别威胁特征
            for sig_name, sig_info in self.THREAT_SIGNATURES.items():
                if re.search(sig_info["pattern"], log_line, re.IGNORECASE):
                    dataframe.at[i, 'threat_description'] = sig_info["description"]
                    dataframe.at[i, 'severity'] = sig_info["severity"]
                    break
            
            # 尝试识别其他可能的IP地址关系
            if dataframe.at[i, 'attacker_ip'] is None or dataframe.at[i, 'target_ip'] is None:
                self._identify_ip_relationships(dataframe, i, log_line)
        
        return dataframe
    
    def _identify_ip_relationships(self, dataframe, idx, log_line):
        """识别日志行中可能的IP地址关系
        
        Args:
            dataframe: 要更新的DataFrame
            idx: 当前行索引
            log_line: 日志文本
        """
        # 提取所有IP地址
        ip_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_line)
        if len(ip_addresses) < 1:
            return
        
        # 根据日志内容确定IP角色
        if len(ip_addresses) >= 2:
            # 有多个IP时，通过上下文判断关系
            if re.search(r'(?:from|source|src|attacker)', log_line, re.IGNORECASE):
                for i, ip in enumerate(ip_addresses):
                    if re.search(rf'(?:from|source|src|attacker).*?{re.escape(ip)}', log_line, re.IGNORECASE):
                        if dataframe.at[idx, 'attacker_ip'] is None:
                            dataframe.at[idx, 'attacker_ip'] = ip
                            break
            
            if re.search(r'(?:to|dest|destination|target)', log_line, re.IGNORECASE):
                for i, ip in enumerate(ip_addresses):
                    if re.search(rf'(?:to|dest|destination|target).*?{re.escape(ip)}', log_line, re.IGNORECASE):
                        if dataframe.at[idx, 'target_ip'] is None:
                            dataframe.at[idx, 'target_ip'] = ip
                            break
            
            # 如果未能确定关系但有多个IP，默认第一个是源，第二个是目标
            if dataframe.at[idx, 'attacker_ip'] is None and dataframe.at[idx, 'target_ip'] is None:
                dataframe.at[idx, 'attacker_ip'] = ip_addresses[0]
                if len(ip_addresses) > 1:
                    dataframe.at[idx, 'target_ip'] = ip_addresses[1]
        elif len(ip_addresses) == 1:
            # 只有一个IP时，通过关键词判断角色
            ip = ip_addresses[0]
            if re.search(r'(?:attack|hack|exploit|scan|brute|force|failed|rejected|blocked|denied|malicious)', log_line, re.IGNORECASE):
                if dataframe.at[idx, 'attacker_ip'] is None:
                    dataframe.at[idx, 'attacker_ip'] = ip
            elif re.search(r'(?:victim|compromised|targeted)', log_line, re.IGNORECASE):
                if dataframe.at[idx, 'target_ip'] is None:
                    dataframe.at[idx, 'target_ip'] = ip
    
    @staticmethod
    def _get_attack_type_name(attack_type):
        """将攻击类型转换为友好名称"""
        attack_names = {
            "ssh_failed_login": "SSH登录失败",
            "ssh_repeated_login": "多次SSH登录失败",
            "firewall_block": "防火墙阻断",
            "port_scan": "端口扫描",
            "web_attack": "Web应用攻击",
            "malware": "恶意软件",
            "dos_attack": "拒绝服务攻击"
        }
        return attack_names.get(attack_type, attack_type)
    
    def get_security_summary(self, dataframe):
        """生成安全日志摘要
        
        Args:
            dataframe: 增强后的日志DataFrame
            
        Returns:
            安全摘要字典
        """
        summary = {
            "total_entries": len(dataframe),
            "identified_threats": 0,
            "unique_attackers": set(),
            "unique_targets": set(),
            "threat_types": {},
            "severity_counts": {"高": 0, "中": 0, "低": 0, "未知": 0}
        }
        
        # 统计威胁信息
        for _, row in dataframe.iterrows():
            if row.get('threat_type') or row.get('threat_description'):
                summary["identified_threats"] += 1
                
                if row.get('attacker_ip'):
                    summary["unique_attackers"].add(row['attacker_ip'])
                    
                if row.get('target_ip'):
                    summary["unique_targets"].add(row['target_ip'])
                    
                threat_type = row.get('threat_type', '未知威胁')
                summary["threat_types"][threat_type] = summary["threat_types"].get(threat_type, 0) + 1
                
                severity = row.get('severity', '未知')
                summary["severity_counts"][severity] = summary["severity_counts"].get(severity, 0) + 1
        
        # 转换集合为列表，以便于JSON序列化
        summary["unique_attackers"] = list(summary["unique_attackers"])
        summary["unique_targets"] = list(summary["unique_targets"])
        
        # 按出现次数排序威胁类型
        summary["threat_types"] = dict(sorted(summary["threat_types"].items(), key=lambda x: x[1], reverse=True))
        
        return summary
    
    @staticmethod
    def extract_alert_context(dataframe, alert_line_index, context_lines=5):
        """从DataFrame中提取告警上下文
        
        Args:
            dataframe: 日志DataFrame
            alert_line_index: 告警行索引
            context_lines: 前后上下文行数
            
        Returns:
            告警上下文文本
        """
        start_idx = max(0, alert_line_index - context_lines)
        end_idx = min(len(dataframe), alert_line_index + context_lines + 1)
        
        # 根据DataFrame的列结构提取文本
        if 'raw_log' in dataframe.columns:
            context = dataframe.iloc[start_idx:end_idx]['raw_log'].to_list()
            return '\n'.join(context)
        elif 'timestamp' in dataframe.columns and 'message' in dataframe.columns:
            context = []
            for _, row in dataframe.iloc[start_idx:end_idx].iterrows():
                context.append(f"{row['timestamp']} {row['message']}")
            return '\n'.join(context)
        else:
            # 尝试将所有列合并为一行
            context = []
            for _, row in dataframe.iloc[start_idx:end_idx].iterrows():
                context.append(' '.join(str(v) for v in row.values))
            return '\n'.join(context) 