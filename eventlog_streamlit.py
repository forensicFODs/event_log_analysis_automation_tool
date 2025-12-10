import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import tempfile, os, re, base64, ipaddress
from pathlib import Path
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

# =========================
# 상수/카탈로그
# =========================

SEVERITY_COLORS = {"critical": "#dc3545", "warning": "#ffc107", "info": "#17a2b8"}
SEVERITY_ICONS  = {"critical": "🔴", "warning": "🟡", "info": "🔵"}

LOGON_TYPE_MAP = {
    "2": "Interactive(콘솔)", "3": "Network(네트워크)", "4": "Batch", "5": "Service",
    "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
    "10": "RemoteInteractive(RDP)", "11": "CachedInteractive",
}

# ---- 🆕 Provider별 Event ID 매핑 (최우선 순위)
EVENT_MAPPING = {
    # Security 로그
    "Microsoft-Windows-Security-Auditing": {
        4624: {"technique": "T1078", "tactic": "Initial Access", "name": "Valid Accounts", "description": "성공한 로그온", "severity": "info"},
        4625: {"technique": "T1110", "tactic": "Credential Access", "name": "Brute Force", "description": "계정 로그온 실패", "severity": "critical"},
        4648: {"technique": "T1078", "tactic": "Initial Access", "name": "Valid Accounts", "description": "명시적 자격증명을 사용한 로그온", "severity": "warning"},
        4688: {"technique": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter", "description": "새 프로세스 생성", "severity": "info"},
        4689: {"technique": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter", "description": "프로세스 종료", "severity": "info"},
        4672: {"technique": "T1078.002", "tactic": "Privilege Escalation", "name": "Valid Accounts: Domain Accounts", "description": "관리자 권한으로 로그온", "severity": "warning"},
        4720: {"technique": "T1136.001", "tactic": "Persistence", "name": "Create Account: Local Account", "description": "새 사용자 계정 생성", "severity": "critical"},
        1102: {"technique": "T1070.001", "tactic": "Defense Evasion", "name": "Indicator Removal: Clear Windows Event Logs", "description": "보안 감사 로그가 삭제됨", "severity": "critical"},
        4719: {"technique": "T1562.002", "tactic": "Defense Evasion", "name": "Disable Windows Event Logging", "description": "시스템 감사 정책 변경", "severity": "critical"},
    },
    
    # System 로그
    "Microsoft-Windows-Eventlog": {
        104: {"technique": "T1070.001", "tactic": "Defense Evasion", "name": "Indicator Removal: Clear Windows Event Logs", "description": "이벤트 로그가 삭제됨", "severity": "critical"},
    },
    
    "Service Control Manager": {
        7045: {"technique": "T1543.003", "tactic": "Persistence", "name": "Windows Service", "description": "새 서비스 설치됨", "severity": "critical"},
        7040: {"technique": "T1562.001", "tactic": "Defense Evasion", "name": "Impair Defenses", "description": "서비스 시작 유형 변경됨", "severity": "warning"},
        7036: {"technique": "T1543.003", "tactic": "Persistence", "name": "Windows Service", "description": "서비스 상태 변경됨", "severity": "info"},
    },
    
    # Sysmon 로그
    "Microsoft-Windows-Sysmon": {
        1:  {"technique": "T1059", "tactic": "Execution", "name": "Process Create", "description": "Sysmon 프로세스 생성", "severity": "info"},
        3:  {"technique": "T1071", "tactic": "Command and Control", "name": "Network Connection", "description": "Sysmon 네트워크 연결", "severity": "info"},
        7:  {"technique": "T1129", "tactic": "Defense Evasion", "name": "Image Loaded", "description": "Sysmon 이미지 로드", "severity": "info"},
        10: {"technique": "T1055", "tactic": "Defense Evasion", "name": "Process Access", "description": "Sysmon 프로세스 접근", "severity": "warning"},
        11: {"technique": "T1105", "tactic": "Collection", "name": "File Create", "description": "Sysmon 파일 생성", "severity": "info"},
        12: {"technique": "T1112", "tactic": "Defense Evasion", "name": "Registry Add", "description": "Sysmon 레지스트리 키/값 생성", "severity": "warning"},
        13: {"technique": "T1112", "tactic": "Defense Evasion", "name": "Registry Set", "description": "Sysmon 레지스트리 값 설정", "severity": "warning"},
        14: {"technique": "T1112", "tactic": "Defense Evasion", "name": "Registry Rename", "description": "Sysmon 레지스트리 값 이름 변경", "severity": "warning"},
        15: {"technique": "T1564.004", "tactic": "Defense Evasion", "name": "Alternate Data Streams", "description": "Sysmon ADS 생성", "severity": "warning"},
        22: {"technique": "T1046", "tactic": "Discovery", "name": "DNS Query", "description": "Sysmon DNS 쿼리", "severity": "info"},
    },
    
    # PowerShell 로그
    "Microsoft-Windows-PowerShell": {
        4103: {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell 모듈/바인딩", "severity": "warning"},
        4104: {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell ScriptBlock 로깅", "severity": "warning"},
        4105: {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell 스크립트 시작", "severity": "warning"},
        4106: {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell 스크립트 종료", "severity": "info"},
    },
    
    "PowerShell": {
        400: {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell 엔진 시작", "severity": "info"},
        403: {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell 엔진 중지", "severity": "info"},
        800: {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell 콘솔 명령 실행", "severity": "warning"},
    },
    
    # Windows Defender
    "Microsoft-Windows-Windows Defender": {
        1116: {"technique": "T1490", "tactic": "Impact", "name": "Inhibit System Recovery", "description": "악성 소프트웨어 탐지됨", "severity": "critical"},
        1117: {"technique": "T1490", "tactic": "Impact", "name": "Inhibit System Recovery", "description": "악성 소프트웨어 차단됨", "severity": "critical"},
        1118: {"technique": "T1562.001", "tactic": "Defense Evasion", "name": "Impair Defenses", "description": "실시간 보호 비활성화 시도", "severity": "critical"},
        5001: {"technique": "T1562.001", "tactic": "Defense Evasion", "name": "Impair Defenses", "description": "실시간 보호 비활성화됨", "severity": "critical"},
    },
}

# ---- (1) EventID -> MITRE (fallback, Provider 불명확할 때만 사용)
MITRE_ATTACK_MAPPING = {
    4624: {"technique": "T1078", "tactic": "Initial Access", "name": "Valid Accounts", "description": "성공한 로그온", "severity": "info"},
    4648: {"technique": "T1078", "tactic": "Initial Access", "name": "Valid Accounts", "description": "명시적 자격증명을 사용한 로그온", "severity": "warning"},
    4688: {"technique": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter", "description": "새 프로세스 생성", "severity": "info"},
    4689: {"technique": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter", "description": "프로세스 종료", "severity": "info"},
    4103: {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell 모듈 실행", "severity": "warning"},
    4104: {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell 스크립트 실행", "severity": "warning"},
    4105: {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell 스크립트 시작", "severity": "warning"},
    4106: {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell 스크립트 종료", "severity": "info"},
    400:  {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell 엔진 시작", "severity": "info"},
    403:  {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell 엔진 중지", "severity": "info"},
    800:  {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell", "description": "PowerShell 명령 실행", "severity": "warning"},
    4698: {"technique": "T1053.005", "tactic": "Execution", "name": "Scheduled Task", "description": "예약된 작업 생성", "severity": "warning"},
    4702: {"technique": "T1053.005", "tactic": "Execution", "name": "Scheduled Task", "description": "예약된 작업 업데이트", "severity": "warning"},
    4720: {"technique": "T1136.001", "tactic": "Persistence", "name": "Create Account: Local Account", "description": "새 사용자 계정 생성", "severity": "critical"},
    4722: {"technique": "T1098", "tactic": "Persistence", "name": "Account Manipulation", "description": "사용자 계정 활성화", "severity": "warning"},
    7045: {"technique": "T1543.003", "tactic": "Persistence", "name": "Windows Service", "description": "새 서비스 설치됨", "severity": "critical"},
    4697: {"technique": "T1543.003", "tactic": "Persistence", "name": "Windows Service", "description": "서비스가 시스템에 설치됨", "severity": "critical"},
    4699: {"technique": "T1053.005", "tactic": "Execution", "name": "Scheduled Task", "description": "예약된 작업 삭제", "severity": "warning"},
    4672: {"technique": "T1078.002", "tactic": "Privilege Escalation", "name": "Valid Accounts: Domain Accounts", "description": "관리자 권한으로 로그온", "severity": "warning"},
    4673: {"technique": "T1134", "tactic": "Privilege Escalation", "name": "Access Token Manipulation", "description": "권한 있는 서비스 호출 시도", "severity": "warning"},
    4674: {"technique": "T1134", "tactic": "Privilege Escalation", "name": "Access Token Manipulation", "description": "권한 있는 작업 시도", "severity": "warning"},
    4738: {"technique": "T1098", "tactic": "Privilege Escalation", "name": "Account Manipulation", "description": "사용자 계정 변경됨", "severity": "warning"},
    1102: {"technique": "T1070.001", "tactic": "Defense Evasion", "name": "Indicator Removal: Clear Windows Event Logs", "description": "보안 감사 로그가 삭제됨", "severity": "critical"},
    104:  {"technique": "T1070.001", "tactic": "Defense Evasion", "name": "Indicator Removal: Clear Windows Event Logs", "description": "이벤트 로그가 삭제됨", "severity": "critical"},
    4719: {"technique": "T1562.002", "tactic": "Defense Evasion", "name": "Disable Windows Event Logging", "description": "시스템 감사 정책 변경", "severity": "critical"},
    7040: {"technique": "T1562.001", "tactic": "Defense Evasion", "name": "Impair Defenses", "description": "서비스 시작 유형 변경됨", "severity": "warning"},
    4625: {"technique": "T1110", "tactic": "Credential Access", "name": "Brute Force", "description": "계정 로그온 실패", "severity": "critical"},
    4768: {"technique": "T1558.003", "tactic": "Credential Access", "name": "Kerberoasting", "description": "Kerberos 인증 티켓 요청", "severity": "info"},
    4769: {"technique": "T1558.003", "tactic": "Credential Access", "name": "Kerberoasting", "description": "Kerberos 서비스 티켓 요청", "severity": "info"},
    4776: {"technique": "T1110", "tactic": "Credential Access", "name": "Brute Force", "description": "자격증명 유효성 검사 시도", "severity": "warning"},
    5857: {"technique": "T1047", "tactic": "Execution", "name": "WMI", "description": "WMI 활동 감지됨", "severity": "warning"},
    5858: {"technique": "T1047", "tactic": "Execution", "name": "WMI", "description": "WMI 에러 발생", "severity": "info"},
    5859: {"technique": "T1047", "tactic": "Execution", "name": "WMI", "description": "WMI 필터 활동", "severity": "warning"},
    5860: {"technique": "T1047", "tactic": "Execution", "name": "WMI", "description": "WMI 소비자 등록", "severity": "warning"},
    5861: {"technique": "T1047", "tactic": "Execution", "name": "WMI", "description": "WMI 영구 이벤트 등록", "severity": "warning"},
    4778: {"technique": "T1021.001", "tactic": "Lateral Movement", "name": "RDP", "description": "원격 데스크톱 세션 재연결", "severity": "warning"},
    4779: {"technique": "T1021.001", "tactic": "Lateral Movement", "name": "RDP", "description": "원격 데스크톱 세션 연결 해제", "severity": "info"},
    4647: {"technique": "T1078", "tactic": "Lateral Movement", "name": "Valid Accounts", "description": "사용자가 로그오프함", "severity": "info"},
    5140: {"technique": "T1021.002", "tactic": "Lateral Movement", "name": "SMB/Windows Admin Shares", "description": "네트워크 공유 객체 접근", "severity": "warning"},
    4663: {"technique": "T1005", "tactic": "Collection", "name": "Data from Local System", "description": "파일/객체 접근 시도", "severity": "info"},
    5145: {"technique": "T1039", "tactic": "Collection", "name": "Data from Network Shared Drive", "description": "네트워크 공유 상세 접근", "severity": "warning"},
    5156: {"technique": "T1071", "tactic": "Command and Control", "name": "App Layer Protocol", "description": "방화벽이 연결 허용", "severity": "info"},
    5157: {"technique": "T1071", "tactic": "Command and Control", "name": "App Layer Protocol", "description": "방화벽이 연결 차단", "severity": "info"},
    1116: {"technique": "T1490", "tactic": "Impact", "name": "Inhibit System Recovery", "description": "악성 소프트웨어 탐지됨", "severity": "critical"},
    1117: {"technique": "T1490", "tactic": "Impact", "name": "Inhibit System Recovery", "description": "악성 소프트웨어 차단됨", "severity": "critical"},
    1118: {"technique": "T1562.001", "tactic": "Defense Evasion", "name": "Impair Defenses", "description": "실시간 보호 비활성화 시도", "severity": "critical"},
    1119: {"technique": "T1562.001", "tactic": "Defense Evasion", "name": "Impair Defenses", "description": "악성코드 차단 실패", "severity": "critical"},
    5001: {"technique": "T1562.001", "tactic": "Defense Evasion", "name": "Impair Defenses", "description": "실시간 보호 비활성화됨", "severity": "critical"},
    1149: {"technique": "T1021.001", "tactic": "Lateral Movement", "name": "RDP", "description": "원격 데스크톱 인증 성공", "severity": "warning"},
    21:   {"technique": "T1021.001", "tactic": "Lateral Movement", "name": "RDP", "description": "원격 데스크톱 세션 시작", "severity": "warning"},
    22:   {"technique": "T1021.001", "tactic": "Lateral Movement", "name": "RDP", "description": "원격 데스크톱 셸 시작", "severity": "info"},
    23:   {"technique": "T1021.001", "tactic": "Lateral Movement", "name": "RDP", "description": "원격 데스크톱 로그오프", "severity": "info"},
    24:   {"technique": "T1021.001", "tactic": "Lateral Movement", "name": "RDP", "description": "원격 데스크톱 연결 해제", "severity": "info"},
    25:   {"technique": "T1021.001", "tactic": "Lateral Movement", "name": "RDP", "description": "원격 데스크톱 재연결 성공", "severity": "warning"},
    4723: {"technique": "T1098", "tactic": "Persistence", "name": "Account Manipulation", "description": "비밀번호 변경 시도", "severity": "warning"},
    4724: {"technique": "T1098", "tactic": "Persistence", "name": "Account Manipulation", "description": "비밀번호 재설정 시도", "severity": "warning"},
    4725: {"technique": "T1531", "tactic": "Impact", "name": "Account Access Removal", "description": "사용자 계정 비활성화됨", "severity": "warning"},
    4726: {"technique": "T1531", "tactic": "Impact", "name": "Account Access Removal", "description": "사용자 계정 삭제됨", "severity": "critical"},
    4740: {"technique": "T1110", "tactic": "Credential Access", "name": "Brute Force", "description": "사용자 계정 잠김", "severity": "critical"},
    4767: {"technique": "T1098", "tactic": "Persistence", "name": "Account Manipulation", "description": "사용자 계정 잠금 해제됨", "severity": "warning"},
    4781: {"technique": "T1098", "tactic": "Persistence", "name": "Account Manipulation", "description": "계정 이름이 변경됨", "severity": "warning"},
    4657: {"technique": "T1112", "tactic": "Defense Evasion", "name": "Modify Registry", "description": "레지스트리 값 수정됨", "severity": "warning"},
    5142: {"technique": "T1021.002", "tactic": "Lateral Movement", "name": "SMB/Windows Admin Shares", "description": "네트워크 공유 추가됨", "severity": "warning"},
    5143: {"technique": "T1021.002", "tactic": "Lateral Movement", "name": "SMB/Windows Admin Shares", "description": "네트워크 공유 수정됨", "severity": "warning"},
    5144: {"technique": "T1021.002", "tactic": "Lateral Movement", "name": "SMB/Windows Admin Shares", "description": "네트워크 공유 삭제됨", "severity": "warning"},
    5158: {"technique": "T1562.004", "tactic": "Defense Evasion", "name": "Disable/Modify Firewall", "description": "방화벽 포트 바인드 허용됨", "severity": "warning"},
    5159: {"technique": "T1562.004", "tactic": "Defense Evasion", "name": "Disable/Modify Firewall", "description": "방화벽 포트 바인드 차단됨", "severity": "info"},
    7036: {"technique": "T1543.003", "tactic": "Persistence", "name": "Windows Service", "description": "서비스 상태 변경됨", "severity": "info"},
    4700: {"technique": "T1053.005", "tactic": "Execution", "name": "Scheduled Task", "description": "예약된 작업 활성화됨", "severity": "warning"},
    4701: {"technique": "T1053.005", "tactic": "Execution", "name": "Scheduled Task", "description": "예약된 작업 비활성화됨", "severity": "info"},
    4739: {"technique": "T1098", "tactic": "Privilege Escalation", "name": "Account Manipulation", "description": "도메인 정책 변경됨", "severity": "critical"},
    4634: {"technique": "T1078", "tactic": "Defense Evasion", "name": "Valid Accounts", "description": "계정이 로그오프됨", "severity": "info"},
}

# 🗑️ 삭제: MITRE_ATTACK_MAPPING_PROVIDER (EVENT_MAPPING으로 통합)

# 🆕 Provider별 Activity 라벨 (UI용)
ACTIVITY_LABELS_PROVIDER = {
    ("Microsoft-Windows-Security-Auditing", 4624): "로그온 성공",
    ("Microsoft-Windows-Security-Auditing", 4625): "로그온 실패",
    ("Microsoft-Windows-Security-Auditing", 4648): "명시적 자격증명 사용",
    ("Microsoft-Windows-Security-Auditing", 4672): "특수 권한 로그온",
    ("Microsoft-Windows-Security-Auditing", 4688): "프로세스 생성",
    ("Microsoft-Windows-Security-Auditing", 4720): "계정 생성",
    ("Microsoft-Windows-Security-Auditing", 1102): "보안 로그 삭제",
    
    ("Microsoft-Windows-Eventlog", 104): "이벤트 로그 삭제",
    
    ("Service Control Manager", 7045): "새 서비스 설치",
    ("Service Control Manager", 7040): "서비스 시작 유형 변경",
    ("Service Control Manager", 7036): "서비스 상태 변경",
    
    ("Microsoft-Windows-Sysmon", 1):  "Sysmon 프로세스 생성",
    ("Microsoft-Windows-Sysmon", 3):  "Sysmon 네트워크 연결",
    ("Microsoft-Windows-Sysmon", 7):  "Sysmon 이미지 로드",
    ("Microsoft-Windows-Sysmon", 10): "Sysmon 프로세스 접근",
    ("Microsoft-Windows-Sysmon", 11): "Sysmon 파일 생성",
    ("Microsoft-Windows-Sysmon", 12): "Sysmon 레지스트리 추가",
    ("Microsoft-Windows-Sysmon", 13): "Sysmon 레지스트리 설정",
    ("Microsoft-Windows-Sysmon", 14): "Sysmon 레지스트리 이름 변경",
    ("Microsoft-Windows-Sysmon", 15): "Sysmon Alternate Data Streams",
    ("Microsoft-Windows-Sysmon", 22): "Sysmon DNS 쿼리",
    
    ("Microsoft-Windows-PowerShell", 4104): "PowerShell ScriptBlock",
    ("Microsoft-Windows-PowerShell", 4103): "PowerShell 모듈/바인딩",
    ("PowerShell", 800): "PowerShell 콘솔 명령",
    ("PowerShell", 400): "PowerShell 엔진 시작",
    ("PowerShell", 403): "PowerShell 엔진 중지",
    
    ("Microsoft-Windows-Windows Defender", 1116): "악성 소프트웨어 탐지",
    ("Microsoft-Windows-Windows Defender", 1117): "악성 소프트웨어 차단",
    ("Microsoft-Windows-Windows Defender", 5001): "실시간 보호 비활성화",
}

ACTIVITY_LABELS = {
    4624: "로그온 성공", 4625: "로그온 실패", 4648: "명시적 자격증명 사용", 4672: "특수 권한 로그온",
    4688: "프로세스 생성", 4697: "서비스 설치", 4698: "스케줄 작업 생성", 4702: "스케줄 작업 변경",
    4700: "스케줄 작업 활성화", 4701: "스케줄 작업 비활성화", 4720: "계정 생성", 4722: "계정 활성화",
    4723: "비밀번호 변경 시도", 4724: "비밀번호 재설정 시도", 4725: "계정 비활성화", 4726: "계정 삭제",
    4738: "계정 속성 변경", 4740: "계정 잠김", 4767: "계정 잠금 해제", 4776: "자격증명 유효성 검사",
    4778: "RDP 재연결", 4779: "RDP 연결 해제", 5140: "네트워크 공유 접근", 5145: "네트워크 공유 상세 접근",
    7045: "새 서비스 설치", 7040: "서비스 시작 유형 변경", 1102: "보안 로그 삭제", 104: "이벤트 로그 삭제",
    4719: "감사 정책 변경", 5857: "WMI 활동", 5859: "WMI 필터", 5860: "WMI 소비자 등록", 5861: "WMI 영구 이벤트 등록",
    1149: "RDP 인증 성공", 21: "RDP 세션 시작", 22: "RDP 셸 시작", 23: "RDP 로그오프", 24: "RDP 연결 해제", 25: "RDP 재연결 성공",
    5156: "방화벽 연결 허용", 5157: "방화벽 연결 차단", 5158: "방화벽 포트 허용", 5159: "방화벽 포트 차단",
    4663: "파일/객체 접근", 4657: "레지스트리 값 수정",
    1116: "악성 소프트웨어 탐지", 1117: "악성 소프트웨어 차단", 1118: "실시간 보호 비활성화 시도", 1119: "악성코드 차단 실패", 5001: "실시간 보호 비활성화",
    4103: "PowerShell 모듈/바인딩", 4104: "PowerShell ScriptBlock", 800: "PowerShell 콘솔 명령",
}

# 간단 의심행동 프리셋
SIMPLE_FILTERS = {
    "로그 삭제/감사 변경": [1102, 104, 4719],
    "원격 접속 (RDP/SMB)": [1149, 21, 22, 23, 24, 25, 4778, 4779, 5140, 5145],
    "계정 공격 (로그온 실패/잠금)": [4625, 4740, 4776],
    "지속성 (서비스/작업)": [7045, 4697, 4698, 4699, 4700, 4701, 4702],
    "PowerShell/WMI": [4103, 4104, 4105, 4106, 800, 5857, 5858, 5859, 5860, 5861, 400, 403],
}

EVENT_ID_DESCRIPTIONS = {
    4608: "Windows 시작", 4616: "시스템 시간 변경", 4732: "보안 그룹에 멤버 추가", 4733: "보안 그룹에서 멤버 제거",
    4800: "워크스테이션 잠김", 4801: "워크스테이션 잠금 해제",
}

SUSPICIOUS_PATTERNS = {
    1102: "보안 로그 삭제", 104: "로그 클리어", 4625: "로그온 실패 증가", 4740: "계정 잠김", 4720: "신규 계정 생성",
    4732: "관리자 그룹 멤버 추가", 4672: "특수 권한 로그온", 7045: "새 서비스 설치", 4698: "스케줄 작업 생성",
}

PS_SUSPICIOUS_KEYWORDS = [
    "Invoke-Mimikatz", "IEX", "FromBase64String", "DownloadString", "Net.WebClient",
    "Add-MpPreference", "Set-MpPreference", "DisableRealtimeMonitoring",
    "ExecutionPolicy Bypass", "Bypass", "Hidden", "AmsiScanBuffer", "AMSI",
    "Invoke-Expression", "System.Reflection.Assembly::Load", "Start-BitsTransfer",
]

EXTRA_FIELDS = [
    # 계정/로그온/권한
    "SubjectUserSid","TargetUserSid",
    "SubjectUserName","SubjectDomainName","TargetUserName","TargetDomainName","SubjectLogonId","TargetLogonId",
    "LogonType","LogonProcessName","AuthenticationPackageName","TransmittedServices","FailureReason","Status","SubStatus","WorkstationName","LmPackageName","KeyLength","PrivilegeList",
    # 프로세스
    "NewProcessName","ProcessName","CreatorProcessName","ParentProcessName","ProcessId","ParentProcessId",
    "CommandLine","ParentCommandLine","TokenElevationType","MandatoryLabel","IntegrityLevel",
    # 네트워크/방화벽
    "IpAddress","IpPort","SourceAddress","SourcePort","DestAddress","DestPort","Protocol","Direction",
    # 서비스/작업/공유/객체
    "ServiceName","TaskName","TaskContent","ShareName","ShareLocalPath","RelativeTargetName",
    "ObjectName","ObjectType","ObjectValue","AccessList",
    # PowerShell
    "ScriptBlockText","ScriptBlockId","ScriptName","ScriptPath","ContextInfo","HostApplication","MessageNumber","Message","Payload",
    # Sysmon/일반
    "Image","ImageLoaded","FileName","Hashes","User","RuleName",
    # DNS
    "QueryName","QueryStatus","QueryResults",
    # Defender(1116 등)
    "Product Name","Product Version","Detection ID","Threat ID","Threat Name","Severity ID","Severity Name","Category ID","Category Name",
    "FWLink","Status Code","State","Source ID","Source Name","Process Name","Detection User","Path","Origin ID","Origin Name","Execution ID","Execution Name",
    "Type ID","Type Name","Pre Execution Status","Action ID","Action Name","Error Code","Error Description","Post Clean Status","Additional Actions ID","Additional Actions String",
    "Signature Version","Engine Version","Detection Time","DetectionTime"
]

# 보고서용 간단 카테고리
REPORT_CATEGORY_MAP = {
    "logon_logoff":       [4624,4625,4634,4647,4648,4768,4769,4776],
    "service":            [7036,7045,7040,4697],
    "privilege_use":      [4672,4673,4674],
    "process_tracking":   [4688,4689],
    "rdp":                [1149,21,22,23,24,25,4778,4779],
    "system_event":       [6005,6006,6008,6009,6013],
    "defender":           [1116,1117,1118,1119,5001],
    "powershell":         [400,403,4103,4104,4105,4106,800],
}

# =========================
# 유틸/헬퍼
# =========================

def has_col(df: pd.DataFrame, col: str) -> bool:
    return col in df.columns

def _get_ns_root(xml_str: str):
    root = ET.fromstring(xml_str)
    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    return root, ns

def _find_first(root, ns, xpath):
    node = root.find(xpath, ns)
    if node is None:
        node = root.find(xpath.replace("ns:", ""))
    return node

def _extract_data_field(root, ns, name):
    node = _find_first(root, ns, f".//ns:Data[@Name='{name}']")
    if node is None:
        node = root.find(f".//Data[@Name='{name}']")
    return node.text if (node is not None and node.text is not None) else None

def _extract_many(root, ns, names):
    return {n: _extract_data_field(root, ns, n) for n in names}

def _decode_ps_encoded(cmd: str) -> str | None:
    if not cmd:
        return None
    m = re.search(r'(?i)-(?:enc|encodedcommand|e)\s+(?:"([^"]+)"|\'([^\']+)\'|([A-Za-z0-9+/=]+))', cmd)
    b64 = None
    if m:
        b64 = next((g for g in m.groups() if g), None)
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64)
        try:
            return raw.decode("utf-16le", errors="ignore").strip()
        except Exception:
            return raw.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None

def _short(s: str, n: int = 240) -> str:
    if not s:
        return ""
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else (s[:n] + " …")

# 🆕 개선된 함수: Provider 기반 Activity 라벨 반환
def _provider_activity_label(provider: str, event_id: int) -> str:
    """
    Provider + EventID 조합으로 Activity 라벨 반환
    우선순위: ACTIVITY_LABELS_PROVIDER -> ACTIVITY_LABELS -> 기본값
    """
    # 1순위: Provider별 라벨
    key = (provider, event_id)
    if key in ACTIVITY_LABELS_PROVIDER:
        return ACTIVITY_LABELS_PROVIDER[key]
    
    # 2순위: EventID만으로 매핑 (fallback)
    if event_id in ACTIVITY_LABELS:
        return ACTIVITY_LABELS[event_id]
    
    # 3순위: 기본값
    return f"Event {event_id}"

# 🆕 개선된 함수: Provider 기반 MITRE 매핑 반환 (3단계 fallback)
def _provider_mitre(provider: str, event_id: int):
    """
    Provider + EventID 조합으로 MITRE 매핑 반환
    우선순위:
      1) EVENT_MAPPING[provider][event_id] (Provider별 매핑)
      2) MITRE_ATTACK_MAPPING[event_id] (EventID만 매핑)
      3) None
    """
    # 1단계: Provider별 매핑 확인
    if provider in EVENT_MAPPING:
        if event_id in EVENT_MAPPING[provider]:
            return EVENT_MAPPING[provider][event_id]
    
    # 2단계: EventID만으로 fallback
    if event_id in MITRE_ATTACK_MAPPING:
        return MITRE_ATTACK_MAPPING[event_id]
    
    # 3단계: 매핑 없음
    return None

def _ip_match_cidr(ip_str: str, cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        ip = ipaddress.ip_address(ip_str)
        return ip in net
    except Exception:
        return False

def _ps_suspicious_score(ps_text: str | None, decoded: str | None) -> bool:
    hay = " ".join([ps_text or "", decoded or ""]).lower()
    return any(k.lower() in hay for k in PS_SUSPICIOUS_KEYWORDS)

def _ip_scope(ip_str: str):
    if not ip_str:
        return None
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "internal"
        return "external"
    except Exception:
        return None

def facet_options(df: pd.DataFrame, col: str, top: int = 50):
    s = df[col].dropna().astype(str)
    if s.empty:
        return [], {}
    vc = s.value_counts()
    opts = list(vc.head(top).index)
    labels = {v: f"{v} ({int(vc[v])})" for v in opts}
    return opts, labels

def facet_ips(df: pd.DataFrame, top: int = 50):
    cols = [c for c in ["ip_address", "source_ip", "dest_ip"] if c in df.columns]
    if not cols:
        return [], {}
    s = pd.concat([df[c] for c in cols], ignore_index=True).dropna().astype(str)
    if s.empty:
        return [], {}
    vc = s.value_counts()
    opts = list(vc.head(top).index)
    labels = {v: f"{v} ({int(vc[v])})" for v in opts}
    return opts, labels

def _sanitize_field_name(k: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", k)

def _report_category(eid: int) -> str:
    try:
        eid = int(eid)
    except Exception:
        return "unknown"
    for cat, ids in REPORT_CATEGORY_MAP.items():
        if eid in ids:
            return cat
    return "unknown"

# 🆕 개선된 함수: Provider 정보를 포함한 Event 라벨 (UI 표시용)
def _event_label_for_ui(df: pd.DataFrame) -> dict[int, str]:
    """
    Event ID별 라벨 생성 (Provider 정보 포함)
    형식: "EventID · Activity | Tactic/Technique [Provider]"
    """
    labels = {}
    for eid in sorted(pd.Series(df["event_id"]).dropna().unique()):
        try:
            eid = int(eid)
        except Exception:
            continue
        
        # 해당 EventID를 가진 레코드 중 가장 많이 등장하는 Provider 사용
        sub = df[df["event_id"] == eid]
        if sub.empty:
            continue
            
        # Provider 최빈값 추출
        provider_counts = sub["provider"].value_counts(dropna=False)
        provider = provider_counts.idxmax() if not provider_counts.empty else ""
        
        # MITRE 매핑 확인
        m = _provider_mitre(provider, eid)
        activity = _provider_activity_label(provider, eid)
        
        # Provider 이름 간소화 (너무 길 경우)
        prov_short = provider if provider else "N/A"
        if len(prov_short) > 40:
            prov_short = prov_short[:37] + "..."
        
        if m:
            labels[eid] = f"{eid} · {activity} | {m['tactic']}/{m['technique']} [{prov_short}]"
        else:
            desc = EVENT_ID_DESCRIPTIONS.get(eid, activity)
            labels[eid] = f"{eid} · {desc} [{prov_short}]"
    
    return labels

# =========================
# 파서/분석기
# =========================

class EVTXForensicAnalyzer:
    def __init__(self):
        self.events = []
        self.df = pd.DataFrame()

    def parse_evtx_files(self, evtx_files, progress_callback=None) -> pd.DataFrame:
        events = []
        for idx, uploaded in enumerate(evtx_files):
            if progress_callback:
                progress_callback(idx + 1, len(evtx_files), getattr(uploaded, "name", ""))
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as tmp:
                    tmp.write(uploaded.read())
                    tmp_path = tmp.name

                with evtx.Evtx(tmp_path) as log:
                    for record in log.records():
                        try:
                            xml_str = record.xml()
                            root, ns = _get_ns_root(xml_str)

                            event_id_el = _find_first(root, ns, ".//ns:EventID")
                            if event_id_el is None or not event_id_el.text:
                                continue
                            event_id = int(event_id_el.text)

                            time_el = _find_first(root, ns, ".//ns:TimeCreated")
                            ts = time_el.get("SystemTime") if time_el is not None else None
                            timestamp = pd.to_datetime(ts) if ts else pd.Timestamp.now()

                            comp_el = _find_first(root, ns, ".//ns:Computer")
                            computer = comp_el.text if comp_el is not None else "N/A"

                            rec_id_el = _find_first(root, ns, ".//ns:EventRecordID")
                            record_number = int(rec_id_el.text) if rec_id_el is not None else 0

                            channel_el = _find_first(root, ns, ".//ns:Channel")
                            channel = channel_el.text if channel_el is not None else "N/A"

                            provider_el = _find_first(root, ns, ".//ns:Provider")
                            provider = provider_el.get("Name") if provider_el is not None else "N/A"

                            data_fields = _extract_many(root, ns, EXTRA_FIELDS)

                            user = data_fields.get("SubjectUserName") or data_fields.get("TargetUserName") or data_fields.get("User")
                            domain = data_fields.get("SubjectDomainName") or data_fields.get("TargetDomainName")
                            logon_type = data_fields.get("LogonType")

                            process_name = (
                                data_fields.get("NewProcessName") or data_fields.get("ProcessName")
                                or data_fields.get("CreatorProcessName") or data_fields.get("Image")
                            )
                            parent_process = data_fields.get("ParentProcessName") or data_fields.get("ParentImage")
                            command_line = data_fields.get("CommandLine") or data_fields.get("Message") or data_fields.get("Payload")
                            parent_cmd = data_fields.get("ParentCommandLine")

                            ip_address = (
                                data_fields.get("IpAddress") or data_fields.get("SourceAddress")
                                or data_fields.get("DestAddress")
                            )

                            ps_script_block = data_fields.get("ScriptBlockText")
                            ps_host_app = data_fields.get("HostApplication")
                            ps_decoded = _decode_ps_encoded(command_line)
                            if not ps_script_block and provider in ("PowerShell", "Microsoft-Windows-PowerShell") and data_fields.get("Message"):
                                ps_script_block = data_fields.get("Message")

                            base = {
                                "timestamp": timestamp,
                                "event_id": event_id,
                                "source": getattr(uploaded, "name", ""),
                                "computer": computer,
                                "record_number": record_number,
                                "channel": channel,
                                "provider": provider,
                                "xml_data": xml_str,

                                "user": user,
                                "domain": domain,
                                "logon_type": logon_type,
                                "process_name": process_name,
                                "parent_process": parent_process,
                                "command_line": command_line,
                                "parent_command_line": parent_cmd,

                                "ip_address": ip_address,
                                "source_ip": data_fields.get("SourceAddress"),
                                "source_port": data_fields.get("SourcePort"),
                                "dest_ip": data_fields.get("DestAddress"),
                                "dest_port": data_fields.get("DestPort"),
                                "protocol": data_fields.get("Protocol"),

                                "service_name": data_fields.get("ServiceName"),
                                "task_name": data_fields.get("TaskName"),
                                "share_name": data_fields.get("ShareName"),
                                "object_name": data_fields.get("ObjectName"),
                                "object_type": data_fields.get("ObjectType"),

                                "ps_command": ps_script_block,
                                "ps_host_app": ps_host_app,
                                "ps_decoded": ps_decoded,

                                "dns_query": data_fields.get("QueryName"),
                                "dns_status": data_fields.get("QueryStatus"),
                                "dns_results": data_fields.get("QueryResults"),
                                "hashes": data_fields.get("Hashes"),
                            }

                            # 모든 EXTRA_FIELDS를 안전한 컬럼명으로 부가 저장(보고서/상세 출력용)
                            for k, v in data_fields.items():
                                base[_sanitize_field_name(k)] = v

                            # 🆕 Provider 기반 MITRE 매핑
                            m = _provider_mitre(provider, event_id)
                            if m:
                                base.update({
                                    "mitre_technique": m["technique"],
                                    "mitre_tactic": m["tactic"],
                                    "mitre_name": m["name"],
                                    "description": m["description"],
                                    "severity": m["severity"],
                                    "is_forensic": True,
                                })
                            else:
                                desc = EVENT_ID_DESCRIPTIONS.get(event_id, f"Event ID {event_id}")
                                base.update({
                                    "mitre_technique": None, "mitre_tactic": None, "mitre_name": None,
                                    "description": desc if isinstance(desc, str) else str(desc),
                                    "severity": "info", "is_forensic": False,
                                })

                            base["suspicious"] = (event_id in SUSPICIOUS_PATTERNS)
                            base["alert"] = SUSPICIOUS_PATTERNS.get(event_id)

                            events.append(base)
                        except Exception:
                            continue
            except Exception as e:
                st.warning(f"파싱 실패: {getattr(uploaded, 'name', '')} - {e}")
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    try: os.unlink(tmp_path)
                    except Exception: pass

        self.events = events
        self.df = pd.DataFrame(events) if events else pd.DataFrame()
        if not self.df.empty:
            self.df = add_derived_fields(self.df)
        return self.df

# 파생 필드
def add_derived_fields(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # 🆕 Provider 기반 activity 라벨
    df["activity"] = df.apply(
        lambda r: _provider_activity_label(r.get("provider",""), int(r.get("event_id"))),
        axis=1
    )
    df["logon_type_label"] = df["logon_type"].astype(str).map(LOGON_TYPE_MAP)
    df["date"] = pd.to_datetime(df["timestamp"]).dt.date
    df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour

    df["ps_flag"] = df.apply(lambda r: _ps_suspicious_score(r.get("ps_command"), r.get("ps_decoded")), axis=1)
    df.loc[df["ps_flag"] == True, "suspicious"] = True
    df.loc[df["ps_flag"] == True, "alert"] = df["alert"].fillna("의심스러운 PowerShell 패턴 감지")

    df["ip_scope"] = df["ip_address"].apply(_ip_scope)
    df["is_external_ip"] = df["ip_scope"].eq("external")

    # 보고서용 카테고리
    df["report_category"] = df["event_id"].apply(_report_category)

    return df

# =========================
# 권장 조치(카드에 사용)
# =========================
def recommend_guidance(event: pd.Series) -> str:
    eid = event.get("event_id")
    act = event.get("activity","")
    provider = event.get("provider","")

    if eid in (1102, 104):
        return "증거보전(메모리/디스크/관련 호스트), 관리자 행위 대조, 로깅/감사정책 복구 및 비교"
    if act == "로그온 실패":
        return "계정·IP·호스트별 실패 패턴/시간대 분석, RDP/SMB 상관, 계정 잠금·정책 튜닝"
    if act in ("새 서비스 설치","서비스 설치"):
        return "바이너리 경로·서명·해시 수집, 시작유형/설치주체 확인, 자동시작 항목 점검"
    if act.startswith("스케줄 작업"):
        return "작업명/작성자/트리거/실행명령 확인, 작업폴더/바이너리 무결성·서명 검사"
    if act.startswith("RDP"):
        return "1149/21~25/4778/4779 상관, 외부 IP 검증, MFA/네트워크 ACL 점검"
    if eid == 4688 or (provider.startswith("Microsoft-Windows-Sysmon") and eid in (1,10)):
        return "명령줄·부모/자식 트리, 서명/해시/평판 분석"
    if provider in ("PowerShell","Microsoft-Windows-PowerShell") and eid in (4103,4104,800):
        return "ScriptBlock 원문/복원문 리뷰, -enc/-bypass/AMSI 우회 확인, AMSI/WDAC 정책 점검"
    if eid == 4719:
        return "감사정책 변경 주체/사유 확인, 이전 스냅샷 비교, 완화 설정 점검"
    return ""

# =========================
# 간단 필터 적용
# =========================

def apply_simple(df: pd.DataFrame,
                 users=None, computers=None,
                 ips=None, extra_ip_terms=None, external_only=False,
                 activities=None, event_ids=None,
                 start_date=None, end_date=None, hour_range=(0,23),
                 keyword=None, off_hours_only=False, business_hours=(9,18)):
    out = df.copy()

    if start_date and end_date:
        out = out[(out["timestamp"].dt.date >= start_date) & (out["timestamp"].dt.date <= end_date)]
    if hour_range:
        out = out[(out["hour"] >= hour_range[0]) & (out["hour"] <= hour_range[1])]

    if off_hours_only and business_hours and len(business_hours) == 2:
        s, e = business_hours
        out = out[~((out["hour"] >= s) & (out["hour"] < e))]

    if users:     out = out[out["user"].isin(users)]
    if computers: out = out[out["computer"].isin(computers)]
    if activities: out = out[out["activity"].isin(activities)]
    if event_ids:  out = out[out["event_id"].isin(event_ids)]

    if ips:
        out = out[out["ip_address"].isin(ips) | out["source_ip"].isin(ips) | out["dest_ip"].isin(ips)]

    if extra_ip_terms:
        terms = []
        for t in extra_ip_terms:
            if t:
                terms.extend(re.split(r"[,\s]+", t.strip()))
        terms = [t for t in terms if t]
        if terms:
            ip_mask = pd.Series(False, index=out.index)
            for term in terms:
                if "/" in term:
                    ip_mask = ip_mask | out["ip_address"].fillna("").apply(lambda x: _ip_match_cidr(x, term)) \
                                       | out["source_ip"].fillna("").apply(lambda x: _ip_match_cidr(x, term)) \
                                       | out["dest_ip"].fillna("").apply(lambda x: _ip_match_cidr(x, term))
                else:
                    for col in ["ip_address","source_ip","dest_ip"]:
                        ip_mask = ip_mask | out[col].astype(str).str.contains(term, na=False)
            out = out[ip_mask]

    if external_only and "is_external_ip" in out.columns:
        out = out[out["is_external_ip"] == True]

    if keyword:
        cols = ["user","activity","description","process_name","parent_process","command_line","parent_command_line",
                "ps_command","ps_decoded","ip_address","computer","domain","provider","channel",
                "service_name","task_name","share_name","object_name","object_type","dns_query","hashes"]
        mask = pd.Series(False, index=out.index)
        for c in cols:
            if c in out.columns:
                mask |= out[c].astype(str).str.contains(keyword, case=False, na=False)
        try:
            kid = int(keyword)
            mask |= (out["event_id"] == kid)
        except Exception:
            pass
        out = out[mask]

    return out

# =========================
# 카드 렌더링
# =========================

def render_event_card(event: pd.Series) -> str:
    sev = event.get("severity", "info")
    color = SEVERITY_COLORS.get(sev, "#17a2b8")
    icon = SEVERITY_ICONS.get(sev, "🔵")
    border = "border-left:5px solid #dc3545;" if event.get("suspicious", False) else f"border-left:5px solid {color};"
    bg = "#fff5f5" if event.get("suspicious", False) else "#ffffff"

    ts = pd.to_datetime(event["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
    activity = event.get("activity", event.get("description", ""))

    d = []
    if event.get("user"): d.append(f"👤 {event['user']}")
    if event.get("computer"): d.append(f"💻 {event['computer']}")
    if event.get("ip_address"): d.append(f"🌐 {event['ip_address']}")
    if event.get("process_name"): d.append(f"⚙️ {event['process_name']}")
    if event.get("parent_process"): d.append(f"🧬 Parent: {event['parent_process']}")
    if event.get("command_line"): d.append(f"🧵 {_short(event['command_line'])}")

    net = ""
    if event.get("source_ip") or event.get("dest_ip"):
        src = f"{event.get('source_ip','')}:{event.get('source_port','')}".strip(":")
        dst = f"{event.get('dest_ip','')}:{event.get('dest_port','')}".strip(":")
        proto = event.get("protocol", "")
        net = f"<div style='color:#666;font-size:12px;'>🔌 {src} ➝ {dst} {proto}</div>"

    ps_snip = ""
    if event.get("ps_decoded") or event.get("ps_command"):
        ps_txt = _short(event.get("ps_decoded") or event.get("ps_command"))
        ps_snip = f"<div style='margin-top:6px;font-size:12px;color:#333;background:#f0f6ff;padding:6px;border-radius:6px;'>📜 PS: {ps_txt}</div>"

    mitre = f"🎯 {event.get('mitre_tactic','N/A')} | 🔧 {event.get('mitre_technique','N/A')} | 🆔 {event['event_id']}"

    guidance = recommend_guidance(event)
    guide_html = f"<div style='margin-top:8px;padding:8px;background:#f7f7ff;border-radius:6px;color:#333;font-size:12px;'>🧭 권장 조치: {guidance}</div>" if guidance else ""

    alert_html = f"<div style='margin-top:8px;padding:8px;background:#ffe6e6;border-radius:6px;color:#d32f2f;font-weight:bold;'>{event.get('alert','')}</div>" if event.get("suspicious", False) else ""

    return f"""
    <div style="border-radius:10px;padding:15px;margin:10px 0;background-color:{bg};{border};box-shadow:0 2px 4px rgba(0,0,0,0.1);">
      <div style="font-size:16px;font-weight:bold;margin-bottom:6px;">{icon} {activity}</div>
      <div style="color:#666;font-size:13px;margin-bottom:6px;">🕒 {ts} &nbsp; | &nbsp; 📦 {event.get('provider','N/A')} / {event.get('channel','')}</div>
      <div style="color:#333;font-size:13px;margin-bottom:6px;">{" &nbsp; ".join(d)}</div>
      {net}
      {ps_snip}
      <div style="margin-top:6px;font-size:12px;color:#888;">{mitre}</div>
      {guide_html}
      {alert_html}
    </div>
    """

# =========================
# 보고서 생성기
# =========================

def _hour_bar(n, max_n, width=40, char="█"):
    if max_n <= 0:
        return ""
    k = int(round((n / max_n) * width))
    return char * k

def build_text_report(df: pd.DataFrame, tz: str, start_date, end_date, max_items: int = 50) -> str:
    if df.empty:
        return "데이터가 없습니다."

    # 타임존 변환(KST 등)
    ts_local = pd.to_datetime(df["timestamp"], utc=True).dt.tz_convert(tz)
    dfx = df.copy()
    dfx["ts_local"] = ts_local
    dfx["date_local"] = ts_local.dt.date
    dfx["hour_local"] = ts_local.dt.hour

    # 범위 내/외
    in_mask = (dfx["date_local"] >= start_date) & (dfx["date_local"] <= end_date)
    in_df  = dfx[in_mask].copy()
    out_df = dfx[~in_mask].copy()

    total_in = len(in_df)
    total_out = len(out_df)
    susp_in = int(in_df.get("suspicious", pd.Series([False]*len(in_df))).fillna(False).sum())

    users_in = in_df["user"].dropna().astype(str).nunique()
    ips_in = in_df["ip_address"].dropna().astype(str).nunique()

    # 파일별 통계
    lines_files = []
    for src, grp in dfx.groupby("source"):
        in_idx  = grp.index.intersection(in_df.index)
        out_idx = grp.index.difference(in_idx)
        in_cnt  = len(in_idx)
        out_cnt = len(out_idx)
        susp_cnt = int(in_df.loc[in_idx].get("suspicious", pd.Series([False]*len(in_idx))).fillna(False).sum()) if len(in_idx)>0 else 0
        lines_files.append((src, in_cnt, out_cnt, susp_cnt))
    lines_files.sort(key=lambda x: (-x[1], x[0]))

    # 카테고리 통계(보고서용)
    cat = in_df["report_category"].value_counts()
    cat_total = cat.sum()
    lines_cats = []
    for k, v in cat.items():
        pct = (v / cat_total * 100.0) if cat_total else 0.0
        lines_cats.append((k, v, pct))

    # 시간대 통계
    by_hour = in_df["hour_local"].value_counts().reindex(range(24), fill_value=0)
    max_hour = by_hour.max()

    # Top Event ID
    top_eids = in_df["event_id"].value_counts().head(20)
    labels = _event_label_for_ui(in_df)

    # 사용자별 통계
    success_eids = {4624, 1149}
    fail_eid = 4625
    user_stats = []
    user_group = in_df.groupby(in_df["user"].fillna("-"))
    for u, g in user_group:
        total = len(g)
        succ = int(g["event_id"].isin(success_eids).sum())
        fail = int((g["event_id"] == fail_eid).sum())
        rate = (fail / (succ + fail) * 100.0) if (succ + fail) > 0 else 0.0
        user_stats.append((str(u), total, succ, fail, rate))
    user_stats.sort(key=lambda x: (-x[1], x[0]))
    user_stats = user_stats[:20]

    # IP별 통계
    ip_stats = []
    ip_group = in_df[in_df["ip_address"].notna()].groupby(in_df["ip_address"])
    for ip, g in ip_group:
        total = len(g)
        succ = int(g["event_id"].isin(success_eids).sum())
        fail = int((g["event_id"] == fail_eid).sum())
        rate = (fail / (succ + fail) * 100.0) if (succ + fail) > 0 else 0.0
        ip_stats.append((str(ip), total, succ, fail, rate))
    ip_stats.sort(key=lambda x: (-x[1], x[0]))
    ip_stats = ip_stats[:20]

    # 헤더
    now_local = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = []
    report.append("="*80)
    report.append("포렌식 이벤트 로그 분석 보고서 (KST 등 타임존 적용 + 날짜 필터)")
    report.append("="*80)
    report.append(f"\n분석 일시 ({tz}): {now_local} {tz}")
    report.append(f"타임존: {tz}")

    report.append("\n[날짜 범위 필터링]")
    report.append(f"  시작: {start_date} 00:00:00 {tz}")
    report.append(f"  종료: {end_date} 23:59:59 {tz}")

    report.append(f"\n총 중요 이벤트 수: {total_in}")
    report.append(f"날짜 범위 외 제외: {total_out}")
    report.append(f"의심스러운 이벤트 수: {susp_in}")
    report.append(f"분석된 사용자 수: {users_in}")
    report.append(f"분석된 IP 주소 수: {ips_in}")

    report.append("\n파일별 이벤트 수:")
    report.append("-"*80)
    for src, a, b, c in lines_files:
        report.append(f"  {src:<50} | 분석됨: {a:7d} | 제외됨: {b:7d} | 의심: {c:7d}")

    report.append("\n카테고리별 이벤트 통계:")
    report.append("-"*80)
    for k, v, pct in lines_cats:
        report.append(f"  {k:<20}: {v:6d} ({pct:5.1f}%)")

    report.append("\n시간대별 활동 통계:")
    report.append("-"*80)
    for h in range(24):
        n = int(by_hour.get(h, 0))
        bar = _hour_bar(n, max_hour, width=40, char="█")
        report.append(f"  {h:02d}:00 - {h:02d}:59 : {n:6d} {bar}")

    report.append("\n가장 빈번한 이벤트 ID (상위 20개):")
    report.append("-"*80)
    for eid, cnt in top_eids.items():
        pct = (cnt / total_in * 100.0) if total_in else 0.0
        lab = labels.get(int(eid), f"Event {eid}")
        lab_simple = lab.split("·", 1)[-1].strip() if "·" in lab else lab
        report.append(f"  [{int(eid):5d}] {lab_simple:<50} : {cnt:6d} ({pct:5.1f}%)")

    report.append("\n사용자별 활동 통계 (상위 20개):")
    report.append("-"*80)
    report.append(f"{'Username':<30} {'Total':>6}  {'Success':>7}  {'Failed':>7}  {'FailRate':>8}")
    report.append("-"*80)
    for u, t, s, fcnt, rate in user_stats:
        report.append(f"{u:<30} {t:6d}  {s:7d}  {fcnt:7d}  {rate:7.1f}%")

    report.append("\nIP 주소별 활동 통계 (상위 20개):")
    report.append("-"*80)
    report.append(f"{'IP Address':<30} {'Total':>6}  {'Success':>7}  {'Failed':>7}  {'FailRate':>8}")
    report.append("-"*80)
    for ip, t, s, fcnt, rate in ip_stats:
        report.append(f"{ip:<30} {t:6d}  {s:7d}  {fcnt:7d}  {rate:7.1f}%")

    # 🆕 의심 활동 상세 섹션 제거 (기존 코드 삭제)
    # 요약 통계만 제공하고 개별 이벤트는 출력하지 않음
    
    report.append("\n" + "="*80)
    report.append("보고서 종료")
    report.append("="*80)

    return "\n".join(report)


# =========================
# 메인 앱
# =========================

def main():
    st.set_page_config(page_title="Windows 이벤트 로그 포렌식 분석기", layout="wide")
    st.title("🔍 Windows 이벤트 로그 포렌식 분석기 (Provider + EventID 기반)")

    # 세션 상태
    if "analyzer" not in st.session_state:
        st.session_state.analyzer = EVTXForensicAnalyzer()
    if "df" not in st.session_state:
        st.session_state.df = pd.DataFrame()
    if "bookmarks" not in st.session_state:
        st.session_state.bookmarks = []

    # 사이드바: 업로드/파싱
    with st.sidebar:
        st.header("📁 파일 업로드")
        mode_upload = st.radio("업로드 방식", ["폴더 경로", "개별 파일"], horizontal=True)
        files = []

        if mode_upload == "폴더 경로":
            folder = st.text_input("폴더 경로", placeholder=r"C:\extracted_logs\winevt\Logs")
            if folder and os.path.exists(folder):
                paths = list(Path(folder).glob("*.evtx"))
                st.caption(f"발견: {len(paths)} 개")
                if st.button("🚀 분석 시작", type="primary"):
                    class FileWrapper:
                        def __init__(self, p): self.path=p; self.name=p.name
                        def read(self): return open(self.path, "rb").read()
                    files = [FileWrapper(p) for p in paths]
            elif folder:
                st.error("경로가 존재하지 않습니다.")
        else:
            ups = st.file_uploader(".evtx 선택", type=["evtx"], accept_multiple_files=True)
            if ups:
                st.caption(f"선택: {len(ups)} 개")
                if st.button("🚀 분석 시작", type="primary"):
                    files = ups

        st.markdown("---")

        if files:
            with st.spinner("파싱 중..."):
                progress_text = st.empty()
                progress_bar = st.progress(0)
                def cb(cur, total, name):
                    progress_bar.progress(int(cur/total*100))
                    progress_text.text(f"{cur}/{total} - {name}")
                df = st.session_state.analyzer.parse_evtx_files(files, cb)
                st.session_state.df = df
                progress_bar.progress(100)
                progress_text.text("완료")
                if not df.empty:
                    st.success(f"총 {len(df):,} 이벤트")
                    if has_col(df,"is_forensic"):
                        st.info(f"포렌식 중요: {int(df['is_forensic'].sum()):,}")
                    st.balloons()
                else:
                    st.warning("이벤트가 없습니다.")

        # 요약 메트릭
        st.markdown("---")
        df = st.session_state.df
        if not df.empty:
            st.metric("총 이벤트", f"{len(df):,}")
            st.metric("고유 Event ID", f"{df['event_id'].nunique():,}")
            st.metric("컴퓨터 수", f"{df['computer'].nunique():,}")

    # 메인
    df = st.session_state.df
    if df.empty:
        st.info("사이드바에서 로그를 불러오세요.")
        return

    tab_dash, tab_explore, tab_susp, tab_ps, tab_bm, tab_export, tab_report = st.tabs(
        ["📊 대시보드", "🔍 탐색(간단)", "⚠️ 의심 활동", "📜 PowerShell", "🔖 북마크", "📤 내보내기", "📑 보고서"]
    )

    # ====== 대시보드 ======
    with tab_dash:
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("전체 이벤트", f"{len(df):,}")
        c2.metric("포렌식 중요", f"{int(df.get('is_forensic', pd.Series([False]*len(df))).sum()):,}")
        c3.metric("심각", f"{int((df['severity']=='critical').sum()):,}")
        c4.metric("경고", f"{int((df['severity']=='warning').sum()):,}")
        c5.metric("의심", f"{int(df.get('suspicious', pd.Series([False]*len(df))).sum()):,}")

        st.markdown("---")
        c1, c2, c3 = st.columns(3)
        c1.info(f"분석 기간: {df['timestamp'].min().strftime('%Y-%m-%d')} ~ {df['timestamp'].max().strftime('%Y-%m-%d')}")
        c2.info(f"고유 Event ID: {df['event_id'].nunique()}개")
        c3.info(f"대상 컴퓨터: {df['computer'].nunique()}대")

        st.markdown("---")
        c1, c2 = st.columns(2)
        with c1:
            series = df.groupby("date").size().reset_index(name="count")
            fig = px.line(series, x="date", y="count", title="일별 이벤트 추이")
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            sev_counts = df["severity"].value_counts().rename_axis("severity").reset_index(name="count")
            sev_label = {'critical':'🔴 심각', 'warning':'🟡 경고', 'info':'🔵 정보'}
            sev_counts["label"] = sev_counts["severity"].map(sev_label)
            fig = px.pie(sev_counts, values="count", names="label", title="심각도 분포")
            st.plotly_chart(fig, use_container_width=True)

        c1, c2 = st.columns(2)
        with c1:
            top_activity = df["activity"].value_counts().head(12).rename_axis("activity").reset_index(name="count")
            fig = px.bar(top_activity, x="count", y="activity", orientation="h", title="가장 많은 활동 (Top 12)")
            fig.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            if has_col(df,"is_forensic") and df["is_forensic"].any():
                tactic_counts = df[df["is_forensic"]]["mitre_tactic"].value_counts().rename_axis("tactic").reset_index(name="count")
                fig = px.bar(tactic_counts, x="count", y="tactic", orientation="h", title="MITRE 전술 분포")
                fig.update_layout(yaxis={'categoryorder': 'total ascending'})
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("MITRE 매핑 이벤트 없음")

    # ====== 탐색(간단) ======
    with tab_explore:
        st.subheader("간단 필터")
        min_d, max_d = df["timestamp"].min().date(), df["timestamp"].max().date()
        colA, colB, colC, colD = st.columns([1,1,1,1])
        start_date = colA.date_input("시작", value=min_d, min_value=min_d, max_value=max_d)
        end_date   = colB.date_input("종료", value=max_d, min_value=min_d, max_value=max_d)
        hour_range = colC.slider("시간(시)", 0, 23, (0,23))
        off_hours_only = colD.checkbox("비업무시간만", value=False)

        st.markdown("---")

        users_opt, users_lbl = facet_options(df, "user", top=100)
        comps_opt, comps_lbl = facet_options(df, "computer", top=100)
        ips_opt, ips_lbl = facet_ips(df, top=100)
        acts_opt, acts_lbl = facet_options(df, "activity", top=50)

        c1, c2, c3 = st.columns(3)
        users_sel = c1.multiselect("사용자", options=users_opt, format_func=lambda x: users_lbl.get(x,x))
        comps_sel = c2.multiselect("컴퓨터", options=comps_opt, format_func=lambda x: comps_lbl.get(x,x))
        ips_sel   = c3.multiselect("IP", options=ips_opt, format_func=lambda x: ips_lbl.get(x,x))

        st.markdown("---")
        c4, c5 = st.columns([2,1])
        acts_sel = c4.multiselect("행동(설명)", options=acts_opt, format_func=lambda x: acts_lbl.get(x,x))
        ext_only = c5.checkbox("외부 IP만", value=False)

        st.markdown("#### 의심행동 빠른 선택")
        eid_present = set(int(x) for x in pd.Series(df["event_id"]).dropna().unique())
        quick_map = {}
        cols = st.columns(5)
        i = 0
        for name, eids in SIMPLE_FILTERS.items():
            if eid_present.intersection(set(eids)):
                checked = cols[i % 5].checkbox(name, value=False)
                if checked:
                    quick_map[name] = eids
                i += 1

        st.markdown("---")
        k1, k2 = st.columns([2,1])
        keyword = k1.text_input("🔎 전역 검색(사용자/프로세스/명령줄/PowerShell/객체/해시/도메인 등)")
        ip_extra = k2.text_area("IP/CIDR 추가 입력", help="쉼표·공백·줄바꿈 구분. 예: 1.2.3.4, 10.0.0.0/8")

        chosen_eids = []
        for _, eids in quick_map.items():
            chosen_eids.extend(eids)

        filtered = apply_simple(
            df,
            users=users_sel or None,
            computers=comps_sel or None,
            ips=ips_sel or None,
            extra_ip_terms=[ip_extra] if ip_extra else None,
            external_only=ext_only,
            activities=acts_sel or None,
            event_ids=chosen_eids or None,
            start_date=start_date, end_date=end_date,
            hour_range=hour_range,
            keyword=keyword or None,
            off_hours_only=off_hours_only,
            business_hours=(9,18)
        )

        st.markdown("---")
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("필터 결과", f"{len(filtered):,}")
        c2.metric("심각", f"{int((filtered['severity']=='critical').sum()):,}")
        c3.metric("경고", f"{int((filtered['severity']=='warning').sum()):,}")
        c4.metric("정보", f"{int((filtered['severity']=='info').sum()):,}")
        c5.metric("고유 Event ID", f"{filtered['event_id'].nunique():,}")

        if not filtered.empty:
            with st.expander("Event ID 분포 / 시간대 분포", expanded=False):
                cc1, cc2 = st.columns(2)
                top_ids = filtered["event_id"].value_counts().head(12).rename_axis("event_id").reset_index(name="count")
                top_ids["label"] = top_ids["event_id"].apply(lambda x: _event_label_for_ui(filtered).get(x, str(x)))
                fig = px.bar(top_ids, x="count", y="label", orientation="h", title="최다 Event ID (Top 12)")
                fig.update_layout(yaxis={'categoryorder':'total ascending'})
                cc1.plotly_chart(fig, use_container_width=True)

                by_hour = filtered.groupby("hour").size().reset_index(name="count")
                fig = px.bar(by_hour, x="hour", y="count", title="시간대 분포")
                cc2.plotly_chart(fig, use_container_width=True)

            colv1, colv2, colv3 = st.columns([2,1,1])
            colv1.subheader("이벤트 목록")
            sort_order = colv2.radio("정렬", ["최신순","오래된순"], horizontal=True)
            view_mode  = colv3.radio("보기", ["카드뷰","테이블뷰"], horizontal=True)

            filtered = filtered.sort_values("timestamp", ascending=(sort_order=="오래된순"))

            if view_mode == "테이블뷰":
                cols = [
                    'timestamp','event_id','activity','severity','provider','channel','user','domain','computer',
                    'ip_address','source_ip','source_port','dest_ip','dest_port','protocol',
                    'process_name','parent_process','command_line','parent_command_line',
                    'ps_host_app','ps_command','ps_decoded',
                    'logon_type_label','service_name','task_name','share_name'
                ]
                show_cols = st.multiselect("표시 컬럼", cols, default=[
                    'timestamp','event_id','activity','user','computer','ip_address','process_name','ps_decoded'
                ])
                tdf = filtered[show_cols].copy()
                if 'timestamp' in tdf.columns:
                    tdf['timestamp'] = pd.to_datetime(tdf['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
                st.dataframe(tdf, use_container_width=True, height=600)
                st.download_button(
                    "📥 CSV 다운로드",
                    tdf.to_csv(index=False),
                    file_name=f"filtered_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
            else:
                page_size = 20
                total_pages = (len(filtered)-1)//page_size + 1
                page = st.number_input("페이지", min_value=1, max_value=max(1,total_pages), value=1, step=1)
                s, e = (page-1)*page_size, min(page*page_size, len(filtered))
                st.caption(f"{page}/{total_pages} (이벤트 {s+1}-{e}/{len(filtered)})")
                for _, row in filtered.iloc[s:e].iterrows():
                    st.markdown(render_event_card(row), unsafe_allow_html=True)
                    with st.expander("🔍 상세/작업"):
                        c1, c2 = st.columns([3,1])
                        with c1:
                            st.write(f"- Event ID: {row['event_id']}")
                            st.write(f"- 소스: {row['source']} | Channel: {row.get('channel','')} | Provider: {row.get('provider','')}")
                            st.write(f"- 레코드 번호: {row.get('record_number','')}")
                            if row.get("domain"):           st.write(f"- 도메인: {row['domain']}")
                            if row.get("logon_type_label"): st.write(f"- 로그온 유형: {row['logon_type_label']}")
                            if row.get("service_name"):     st.write(f"- 서비스: {row['service_name']}")
                            if row.get("task_name"):        st.write(f"- 작업: {row['task_name']}")
                            if row.get("share_name"):       st.write(f"- 공유: {row['share_name']}")
                            if row.get("object_name"):      st.write(f"- 객체: {row['object_name']} ({row.get('object_type','')})")
                            if row.get("dns_query"):        st.write(f"- DNS: {row['dns_query']} / {row.get('dns_status','')} / {row.get('dns_results','')}")
                            if row.get("mitre_technique"):
                                st.markdown("**MITRE:**")
                                st.write(f"- 전술: {row['mitre_tactic']}")
                                st.write(f"- 기법: {row['mitre_technique']} - {row['mitre_name']}")
                                tech_id = str(row['mitre_technique']).replace('.','/')
                                st.markdown(f"[MITRE 문서](https://attack.mitre.org/techniques/{tech_id}/)")
                        with c2:
                            idx = row.name
                            if st.button("🔖 북마크", key=f"bm_{idx}"):
                                if idx not in st.session_state.bookmarks:
                                    st.session_state.bookmarks.append(idx)
                                    st.success("북마크 추가됨")
                                else:
                                    st.info("이미 북마크됨")
                        with st.expander("📄 원본 XML"):
                            st.code(row["xml_data"], language="xml")
        else:
            st.warning("필터 결과가 없습니다.")

    # ====== 의심 활동 ======
    with tab_susp:
        susp = df[df.get("suspicious", pd.Series([False]*len(df))) == True]
        if susp.empty:
            st.success("의심 활동 없음")
        else:
            st.error(f"의심 활동 {len(susp):,}건")
            c1, c2, c3 = st.columns(3)
            c1.metric("로그 삭제", int(susp["event_id"].isin([1102,104]).sum()))
            c2.metric("로그온 실패", int((susp["event_id"]==4625).sum()))
            c3.metric("신규 계정", int((susp["event_id"]==4720).sum()))

            st.markdown("---")
            with st.expander("유형/시간 분포", expanded=True):
                cc1, cc2 = st.columns(2)
                sc = susp["activity"].value_counts().rename_axis("activity").reset_index(name="count")
                cc1.plotly_chart(px.bar(sc, x="count", y="activity", orientation="h", title="의심 활동 유형"), use_container_width=True)
                by_hour = susp.groupby("hour").size().reset_index(name="count")
                cc2.plotly_chart(px.line(by_hour, x="hour", y="count", markers=True, title="시간대별 의심 활동"), use_container_width=True)

            with st.expander("패턴 분석: 실패 로그온 상위"):
                f = susp[susp["event_id"]==4625]
                if not f.empty:
                    u = f["user"].value_counts().head(10)
                    ip = f[f["ip_address"].notna()]["ip_address"].value_counts().head(10)
                    st.write("계정별 실패 Top10:"); st.write(u)
                    st.write("IP별 실패 Top10:");   st.write(ip)

            st.markdown("---")
            st.subheader("최근 의심 활동(최대 50)")
            for _, row in susp.sort_values("timestamp", ascending=False).head(50).iterrows():
                st.markdown(render_event_card(row), unsafe_allow_html=True)

    # ====== PowerShell ======
    with tab_ps:
        ps = df[(df["provider"].isin(["Microsoft-Windows-PowerShell","PowerShell"])) | df["ps_command"].notna() | df["ps_decoded"].notna()]
        if ps.empty:
            st.info("PowerShell 관련 로그 없음")
        else:
            st.metric("PS 이벤트", len(ps))
            c1, c2 = st.columns(2)
            with c1:
                top_cmd = ps["process_name"].value_counts().head(10).rename_axis("process").reset_index(name="count")
                st.plotly_chart(px.bar(top_cmd, x="count", y="process", orientation="h", title="프로세스 Top"), use_container_width=True)
            with c2:
                ps_user = ps["user"].value_counts().head(10).rename_axis("user").reset_index(name="count")
                st.plotly_chart(px.bar(ps_user, x="count", y="user", orientation="h", title="사용자 Top"), use_container_width=True)

            st.markdown("---")
            st.subheader("최근 PowerShell 스니펫(복원문 우선, 최대 50)")
            for _, row in ps.sort_values("timestamp", ascending=False).head(50).iterrows():
                st.markdown(render_event_card(row), unsafe_allow_html=True)

    # ====== 북마크 ======
    with tab_bm:
        bms = st.session_state.bookmarks
        if not bms:
            st.info("북마크 없음")
        else:
            st.success(f"북마크 {len(bms)}건")
            if st.button("모두 삭제"):
                st.session_state.bookmarks = []
                st.rerun()
            sub = df.loc[bms].sort_values("timestamp", ascending=False)
            for idx, row in sub.iterrows():
                st.markdown(render_event_card(row), unsafe_allow_html=True)
                with st.expander("상세"):
                    st.write(f"소스: {row['source']} / 레코드: {row['record_number']}")
                    if st.button("이 북마크 삭제", key=f"del_bm_{idx}"):
                        st.session_state.bookmarks.remove(idx)
                        st.rerun()

    # ====== 내보내기 ======
    with tab_export:
        st.subheader("데이터 내보내기")
        col1, col2 = st.columns(2)
        fmt = col1.radio("형식", ["CSV","JSON","HTML"])
        scope = col2.radio("범위", ["전체","포렌식 중요","의심 활동","북마크"])
        include_xml = st.checkbox("XML 포함", value=False)

        if st.button("📥 내보내기 생성", type="primary"):
            if scope == "전체":
                edf = df.copy()
            elif scope == "포렌식 중요":
                edf = df[df.get("is_forensic", pd.Series([False]*len(df))) == True].copy()
            elif scope == "의심 활동":
                edf = df[df.get("suspicious", pd.Series([False]*len(df))) == True].copy()
            else:
                bms = st.session_state.bookmarks
                edf = df.loc[bms].copy() if bms else pd.DataFrame()

            if edf.empty:
                st.warning("내보낼 데이터가 없습니다.")
            else:
                if not include_xml:
                    edf = edf.drop(columns=["xml_data"], errors="ignore")

                if fmt == "CSV":
                    st.download_button(
                        "CSV 다운로드",
                        edf.to_csv(index=False),
                        file_name=f"forensic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
                elif fmt == "JSON":
                    st.download_button(
                        "JSON 다운로드",
                        edf.to_json(orient="records", date_format="iso", indent=2),
                        file_name=f"forensic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
                else:
                    suspicious_html = ""
                    if "suspicious" in edf.columns and edf["suspicious"].any():
                        suspicious_html = edf[edf["suspicious"]==True][["timestamp","activity","user","computer","alert"]].to_html(index=False, border=0)
                    html = f"""
                    <!doctype html>
                    <html><head><meta charset="utf-8"><title>Forensic Report</title>
                    <style>
                    body{{font-family:Segoe UI,Arial,sans-serif;margin:20px;background:#f5f5f5}}
                    .box{{background:#fff;border-radius:8px;padding:16px;margin:12px 0;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
                    h1{{margin:0 0 8px 0}}
                    table{{width:100%;border-collapse:collapse}}
                    th{{background:#667eea;color:#fff;padding:8px;text-align:left}}
                    td{{padding:8px;border-bottom:1px solid #eee}}
                    </style></head><body>
                    <div class="box">
                      <h1>Windows 이벤트 로그 포렌식 분석 보고서</h1>
                      <div>생성: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                      <div>전체: {len(edf):,} / 포렌식 중요: {int(edf.get('is_forensic', pd.Series([False]*len(edf))).sum()):,} / 의심: {int(edf.get('suspicious', pd.Series([False]*len(edf))).sum()):,}</div>
                      <div>기간: {edf['timestamp'].min()} ~ {edf['timestamp'].max()}</div>
                      <div>Event ID: {edf['event_id'].nunique()} / 컴퓨터: {edf['computer'].nunique()}</div>
                    </div>
                    {f'<div class="box"><h2>의심 활동</h2>{suspicious_html}</div>' if suspicious_html else ''}
                    <div class="box">
                      <h2>전체 이벤트</h2>
                      {edf[['timestamp','activity','user','computer','severity','process_name','ps_decoded']].to_html(index=False, border=0)}
                    </div>
                    </body></html>
                    """
                    st.download_button("HTML 보고서 다운로드", html,
                        file_name=f"forensic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                        mime="text/html")
                st.success("내보내기 완료")

    # ====== 보고서 탭 ======
    with tab_report:
        st.subheader("KST/타임존 기반 요약 보고서 생성")
        tz_disp = st.selectbox("타임존", ["Asia/Seoul (KST)", "UTC", "Asia/Tokyo", "America/Los_Angeles", "Europe/London"], index=0)
        tz_map = {
            "Asia/Seoul (KST)": "Asia/Seoul",
            "UTC": "UTC",
            "Asia/Tokyo": "Asia/Tokyo",
            "America/Los_Angeles": "America/Los_Angeles",
            "Europe/London": "Europe/London"
        }
        tzid = tz_map[tz_disp]

        ts_local = pd.to_datetime(df["timestamp"], utc=True).dt.tz_convert(tzid)
        min_d, max_d = ts_local.dt.date.min(), ts_local.dt.date.max()
        colA, colB = st.columns(2)
        start_date = colA.date_input("시작(로컬 날짜)", value=min_d, min_value=min_d, max_value=max_d)
        end_date   = colB.date_input("종료(로컬 날짜)", value=max_d, min_value=min_d, max_value=max_d)

        if st.button("📑 보고서 생성", type="primary"):
            text = build_text_report(df, tzid, start_date, end_date, max_items=50)
            st.code(text, language="text")
            st.download_button("TXT 다운로드", data=text, file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", mime="text/plain")
            html = f"<pre style='white-space:pre-wrap;font-family:Consolas,monospace'>{text}</pre>"
            st.download_button("HTML 다운로드", data=html, file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html", mime="text/html")

if __name__ == "__main__":
    main()
