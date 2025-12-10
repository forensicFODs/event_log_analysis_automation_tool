# event_log_analysis_automation_tool
### 사용 방법

### 설치

```bash
pip install streamlit pandas plotly python-evtx
```

### 실행

```bash
streamlit run app.py
```
# [Windows 이벤트 로그 포렌식 분석기]

## 개요

Windows 이벤트 로그(.evtx)를 심층 분석하여 보안 위협, 의심스러운 활동, 침해 지표(IoC)를 탐지하는 포렌식 분석 도구입니다. MITRE ATT&CK 프레임워크 기반 위협 매핑과 직관적인 웹 UI를 제공합니다.

![image.png](attachment:9d99a54c-360b-4b41-9319-32fcce0657fa:image.png)

---

## 주요 기능

### 1. 다중 로그 파일 처리

- **폴더 경로 입력**: 디렉토리 전체의 .evtx 파일 일괄 분석
- **개별 파일 업로드**: 선택적 파일 업로드 지원
- **대용량 처리**: 수천~수만 개 이벤트 실시간 파싱

### 3. 고급 필터링 & 검색

- **간단 필터**
    - **시간 범위**: 날짜/시간대 선택, 비업무시간 필터링
    - **엔티티 필터**: 사용자, 컴퓨터, IP 주소, 활동 유형
    - **빠른 프리셋**:
        - 로그 삭제/감사 변경
        - 원격 접속 (RDP/SMB)
        - 계정 공격 (Brute Force)
        - 지속성 확보 (서비스/작업)
        - PowerShell/WMI 실행
- **고급 검색**
    - **전역 키워드 검색**: 사용자명, 프로세스명, 명령줄, PowerShell 스크립트, 해시값 등 전체 필드 검색
    - **IP/CIDR 검색**: 개별 IP, CIDR 범위(10.0.0.0/8), 외부 IP 필터링
    - **내부/외부 IP 자동 분류**: RFC1918 사설 IP 자동 식별

### 4. 위협 탐지

- **자동 탐지 패턴**
    - **로그 조작**: 보안 로그 삭제(1102, 104), 감사 정책 변경(4719)
    - **계정 공격**: 로그온 실패 급증(4625), 계정 잠금(4740), Brute Force 패턴
    - **권한 상승**: 특수 권한 로그온(4672), 신규 관리자 계정(4720)
    - **지속성**: 신규 서비스(7045), 스케줄 작업(4698), 레지스트리 변조(4657)
    - **악성코드**: Defender 탐지(1116), 실시간 보호 비활성화(5001, 1118)
- **PowerShell 분석**
    - **난독화 해제**: Base64 인코딩 자동 복원
    - **의심 패턴 탐지**:
        - Invoke-Mimikatz, IEX, DownloadString
        - ExecutionPolicy Bypass, AMSI 우회
        - System.Reflection.Assembly::Load
    - **ScriptBlock 로깅**: 4104 이벤트 전체 스크립트 추출

### 5. 시각화 대시보드

- **통계 차트**
    - **시간대별 활동 추이**: 일별/시간별 이벤트 분포
    - **심각도 분포**: Critical/Warning/Info 비율
    - **MITRE 전술 분포**: 공격 단계별 시각화
    - **Top 활동/Event ID**: 빈도 기반 순위
- **카드뷰**
    - **색상 코딩**: 심각도별 시각적 구분 (🔴 Critical, 🟡 Warning, 🔵 Info)
    - **아이콘 표시**: 사용자👤, 컴퓨터💻, IP🌐, 프로세스⚙️
    - **권장 조치**: 이벤트별 대응 가이드 자동 생성
    - **상세 정보**: MITRE 매핑, 프로세스 트리, 네트워크 연결

### 6. 보고서 생성

- **요약 보고서 (TXT/HTML)**
    - **타임존 변환**: UTC → KST/JST/PST 등 로컬 시간 변환
    - **날짜 필터링**: 특정 기간 집중 분석
    - **통계 섹션**:
        - 파일별 이벤트 수 (분석/제외/의심 건수)
        - 카테고리별 통계 (logon, service, process 등)
        - 시간대별 활동 (24시간 막대 그래프)
        - Top 20 Event ID (빈도/비율)
        - 사용자별 성공/실패 통계 (로그온 실패율)
        - IP별 활동 통계 (외부 IP 강조)
- **상세 내보내기**
    - **CSV**: 표 형식 데이터 (Excel 호환)
    - **JSON**: 구조화된 데이터 (SIEM 연동)
    - **HTML**: 독립 실행 보고서 (첨부 파일 공유용)
    - **범위 선택**: 전체/포렌식 중요/의심 활동/북마크

## 지원 이벤트 ID

| Event ID | 설명 | MITRE Tactic |
| --- | --- | --- |
| 4624 | 로그온 성공 | Initial Access |
| 4625 | 로그온 실패 | Credential Access |
| 4688 | 프로세스 생성 | Execution |
| 4720 | 계정 생성 | Persistence |
| 7045 | 서비스 설치 | Persistence |
| 4698 | 스케줄 작업 생성 | Execution |
| 1102 | 보안 로그 삭제 | Defense Evasion |
| 4104 | PowerShell ScriptBlock | Execution |
| 1116 | 악성코드 탐지 | Impact |
| Sysmon 1 | 프로세스 생성 | Execution |
| Sysmon 3 | 네트워크 연결 | Command & Control |
| Sysmon 11 | 파일 생성 | Collection |

## 기술 스택

- **프론트엔드**: Streamlit (Python 웹 프레임워크)
- **데이터 처리**: Pandas (DataFrame 기반 분석)
- **시각화**: Plotly (인터랙티브 차트)
- **로그 파싱**: python-evtx (Microsoft .evtx 바이너리 파서)
- **XML 처리**: ElementTree (이벤트 필드 추출)
