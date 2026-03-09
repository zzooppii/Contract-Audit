# contract-audit

정적 분석, 동적 분석, LLM 강화를 결합하여 포괄적인 보안 감사 보고서를 생성하는 AI 기반 스마트 컨트랙트 감사 엔진입니다.

[![CI](https://github.com/zzooppii/Contract-Audit/actions/workflows/self-test.yml/badge.svg)](https://github.com/zzooppii/Contract-Audit/actions/workflows/self-test.yml)

## 주요 기능

- **22개 전문 디텍터**: 재진입, 접근 제어, 오라클 조작, 플래시론, ERC-20/ERC-4626, 프록시, 스토리지 충돌, 가스 그리핑, 거버넌스, 프론트러닝, 초기화, 정수 오버플로우, 서명 재사용, 랜덤성, 머클 트리, 타임락, 브릿지, NFT, 크로스 컨트랙트, 프라그마, 미확인 콜
- **정적 분석**: Slither (90+ 디텍터) + Aderyn (Rust, 서브초 분석) + 커스텀 AST 파서
- **크로스 컨트랙트 분석**: 임포트 해석, 상속 그래프, 콜 그래프 + 순환 탐지
- **동적 분석**: Foundry 퍼즈 테스팅 (카테고리별 타겟 하네스 생성) + 불변량 생성 + 심볼릭 실행 (Mythril/hevm)
- **LLM 강화**: Claude로 PoC 생성, Gemini로 설명 및 수정 방안, LLM 기반 비즈니스 로직 취약점 감사
- **오탐 감소**: 설정 가능한 스코어링 엔진 + LLM 트리아지
- **다중 포맷 보고서**: SARIF, JSON, Markdown, HTML, PDF + 감사 비교 (실행 간 diff)
- **GitHub CI 통합**: 자동 SARIF 업로드, PR 코멘트, diff 전용 필터링
- **CLI + API**: Typer CLI (`audit`, `init`, `login`, `logout`, `version` 명령어) + FastAPI REST API

## 빠른 시작

```bash
pip install contract-audit

# 감사 실행
contract-audit audit ./src --config audit.toml

# LLM 없이 실행 (정적 분석만)
contract-audit audit ./src --no-llm -v

# 이전 감사와 비교
contract-audit audit ./src --compare-to previous-report.json

# 설정 파일 초기화
contract-audit init

# LLM 프로바이더 로그인 (선택)
contract-audit login --anthropic
contract-audit login --google
```

## 아키텍처

```
파이프라인 단계:
  1. 소스 로딩       → .sol 파일 로드
  2. 정적 분석       → Slither + Aderyn + AST 파서 + 크로스 컨트랙트 분석
  3. 탐지            → 22개 전문 디텍터
  3.5 LLM 감사      → LLM을 통한 비즈니스 로직 취약점 탐지
  4. 동적 분석       → Foundry 퍼즈 + 불변량 테스트 + 심볼릭 실행
  5. 스코어링        → 설정 가능한 가중치 기반 위험도 점수
  5.5 오탐 감소      → 휴리스틱 + LLM 트리아지 오탐 필터링
  6. LLM 강화        → 설명, 수정 방안, PoC 생성
  7. 보고서 생성      → SARIF, JSON, Markdown, HTML, PDF
```

## 설정

```toml
# audit.toml
[project]
name = "My Protocol"

[llm]
enabled = true
max_budget_usd = 10.0

[llm.providers.anthropic]
auth_method = "oauth"                    # "oauth" (권장) 또는 "api_key"
api_key_env = "ANTHROPIC_API_KEY"        # CI 환경용 폴백

[llm.providers.google]
auth_method = "oauth"                    # "oauth" (권장) 또는 "api_key"
api_key_env = "GOOGLE_AI_API_KEY"        # CI 환경용 폴백

[analysis]
slither_enabled = true
aderyn_enabled = true
foundry_fuzz_enabled = true
symbolic_enabled = false
```

### 인증

```bash
# OAuth 로그인 (권장) - keyring을 통해 토큰 안전 저장
contract-audit login --anthropic
contract-audit login --google

# 또는 환경 변수로 API 키 사용 (CI용)
export ANTHROPIC_API_KEY="sk-ant-..."
export GOOGLE_AI_API_KEY="AI..."
```

## MCP 연동

contract-audit를 Claude Code 또는 MCP 호환 클라이언트에서 MCP 도구 서버로 사용할 수 있습니다.

### 설치

```bash
# 한 줄로 설치 (git clone 불필요)
pip install git+https://github.com/zzooppii/Contract-Audit.git
```

### MCP 설정

Claude Code MCP 설정 파일(`~/.claude/claude_desktop_config.json`)에 추가:

```json
{
  "mcpServers": {
    "contract-audit": {
      "command": "python3.11",
      "args": ["-m", "contract_audit.mcp"]
    }
  }
}
```

### 사용 가능한 도구

| 도구 | 파라미터 | 설명 |
|------|----------|------|
| `audit_contract` | `project_path` | 프로젝트 전체 감사 (22개 디텍터 + AST 파서 + Slither + Aderyn) |
| `audit_source` | `source_code`, `filename?` | 인라인 소스코드 감사 (Slither/Aderyn 비활성) |
| `list_detectors` | — | 22개 디텍터 목록 + 설명 조회 |

### 사용법

설정 완료 후 Claude Code에서 자연어로 바로 사용:

```
> /path/to/my-project 경로의 컨트랙트를 보안 감사해줘
  → audit_contract(project_path="/path/to/my-project") 자동 호출

> 이 Solidity 코드 취약점 있는지 확인해줘: <코드 붙여넣기>
  → audit_source 자동 호출

> 어떤 보안 검사를 할 수 있어?
  → list_detectors 자동 호출
```

### 인증 (LLM 기능용)

MCP 서버는 기본적으로 LLM 비활성 상태로 실행됩니다. CLI에서 LLM 강화를 사용하려면:

```bash
# Anthropic — API 키 사용
export ANTHROPIC_API_KEY="sk-ant-..."

# Google — API 키 또는 OAuth 사용
export GOOGLE_AI_API_KEY="AI..."
contract-audit login --google
```

## CI 통합

```yaml
# .github/workflows/audit.yml
- name: Run Audit
  run: |
    contract-audit audit ./src --ci-mode --output-sarif audit.sarif
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: audit.sarif
```

## 개발

```bash
# 개발 모드 설치
python3.11 -m pip install -e ".[dev]"

# 테스트 실행 (428개)
python3.11 -m pytest tests/ -v

# 린트
ruff check src/ tests/

# 타입 체크
mypy src/

# 1. 감사 대상 폴더에 audit.toml을 만들어두고
cd ~/my-defi-project
contract-audit init          # audit.toml 생성됨
contract-audit audit ./src   # 자동으로 같은 폴더의 audit.toml 사용

# 2. 또는 절대경로로 지정
contract-audit audit ~/my-defi-project/src --config ~/configs/audit.toml
```

## 테스트 구성

| 카테고리 | 테스트 수 | 설명 |
|----------|-----------|------|
| 단위 | ~300 | 디텍터 로직, 유틸리티, 스코어링, 설정 |
| 엣지 케이스 | 264 | 22개 디텍터 x 12개 엣지 케이스 입력 |
| 통합 | ~20 | 모의 라우터 기반 LLM 파이프라인, 디텍터 통합 |
| E2E | ~25 | 23개 예제 컨트랙트 대상 전체 파이프라인 |

## 라이선스

MIT
