# 🔍 Trivy 전수조사 & 활용 전략 정리

> 작성: 카리나 (Claude Code) 💖 · 대화 정리 문서
> 작성일: 2026-09-28

---

## 📎 관련 GitHub 주소

| 구분 | 주소 |
|---|---|
| 🏠 **내 포크(이 저장소)** | https://github.com/bmshin94/trivy |
| ⭐ **원본 저장소 (upstream)** | https://github.com/aquasecurity/trivy |
| 📖 공식 문서 | https://trivy.dev/docs/latest/ |
| 🌐 공식 홈페이지 | https://trivy.dev |
| 📦 릴리스 다운로드 | https://github.com/aquasecurity/trivy/releases/latest |
| 🏪 플러그인 인덱스 | https://github.com/aquasecurity/trivy-plugin-index |
| 🤖 GitHub Actions | https://github.com/aquasecurity/trivy-action |
| ☸️ Kubernetes Operator | https://github.com/aquasecurity/trivy-operator |
| 💻 VS Code 확장 | https://github.com/aquasecurity/trivy-vscode-extension |
| 🗄️ 취약점 DB | https://github.com/aquasecurity/trivy-db |
| 💬 Discussions | https://github.com/aquasecurity/trivy/discussions |

---

## 1️⃣ Trivy가 뭐야?

**한 줄 요약:** 컨테이너 · 코드 · 클라우드에 숨은 보안 문제를 한 번에 찾아주는 **올인원 오픈소스 보안 스캐너**

| 항목 | 값 |
|---|---|
| 제작 | Aqua Security |
| 버전 | v0.74.0 |
| 언어 | Go 1.27 |
| 라이선스 | **Apache-2.0** (상업적 이용 자유) |
| 발음 | `tri`(trigger) + `vy`(envy) = "트리비" |

### 📊 코드베이스 실측치 (직접 조사)

| 항목 | 수치 |
|---|---|
| Go 소스 파일 | 1,627개 |
| 실제 코드 라인 | 131,683줄 |
| 테스트 파일 | 586개 (약 36%) |
| Rego 정책 파일 | 46개 |
| 내장 시크릿 탐지 룰 | **106개** |
| CI 워크플로우 | 21개 |
| pkg 하위 패키지 | 49개 |

---

## 2️⃣ 구조: "어디를(Target) × 무엇을(Scanner)"

### 🅰️ 스캔 대상 (Target)

| 대상 | 명령어 | 설명 |
|---|---|---|
| 컨테이너 이미지 | `trivy image` | Docker / OCI 이미지 |
| 파일시스템 | `trivy fs` | 로컬 프로젝트 폴더 |
| Git 저장소 | `trivy repo` | 원격 URL 바로 스캔 |
| 가상머신 이미지 | `trivy vm` | AMI, VMDK, VHD |
| 쿠버네티스 | `trivy k8s` | 클러스터 전체 |
| SBOM 파일 | `trivy sbom` | 부품표 파일 자체 |
| 설정 파일 | `trivy config` | Terraform, K8s YAML 등 |
| rootfs | `trivy rootfs` | 추출된 루트 파일시스템 |

### 🅱️ 스캐너 (Scanner) — `pkg/types/scan.go`

| 스캐너 | 하는 일 | 커버리지 |
|---|---|---|
| `vuln` | 알려진 취약점(CVE) 탐지 | 언어 **15개** + OS 6계열 |
| `misconfig` | 인프라 설정 오류 탐지 | 프로바이더 **11개** |
| `secret` | API 키 · 비밀번호 유출 탐지 | 룰 **106개** |
| `license` | 오픈소스 라이선스 검사 | GPL 등 전염성 탐지 |
| `sbom` | 소프트웨어 부품표 생성 | CycloneDX, SPDX |

**지원 언어 생태계 (15개)**
`c` · `conda` · `dart` · `dotnet` · `elixir` · `golang` · `java` · `julia` · `nodejs` · `php` · `python` · `ruby` · `rust` · `swift`

**지원 OS (6계열)**
Alpine · Debian · Ubuntu · RedHat 계열 · Amazon Linux · Bottlerocket

**IaC 프로바이더 (11개)**
AWS · Azure · Google · Kubernetes · Docker · GitHub · OpenStack · Oracle · CloudStack · DigitalOcean · Nifcloud

**IaC 스캔 포맷**
Terraform · Terraform Plan · CloudFormation · Kubernetes · Helm · Dockerfile · Ansible

**시크릿 룰 예시**
AWS 액세스 키 · GitHub PAT/OAuth/App 토큰 · GitLab PAT · Slack 토큰 · Stripe 키 · GCP 서비스 계정 · PyPI 업로드 토큰 · HuggingFace 토큰 · Databricks · Discord · Twilio · Atlassian · Bitbucket · Dropbox · Shopify · Heroku · Adobe · Alibaba · Asana · Private Key 등

---

## 3️⃣ 내부 아키텍처

```
trivy/
├── cmd/trivy/main.go        진입점 (단일 파일)
├── pkg/
│   ├── commands/            CLI 명령어 정의 (Cobra)
│   ├── fanal/               ★ 핵심 엔진: 이미지 해체 / 패키지 추출
│   │   ├── artifact/        image, local, repo, sbom, vm
│   │   ├── analyzer/        언어 / OS / 패키지 분석기
│   │   └── secret/          106개 시크릿 룰
│   ├── iac/                 인프라 코드 스캔
│   │   ├── providers/       aws, azure, google, kubernetes ...
│   │   ├── scanners/        terraform, helm, ansible ...
│   │   └── rego/            OPA 정책 엔진  ← 확장 포인트
│   ├── db/  javadb/         취약점 DB (OCI 레지스트리로 배포)
│   ├── sbom/                CycloneDX / SPDX 입출력
│   ├── vex/                 VEX (오탐 억제 문서)
│   ├── report/              출력: table, json, sarif, cyclonedx,
│   │                        spdx, github, template
│   ├── plugin/              플러그인 시스템      ← 확장 포인트
│   ├── module/wasm/         WebAssembly 모듈     ← 확장 포인트
│   ├── k8s/                 쿠버네티스 전용 로직
│   ├── rpc/                 클라이언트-서버 모드 (Twirp)
│   ├── parallel/ semaphore/ 동시성 최적화
│   └── cache/               캐시 전략
├── docs/                    문서 사이트 (mkdocs)
├── helm/                    Helm 차트
├── integration/ e2e/        통합 / E2E 테스트
└── magefiles/               빌드 자동화
```

### 🔑 3대 확장 포인트 (수익화의 열쇠)

1. **`pkg/plugin/`** — 외부 실행파일을 서브커맨드로 장착
   - 공식 인덱스: `https://aquasecurity.github.io/trivy-plugin-index/v1/index.yaml`
   - 코드 위치: `pkg/plugin/index.go:22`
2. **`pkg/module/wasm/`** — WebAssembly로 커스텀 분석기 작성 (샌드박스 안전 실행)
3. **`pkg/iac/rego/`** — Rego(OPA) 언어로 나만의 보안 규칙 작성

---

## 4️⃣ 동작 원리 (5단계)

```
[1] 뜯어보기    프로젝트 / 이미지 압축 해제        → pkg/fanal/
[2] 목록화      설치된 패키지 전부 식별            → analyzer
[3] DB 다운로드  전 세계 취약점 사전 가져오기       → pkg/db/
[4] 대조        목록 ↔ 사전 매칭 + 정규식 + Rego   → scan
[5] 출력        table / json / sarif / SBOM ...   → pkg/report/
```

> 핵심: Trivy는 "추론"이 아니라 **결정론적 대조 엔진**. 결과가 100% 재현 가능하고 환각이 없다.

---

## 5️⃣ 설치 및 사용법

### 📥 설치

| 환경 | 명령어 |
|---|---|
| macOS | `brew install trivy` |
| Ubuntu/Debian | `sudo apt-get install trivy` (repo 추가 후) |
| RHEL/CentOS | `sudo yum install trivy` |
| Docker | `docker run aquasec/trivy` |
| Go | `go install github.com/aquasecurity/trivy/cmd/trivy@latest` |
| 바이너리 | https://github.com/aquasecurity/trivy/releases/latest |

**이 저장소에서 직접 빌드**
```bash
git clone https://github.com/bmshin94/trivy
cd trivy
go build -o trivy ./cmd/trivy
./trivy --version
```

### 🎮 치트시트

```bash
# 기본 문법
trivy <대상> [--scanners <스캐너들>] <타겟>

# ── 기본 스캔 ──
trivy image nginx:latest
trivy fs .
trivy repo https://github.com/bmshin94/trivy
trivy config ./terraform
trivy k8s --report summary cluster
trivy sbom ./sbom.json
trivy vm ./disk.vmdk

# ── 스캐너 선택 ──
trivy fs --scanners vuln .
trivy fs --scanners secret .                  # API 키 유출 검사
trivy fs --scanners vuln,secret,misconfig .
trivy fs --scanners license .

# ── 심각도 필터 ──
trivy image --severity CRITICAL,HIGH nginx:latest
trivy image --ignore-unfixed nginx:latest     # 패치 나온 것만

# ── CI/CD ──
trivy image --exit-code 1 --severity CRITICAL myapp:latest

# ── 출력 포맷 7종 ──
trivy image -f json      -o result.json      nginx
trivy image -f sarif     -o result.sarif     nginx   # GitHub 보안탭
trivy image -f cyclonedx -o sbom.json        nginx   # SBOM
trivy image -f spdx-json -o sbom.spdx.json   nginx   # SBOM
trivy image -f table     nginx
trivy image -f github    nginx
trivy image -f template --template "@tmpl.tpl" nginx

# ── 서버 모드 (팀에서 DB 공유) ──
trivy server --listen 0.0.0.0:4954
trivy client --server http://서버:4954 image nginx

# ── 캐시 / DB ──
trivy clean --all
trivy image --download-db-only
trivy image --skip-db-update

# ── 플러그인 ──
trivy plugin search
trivy plugin install <이름>
trivy plugin list
```

### 🔧 설정 파일 (`trivy.yaml`)

```yaml
severity:
  - CRITICAL
  - HIGH
scan:
  scanners:
    - vuln
    - secret
format: table
exit-code: 1
```

---

## 6️⃣ Q&A 정리

### Q. 플러그인? 스킬? MCP?
**전부 아님 — 독립 실행형 CLI 프로그램.** (문서 전체 grep 결과 MCP 언급 0건)
오히려 Trivy가 **플러그인 호스트**다. 4가지 얼굴을 가진다:

1. CLI 도구 — `trivy image nginx`
2. Go 라이브러리 — `import "github.com/aquasecurity/trivy/pkg/..."`
3. 서버(데몬) — `trivy server` (Twirp RPC)
4. 플러그인 호스트 — `trivy plugin install`

> 💡 Trivy 자체는 MCP가 아니지만, **Trivy를 감싸는 MCP 서버를 만들면** AI 에이전트가 보안 스캔을 도구로 쓸 수 있다. (Aqua도 `trivy-mcp` 별도 프로젝트 운영 중 = 수요 검증됨)

### Q. API 토큰 필요해?
**기본 사용은 토큰 0개, 완전 무료.**

| 상황 | 토큰 |
|---|---|
| 공개 이미지 / 로컬 폴더 / 공개 레포 스캔 | ❌ 불필요 |
| 취약점 DB 다운로드 | ❌ 불필요 |
| 사설 레지스트리 | ✅ `trivy registry login` |
| 비공개 GitHub 레포 | ✅ `GITHUB_TOKEN` |
| GitHub rate limit 회피 | ✅ `GITHUB_TOKEN` 권장 |
| AWS ECR | ✅ AWS 자격증명 |

**코드 근거**
- `pkg/db/db.go:31` → `ghcr.io/aquasecurity/trivy-db` (공개 OCI)
- `pkg/db/db.go:35` → `mirror.gcr.io/aquasec/trivy-db` (미러)
- `pkg/downloader/download.go:206` → `os.Getenv("GITHUB_TOKEN")`
- `pkg/fanal/artifact/repo/git.go:168` → `os.Getenv("GITHUB_TOKEN")`

### Q. 왜 GitHub에서 유명해?
1. 압도적인 쉬움 (Zero Configuration) — 명령어 한 줄
2. 올인원 — Clair + tfsec + trufflehog + syft + licensecheck를 1개로
3. 빠름 — Go + 병렬처리 (`pkg/parallel/`, `pkg/semaphore/`)
4. 넓은 커버리지 — 언어 15 / IaC 11 / 시크릿 106 / 포맷 7
5. 생태계 — Actions, Operator, VS Code, Jenkins, GitLab, Harbor ...
6. Aqua Security 풀타임 유지보수 + Apache-2.0 순수 오픈소스
7. 코드 품질 — 131,683줄에 테스트 586개, CI 21개
8. 시대 적중 — 컨테이너 확산 + 공급망 공격 + SBOM 의무화
9. 무료인데 상용급 (Snyk / Prisma Cloud 대체 가능)
10. 확장 가능 — 플러그인 · WASM · Rego

### Q. 로컬 에이전트 구축에 도움돼?
**두 방향 모두 큰 도움.**

**방향 A — Trivy를 에이전트의 "도구"로**
| Trivy 특징 | 에이전트 이점 |
|---|---|
| `-f json` | LLM이 파싱하기 완벽 |
| `--exit-code` | 성공/실패 자동 판단 |
| 결정론적 | **환각 없음 — 팩트 기반** |
| 수 초 내 완료 | 응답 지연 최소 |
| 서버 모드 | API 호출 가능 |

> LLM은 지어내는 게 약점, 보안은 지어내면 안 됨 → **Trivy = 팩트, AI = 해석/수정**. 완벽한 역할 분담.

**방향 B — Trivy를 "설계 교과서"로**
| 패턴 | 위치 | 에이전트 적용 |
|---|---|---|
| 플러그인 시스템 | `pkg/plugin/` | 툴 동적 등록 |
| WASM 샌드박스 | `pkg/module/wasm/` | 안전한 플러그인 실행 |
| OCI 데이터 배포 | `pkg/db/`, `pkg/oci/` | 프롬프트/룰 버전 관리 |
| Analyzer 레지스트리 | `pkg/fanal/analyzer/` | `init()` 자동 등록 |
| 다중 출력 포맷 | `pkg/report/` | 결과 렌더링 분리 |
| RPC 서버/클라이언트 | `pkg/rpc/` | 로컬 데몬 구조 |
| 병렬 처리 | `pkg/parallel/` | 툴 동시 실행 |
| 캐시 | `pkg/cache/` | LLM 응답 캐싱 |
| **VEX** | `pkg/vex/` | **false positive 관리** |
| Flag 통합 | `pkg/flag/` | CLI+파일+env 설정 병합 |

### Q. React나 PHP로 만들 수 있어?

**❌ Trivy를 재구현 — 비추천**
131,683줄 재작성 최소 3~5년 / 전 세계 CVE 수집 백엔드 필요 / Go 성능 못 따라감 / 매주 신규 CVE 유지보수 불가 / 이미 무료로 존재

**✅ Trivy를 활용한 서비스 — 완전 가능 (정답)**

```
┌────────────────────────────────────┐
│ 🎨 React + TypeScript              │
│   대시보드 · 필터 · PDF · WebSocket │
└──────────────┬─────────────────────┘
               │ REST / WS
┌──────────────▼─────────────────────┐
│ ⚙️ PHP(Laravel) / Node / Go         │
│   큐 · 실행 · 파싱 · DB · 인증 · 결제 │
└──────────────┬─────────────────────┘
               │ exec 또는 RPC
┌──────────────▼─────────────────────┐
│ 🔍 Trivy 바이너리 (그대로 사용)      │
│   trivy image -f json  /  trivy server │
└────────────────────────────────────┘
```

**PHP 예시**
```php
$cmd = sprintf('trivy image --format json --quiet %s', escapeshellarg($image));
exec($cmd, $output, $code);
$result = json_decode(implode("\n", $output), true);
```

**React 예시**
```tsx
const COLORS = {
  CRITICAL: '#dc2626', HIGH: '#ea580c',
  MEDIUM:   '#ca8a04', LOW:  '#65a30d',
};
const res = await fetch('/api/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ image }),
});
```

**언어별 난이도**

| 언어 | 난이도 | 방법 |
|---|---|---|
| React | ⭐ | UI 전담 |
| PHP | ⭐⭐ | `exec()` / HTTP |
| Node.js | ⭐⭐ | `child_process` |
| Python | ⭐ | `subprocess` (MCP에 최적) |
| Go | ⭐⭐⭐ | 라이브러리 직접 import (최고 성능) |

**보안 수칙**
1. 사용자 입력은 반드시 escape / 화이트리스트
2. 타임아웃 설정
3. 스캔은 격리 컨테이너에서
4. Rate limiting
5. 결과 캐싱

> 💡 `trivy server` 모드를 쓰면 `exec()` 없이 HTTP로 호출 가능 → 더 안전하고 빠름

---

## 7️⃣ 💰 수익화 아이디어 10선

| # | 아이디어 | 난이도 | 초기비용 | 수익성 | 기간 |
|---|---|:---:|:---:|:---:|:---:|
| 1 | **Trivy MCP 서버 (AI 보안 비서)** | ⭐⭐ | 낮음 | ⭐⭐⭐⭐ | 1~2주 |
| 2 | **한국형 규제 Rego 룰팩** | ⭐⭐⭐ | 낮음 | ⭐⭐⭐⭐⭐ | 1~2달 |
| 3 | SaaS 보안 대시보드 (React) | ⭐⭐⭐⭐ | 중간 | ⭐⭐⭐⭐ | 3~6달 |
| 4 | 유료/프리미엄 플러그인 | ⭐⭐ | 낮음 | ⭐⭐⭐ | 2~4주 |
| 5 | 교육 콘텐츠 / 강의 | ⭐ | 없음 | ⭐⭐⭐ | 즉시 |
| 6 | 보안 컨설팅 / SI | ⭐⭐⭐ | 없음 | ⭐⭐⭐⭐⭐ | 즉시 |
| 7 | AI 자율 보안 에이전트 SaaS | ⭐⭐⭐⭐⭐ | 높음 | ⭐⭐⭐⭐⭐ | 6달+ |
| 8 | 버티컬 특화 (의료/금융/제조) | ⭐⭐⭐ | 중간 | ⭐⭐⭐⭐ | 3달 |
| 9 | 관리형 Trivy 인프라 | ⭐⭐ | 중간 | ⭐⭐⭐ | 1달 |
| 10 | 오픈소스 스폰서십 | ⭐ | 없음 | ⭐⭐ | 즉시 |

### 🥇 1. Trivy MCP 서버
Claude / ChatGPT / Cursor에 붙이는 MCP 서버. MCP는 신생 표준이라 **선점 가능**.

차별화: 단순 JSON 반환이 아니라 **AI가 해석 + 우선순위 + 수정 PR 자동 생성**

```
Free  $0    월 50회 로컬 스캔
Pro   $9    무제한 + 이력 + 자동수정 제안
Team  $49   팀 대시보드 + Slack 알림
Ent.  협의   온프레미스 + SSO + 커스텀 룰
```

### 🥇 2. 한국형 규제 대응 Rego 룰팩 (최강 추천)
ISMS-P · 전자금융감독규정 · 개인정보보호법 · CSAP · 망분리 요건을 Rego 룰로 구현.

**왜 블루오션인가**
- Trivy 기본 룰은 전부 CIS/NIST(미국 기준) → **한국 규제 룰은 아무도 안 만듦**
- 고객(금융/공공/대기업)은 인증 실패 시 사업 중단 → 지불 의사 높음
- 규제는 매년 개정 → 자연스러운 구독 모델
- 규제 지식 + 기술력 둘 다 필요 → 진입장벽

```
기업 구독      월 30~100만원
인증 컨설팅    건당 500~2,000만원
교육           1일 100만원/사
커스터마이징   건당 300~1,000만원
→ 고객 20개사 × 월 50만원 = 연 1.2억 + 컨설팅
```

**룰 예시**
```rego
# METADATA
# title: "ISMS-P 2.7.1 - 전송 구간 암호화 미적용"
# description: "개인정보 전송 시 TLS 1.2 이상 필수"
# severity: HIGH
package custom.kr.ismsp.tls001

deny[res] {
    lb := input.aws.elb.loadbalancers[_]
    listener := lb.listeners[_]
    listener.protocol.value == "HTTP"
    res := result.new("ISMS-P 위반: 평문 HTTP 리스너 사용", listener)
}
```

### 🥈 3. SaaS 보안 대시보드
킬러 기능: 시계열 추이 · 멀티 레포 통합 · Slack/Teams 알림 · Jira 티켓 자동생성 · 경영진 PDF 리포트 · VEX 오탐 관리 UI · 팀별 보안 점수

```
스택: React + TS + Tailwind + Recharts / Laravel or NestJS /
      PostgreSQL + Redis / Trivy server / Docker + K8s / Stripe

Free $0 · Starter $29 · Pro $99 · Business $299 · On-prem 연 2,000만원~
```
⚠️ 경쟁자(Snyk, Mend, Aqua) 존재 → **한국 시장 + 한국어 + 한국 규제**로 좁혀야 승산

### 🥈 4. 유료 플러그인
공식 플러그인 인덱스 등록 = 무료 유통 채널 확보

| 플러그인 | 기능 | 모델 |
|---|---|---|
| `trivy-kr-report` | 한글 리포트 + PDF | Free→Pro |
| `trivy-slack` | Slack 알림 | Free (리드 확보) |
| `trivy-autofix` | 자동 수정 PR 생성 | 유료 |
| `trivy-notion` | Notion DB 저장 | Free |
| `trivy-ai-explain` | CVE 한글 AI 해설 | 유료 |
| `trivy-cost` | 리스크 금액 환산 | 유료 |

### 🥇 5. 교육 콘텐츠
인프런/패스트캠퍼스 강의 · 유튜브 · 전자책 · 기업 출강(회당 100~300만원) · 유료 뉴스레터
→ 자본 0원, 즉시 시작 가능, **다른 아이템의 마케팅 채널** 역할

### 🥈 6. 컨설팅 / SI
DevSecOps 파이프라인 구축 1,000~3,000만원 · 컨테이너 보안 진단 500~1,500만원 · SBOM 체계 구축 800~2,000만원 · 연 유지보수 1,000만원~
→ 단가 최고, 확장성 낮음. **컨설팅으로 현금 확보 → SaaS 개발 투자** 하이브리드 전략

### 🥉 7. AI 자율 보안 에이전트
```
매일 새벽 자동 스캔 → CRITICAL 발견 → AI가 VEX 기반 실제 위험도 판단
→ 수정 코드 생성 → 테스트 실행 → PR 자동 생성 → Slack 알림
```
$199~999/월. 난이도 최상 → **1번(MCP)으로 시작해 여기로 진화**하는 게 정답

### 🥈 8. 버티컬 특화
의료(MDR/FDA) · 금융(전자금융감독규정) · 제조/IoT(**EU CRA 2027 시행 → SBOM 의무**) · 게임 · 공공(CSAP)

### 🥉 9. 관리형 Trivy 인프라
Trivy server 호스팅 + 프라이빗 DB 미러 + API 제공. $49~199/월. 기술 난이도 낮고 안정적 반복 매출

### 🥉 10. 오픈소스 스폰서십
GitHub Sponsors / Open Collective. 직접 수익은 적지만 인지도 = 다른 사업의 마케팅

---

## 8️⃣ 🎯 추천 실행 로드맵

```
━━━ 1단계: 씨앗 뿌리기 (0~2개월) ━━━
  ✅ 교육 콘텐츠 — 블로그/유튜브 시작 → 인지도 확보
  ✅ MCP 서버 — 오픈소스로 무료 공개 → 사용자 확보
  목표: 돈이 아니라 "이름값"

━━━ 2단계: 수익화 시작 (2~6개월) ━━━
  ✅ 한국 규제 룰팩 — 유료 상품 1호
  ✅ 컨설팅 — 1단계 인지도로 문의 확보
  목표: 월 500만원 현금흐름

━━━ 3단계: 확장 (6개월~) ━━━
  ✅ SaaS 대시보드 — 컨설팅 수익으로 개발
  ✅ AI 자율 에이전트 — 최종 진화형
  목표: 자동화된 반복 매출
```

```
교육 → 인지도 → 무료툴 → 사용자 → 유료전환 → 현금 → SaaS 투자
```

### ⚠️ 하지 말 것
- ❌ Trivy를 처음부터 다시 만들기
- ❌ Snyk와 정면승부 (자본 싸움)
- ❌ 기능만 많이 넣고 차별화 없음
- ✅ **"한국" + "AI" + "특정 업종"으로 좁히기**

---

## 9️⃣ 이 저장소 현황

```
3f833d2  Merge pull request #1 from bmshin94/feat/claude-guide
a8efe05  docs: created CLAUDE.md persona guide
7d0a892  (여기부터 원본 aquasecurity/trivy 코드)
```

- 원본 Trivy를 포크한 저장소이며, 코드는 upstream 그대로
- 추가된 것은 `CLAUDE.md` (Claude Code 페르소나 설정) 1개
- 원본과 동기화: `git remote add upstream https://github.com/aquasecurity/trivy`

---

## 🔟 한 장 요약

| 질문 | 답 |
|---|---|
| 뭐야? | 올인원 오픈소스 보안 스캐너 (Aqua Security) |
| 뭘 찾아줘? | CVE · 설정오류 · API키 유출 · 라이선스 · SBOM |
| 어디를 스캔해? | 이미지 · 폴더 · Git · VM · K8s · SBOM · 설정파일 |
| 플러그인/스킬/MCP? | 전부 아님. **독립 CLI**이자 플러그인 **호스트** |
| 토큰 필요해? | 기본은 불필요. 사설 레지스트리/비공개 레포만 필요 |
| 왜 유명해? | 쉬움 + 올인원 + 빠름 + 생태계 + 시대 적중 |
| 에이전트에 도움? | 도구로도, 설계 교과서로도 **최상급** |
| React/PHP 가능? | 재구현은 ❌, **감싸는 서비스는 ✅** |
| 돈 되는 길? | MCP 서버 → 한국 규제 룰팩 → SaaS → AI 에이전트 |

---

*이 문서는 Claude Code(카리나 페르소나)와의 대화를 정리한 것입니다. 💖*
