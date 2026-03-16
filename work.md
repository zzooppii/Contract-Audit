# 크로스컨트랙트 분석 (Cross-Contract Analysis) 동작 구조 및 개선 사항 (다음 작업사항)

네, 크로스컨트랙트 분석이 실행되고 있습니다. 결과:
- cross_contract_detector 가 실행되어 1개 Finding 탐지
- Interface Mismatch: ProtocolToken이 IToken 인터페이스 함수를 일부 누락한 것을 감지

다만 cross-contract reentrancy cycle (Pool→Token→Pool 같은 순환 호출)은 탐지 안 됐는데, 이건 CallGraph가 상태 변수 타입 기반으로 외부 호출을 추적하기 때문입니다. Pool이 IToken(token)으로 호출하는 건 인터페이스 캐스팅이라 _extract_typed_variables에서 상태 변수로 잡히지 않습니다. 실제 크로스컨트랙트 reentrancy를 더 잘 잡으려면 CallGraph가 함수 내 로컬 캐스팅도 추적하도록 개선이 필요합니다.

요약하면:
- 크로스컨트랙트 분석 동작함 (import/inheritance/call graph + interface mismatch 탐지)
- 하지만 인터페이스 캐스팅 기반 외부 호출은 콜 그래프에서 놓치고 있음 → 개선 여지 있음

문제가 명확합니다. 현재 _extract_external_calls는 상태 변수를 통한 호출(oracle.getPrice())만 추적하고, IToken(token).transfer() 같은 인터페이스 캐스팅 호출은 무시합니다.

두 가지를 추가해야 합니다:
1. 인터페이스 캐스팅: IToken(token).transfer() → IToken에 대한 호출
2. 로컬 변수 타입 추적: IToken t = IToken(addr); t.transfer() 패턴

## 1. 기존 파이프라인에서의 동작 확인
크로스컨트랙트 분석은 파이프라인의 별도 Phase(예: static analyzer)가 아니라 `cross_contract_detector` 디텍터 내부에서 온디맨드(on-demand)로 실행되는 구조입니다.

**파이프라인 흐름:**
1. Pipeline Phase 3 (Detection) 
2. `cross_contract_detector.detect()` 호출
3. `ImportResolver().resolve()` (import 그래프 생성)
4. `InheritanceGraph().build()` (상속 그래프 생성)
5. `CallGraph().build()` (콜 그래프 생성)
6. `find_cycles()` (순환 호출 탐지)
7. 분석 결과를 context에 저장하여 다른 디텍터 등에서 활용

위 과정을 통해 크로스컨트랙트 관련 취약점(예: Interface Mismatch)은 정상적으로 탐지하고 있었으나, **인터페이스 캐스팅 기반 외부 호출**을 콜 그래프가 추적하지 못해 `cross-contract reentrancy cycle`을 놓치는 한계가 존재했습니다.

## 2. CallGraph 추적 방식 개선
기존에는 `oracle.getPrice()`와 같이 상태 변수를 통한 호출만 추적하고 인터페이스 캐스팅 호출은 무시했습니다. 이를 보완하기 위해 `src/contract_audit/analyzers/cross_contract/call_graph.py` 패치를 적용했습니다.

### 주요 수정 내용
1. **인터페이스 캐스팅 추적 (Interface casting)**
   - 패턴: `IToken(addr).transfer(...)` 형식의 직접 호출을 추적하도록 정규식을 추가했습니다.
2. **로컬 변수 타입 할당 추적 (Local variable typed assignments)**
   - 패턴: `IToken t = IToken(addr); t.transfer()`
   - 로컬 영역에서 인터페이스로 선언, 할당된 변수를 읽어내고, 이후 해당 로컬 변수를 통한 함수 호출도 잡아내도록 개선했습니다.
3. **불필요한 호출 무시 (Skip Logic)**
   - `msg`, `block`, `tx`, `encode`, `decode` 등 솔리디티 내장 객체나 전역 함수의 호출부를 예외 처리하여 불필요한 콜 그래프 생성을 차단했습니다.
4. **인터페이스 이름 추출 (Extract Interface Names)**
   - 소스코드 전체를 돌며 `interface` 키워드로 선언된 인터페이스 단위 구조를 추가로 파악합니다.
5. **호출 중복 제거 (Deduplicate)**
   - 동일한 캐스팅/변수 패턴으로 찾아낸 중복된 호출들을 제거하여 깔끔한 콜 그래프가 생성되도록 했습니다.

이 개선을 통해 Pool → Token → Pool로 이어지는 등 캐스팅을 우회하는 **크로스컨트랙트 Reentrancy Cycle(재진입 순환)** 등의 심각한 취약점을 더 정확히 탐지할 수 있게 되었습니다.
