import React from "react"
import "./styles/log.css"

const sections = [
  {
    title: "시스템 로그란?",
    description:
      "시스템 로그는 운영체제에서 발생하는 다양한 이벤트를 기록한 로그입니다.",
    listItems: [
      "✔️ 사용자 로그인 / 로그아웃",
      "✔️ 서비스 시작 / 종료",
      "✔️ 커널 메시지 (예: dmesg)",
      "✔️ 시스템 오류 및 경고 기록",
    ],
  },
  {
    title: "네트워크 로그란?",
    description:
      "네트워크 로그는 네트워크 장비 및 서비스의 트래픽이나 연결 상태를 기록합니다.",
    listItems: [
      "✔️ 방화벽 통과/차단 기록",
      "✔️ VPN 연결 기록",
      "✔️ IDS/IPS 탐지 이벤트",
      "✔️ 라우터/스위치 포트 상태",
    ],
  },
  {
    title: "로그 수집 목적",
    description:
      "로그는 다음과 같은 이유로 수집되어 분석 및 보안에 활용됩니다.",
    listItems: [
      "🛠 시스템 상태 모니터링",
      "🔍 장애 원인 추적 및 해결",
      "🧠 사용자 행동 분석",
      "🛡 침입 탐지 및 위협 대응",
    ],
  },
  {
    title: "보안 및 개인정보 보호 정책",
    description:
      "사용자 로그 데이터는 보안 기준을 준수하여 보호되며, 민감 정보는 아래 정책에 따라 처리됩니다.",
    listItems: [
      "🔒 암호화 저장 및 전송",
      "👤 개인정보 익명화 처리",
      "🚫 무단 접근 차단 및 접근 제어",
      "📝 감사 로그를 통한 추적 가능성 확보",
    ],
  },
  {
    title: "로그 보관 정책",
    description:
      "로그는 분석 및 감사 목적에 따라 일정 기간 보관되며, 다음 기준을 따릅니다.",
    listItems: [
      "⏳ 기본 보관 기간: 90일",
      "📁 보안 로그는 최대 1년까지 연장 가능",
      "🧹 오래된 로그는 자동 삭제 또는 별도 백업",
      "⚙️ 정책은 보안 요건에 따라 조정 가능",
    ],
  },
  {
    title: "로그의 유형",
    description: "로그는 발생 위치나 목적에 따라 여러 유형으로 나뉩니다.",
    listItems: [
      "<b>이벤트 로그</b>: 시스템 이벤트 기록 (윈도우 이벤트 로그, syslog 등)",
      "<b>트래픽 로그</b>: 네트워크 패킷 흐름 정보",
      "<b>보안 로그</b>: 방화벽, IDS/IPS, 안티바이러스 등의 보안 장비에서 발생",
      "<b>응용 로그</b>: 애플리케이션 동작 기록 (예: 웹 서버 access/error 로그)",
      "<b>감사 로그</b>: 사용자 활동, 시스템 설정 변경 등 민감 행위 기록",
    ],
  },
  {
    title: "주요 로그 필드 설명",
    description:
      "로그는 다양한 필드로 구성되어 있으며, 각 필드의 의미를 이해하는 것이 중요합니다.",
    listItems: [
      "<b>Timestamp</b>: 로그 발생 시간",
      "<b>Hostname / IP</b>: 이벤트가 발생한 장비 또는 출발지 주소",
      "<b>Event ID / Code</b>: 이벤트 종류 식별자",
      "<b>Message</b>: 상세 설명",
      "<b>Severity Level</b>: 로그 심각도 (예: INFO, WARNING, ERROR, CRITICAL)",
    ],
  },
  {
    title: "로그 분석 기준",
    description:
      "로그 분석 시 다음과 같은 기준을 사용하여 이상 행위나 보안 위협을 식별할 수 있습니다.",
    listItems: [
      "📌 <b>패턴 기반 분석</b>: 정해진 시그니처 또는 규칙에 따라 탐지",
      "📌 <b>이상 탐지 기반 분석</b>: 정상 행위에서 벗어난 로그 식별",
      "📌 <b>빈도 분석</b>: 이벤트 발생 횟수를 기반으로 이상 징후 파악",
      "📌 <b>시간대 분석</b>: 특정 시간대에 집중된 이상 이벤트 탐지",
    ],
  },
  {
    title: "Prediction (예측값)",
    description:
      "AI가 로그를 분석해 정상 또는 공격(공격 유형 포함)으로 분류한 결과입니다.",
    listItems: [
      "📌 <b>정상</b>: 추가 조치 없이 모니터링만 진행",
      "📌 <b>공격</b>: 관리자 알림, 의심 세션 차단, 보안 규칙 업데이트",
    ],
  },
  {
    title: "Anomaly Score (이상 점수)",
    description:
      "로그가 정상 패턴에서 얼마나 벗어났는지를 수치로 표현한 값입니다.",
    listItems: [
      "📌 <b>점수 낮음</b>: 정상일 가능성이 높음, 필요시 참고만",
      "📌 <b>점수 높음</b>: 우선적으로 검토, 공격 여부 확인 후 대응",
    ],
  },
  {
    title: "Original Log (원본 로그)",
    description:
      "AI가 분석한 실제 로그 데이터입니다. 예측 결과 검증 및 원인 분석에 활용합니다.",
    listItems: [
      "📌 <b>분석 재검증</b>: Prediction/Score 결과가 의심스러울 때 직접 확인",
      "📌 <b>사후 분석</b>: 보안 사고 발생 시 근본 원인 파악",
    ],
  },
]

const Log = () => {
  return (
    <div className="log-page">
      <h1 className="log-title">시스템 및 네트워크 로그 안내</h1>
      <div className="log-section-container">
        {sections.map((section, idx) => (
          <div className="log-section" key={idx}>
            <h2 className="log-section-title">{section.title}</h2>
            <p className="log-section-desc">{section.description}</p>
            <ul className="log-section-list">
              {section.listItems &&
                section.listItems.map((item, i) => (
                  <li
                    key={i}
                    dangerouslySetInnerHTML={{ __html: item }}
                    className="log-list-item"
                  />
                ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  )
}

export default Log
