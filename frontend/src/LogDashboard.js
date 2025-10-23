import React, { useState, useEffect, useRef } from 'react'
import LogChart from './chart'
import html2canvas from 'html2canvas'
import jsPDF from 'jspdf'
import './styles/LogDashboard.css'

function LogDashboard() {
  // --- 상태 변수 ---
  const [allLogs, setAllLogs] = useState([])
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [displayedData, setDisplayedData] = useState([])
  const [searchTerm, setSearchTerm] = useState('')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)

  // --- PDF 다운로드용 Ref ---
  const reportRef = useRef(null)

  // --- 데이터 불러오기 ---
  useEffect(() => {
    const fetchInitialData = async () => {
      try {
        const [allLogsResponse, vulnerabilitiesResponse] = await Promise.all([
          fetch('http://localhost:8000/api/logs'),
          fetch('http://localhost:8000/api/logs/vulnerabilities'),
        ])

        if (!allLogsResponse.ok || !vulnerabilitiesResponse.ok) {
          throw new Error('데이터를 불러오는 중 문제가 발생했습니다.')
        }

        const allLogsJson = await allLogsResponse.json()
        const vulnerabilitiesJson = await vulnerabilitiesResponse.json()

        setAllLogs(allLogsJson)
        setVulnerabilities(vulnerabilitiesJson)
        setDisplayedData(allLogsJson)
      } catch (err) {
        setError(err.message)
      } finally {
        setIsLoading(false)
      }
    }

    fetchInitialData()
  }, [])

  // --- 검색 및 필터 ---
  const handleShowAll = () => setDisplayedData(allLogs)
  const handleShowVulnerabilities = () => setDisplayedData(vulnerabilities)
  const handleSearchChange = (event) => setSearchTerm(event.target.value)

  const filteredData = displayedData.filter((log) =>
    log._source.original_log.toLowerCase().includes(searchTerm.toLowerCase())
  )

  //  로그 통계 및 요약 텍스트 생성
  const total = filteredData.length
  const normal = filteredData.filter(
    (log) => log._source.prediction.toLowerCase() === 'normal'
  ).length
  const attackLogs = filteredData.filter(
    (log) => log._source.prediction.toLowerCase() !== 'normal'
  )
  const attack = attackLogs.length

  const attackTypes = {}
  attackLogs.forEach((log) => {
    const type = log._source.prediction
    attackTypes[type] = (attackTypes[type] || 0) + 1
  })

  let reportText = `업로드된 로그 파일은 총 ${total}개의 요청으로 구성되어 있으며, `
  reportText += `${normal}개는 정상으로 분류되었습니다. `
  if (attack > 0) {
    reportText += `또한 ${attack}개의 요청에서 공격 패턴이 탐지되었습니다. `
    reportText += `공격 유형은 ${Object.entries(attackTypes)
      .map(([type, count]) => `${type} ${count}건`)
      .join(', ')} 등이 확인되었습니다. `
  } else {
    reportText += '공격 패턴은 발견되지 않았습니다.'
  }

  let warningText = ''
  if (attack > 0) {
    warningText = ` 보안 경고: ${attack}개의 악성 로그가 발견되었습니다. 즉시 시스템 점검 및 관리자 확인이 필요합니다.`
  }

  // --- PDF 다운로드 ---
  const downloadPDF = () => {
    const input = reportRef.current
    html2canvas(input, { scale: 2 }).then((canvas) => {
      const imgData = canvas.toDataURL('image/png')
      const pdf = new jsPDF('p', 'mm', 'a4')
      const imgWidth = 210
      const pageHeight = 297
      const imgHeight = (canvas.height * imgWidth) / canvas.width
      let heightLeft = imgHeight
      let position = 0

      pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight)
      heightLeft -= pageHeight

      while (heightLeft > 0) {
        position = heightLeft - imgHeight
        pdf.addPage()
        pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight)
        heightLeft -= pageHeight
      }

      pdf.save('log-analysis-report.pdf')
    })
  }

  // --- 화면 표시 ---
  if (isLoading) return <div>Loading dashboard...</div>
  if (error) return <div>Error: {error}</div>

  return (
    <div className="dashboard-container" ref={reportRef}>
      <h1>AI Log Analysis Dashboard</h1>

      <div className="controls">
        <button onClick={handleShowAll}>
          전체 로그 보기 ({allLogs.length}개)
        </button>
        <button onClick={handleShowVulnerabilities}>
          취약점만 보기 ({vulnerabilities.length}개)
        </button>
        <input
          type="text"
          placeholder="로그 내용 검색..."
          value={searchTerm}
          onChange={handleSearchChange}
        />
        <button className="pdf-button" onClick={downloadPDF}>
          📄 PDF 다운로드
        </button>
      </div>

      {/* 요약 리포트 문구 표시 영역 */}
      <div className="report-summary">
        <p>{reportText}</p>
        {warningText && <p className="warning-text">{warningText}</p>}
      </div>

      <div className="content-area">
        <div className="table-container">
          <h3>Log Details ({filteredData.length}개 표시)</h3>
          <table>
            <thead>
              <tr>
                <th>Prediction</th>
                <th>Anomaly Score</th>
                <th>Original Log</th>
              </tr>
            </thead>
            <tbody>
              {filteredData.map((logItem) => (
                <tr key={logItem._id}>
                  <td>{logItem._source.prediction}</td>
                  <td>{logItem._source.anomaly_score.toFixed(4)}</td>
                  <td>{logItem._source.original_log}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="chart-container">
          <LogChart logs={filteredData} />
        </div>
      </div>
    </div>
  )
}

export default LogDashboard