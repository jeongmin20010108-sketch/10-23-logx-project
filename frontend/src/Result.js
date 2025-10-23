import React, { useEffect, useState, useRef } from "react"
import jsPDF from "jspdf"
import html2canvas from "html2canvas"
import { PieChart, Pie, Cell, Tooltip, Legend } from "recharts"
import { AlertTriangle } from "lucide-react"

function Result({ analysisData = [] }) {
  const [report, setReport] = useState("")
  const [warning, setWarning] = useState("")
  const reportRef = useRef()

  // 📑 요약 & 보안 경고 생성
  useEffect(() => {
    const total = analysisData.length
    const normal = analysisData.filter((d) => d.prediction === "normal").length
    const attack = total - normal

    const attackTypes = analysisData
      .filter((d) => d.prediction !== "normal")
      .reduce((acc, d) => {
        acc[d.prediction] = (acc[d.prediction] || 0) + 1
        return acc
      }, {})

    let reportText = `업로드된 로그 파일은 총 ${total}개의 요청으로 구성되어 있으며, `
    reportText += `${normal}개는 정상으로 분류되었습니다. `
    if (attack > 0) {
      reportText += `또한 ${attack}개의 요청에서 공격 패턴이 탐지되었습니다. `
      reportText += `공격 유형은 ${Object.entries(attackTypes)
        .map(([type, count]) => `${type} ${count}건`)
        .join(", ")} 등이 확인되었습니다. `
    } else {
      reportText += "공격 패턴은 발견되지 않았습니다."
    }

    let warningText = ""
    if (attack > 0) {
      warningText = `⚠️ 보안 경고: ${attack}개의 악성 로그가 발견되었습니다. `
      warningText += "즉시 시스템 점검 및 관리자 확인이 필요합니다."
    }

    setReport(reportText)
    setWarning(warningText)
  }, [analysisData])

  // 📊 차트 데이터
  const normal = analysisData.filter((d) => d.prediction === "normal").length
  const attackCounts = analysisData
    .filter((d) => d.prediction !== "normal")
    .reduce((acc, d) => {
      acc[d.prediction] = (acc[d.prediction] || 0) + 1
      return acc
    }, {})

  const pieData = [
    { name: "normal", value: normal },
    ...Object.entries(attackCounts).map(([type, count]) => ({
      name: type,
      value: count,
    })),
  ]

  const COLORS = ["#82ca9d", "#ff7f7f", "#8884d8", "#ffc658"]

  // 📥 PDF 다운로드 함수
  const downloadPDF = () => {
    const input = reportRef.current
    html2canvas(input, { scale: 2 }).then((canvas) => {
      const imgData = canvas.toDataURL("image/png")
      const pdf = new jsPDF("p", "mm", "a4")
      const imgWidth = 210
      const pageHeight = 297
      const imgHeight = (canvas.height * imgWidth) / canvas.width
      let heightLeft = imgHeight
      let position = 0

      pdf.addImage(imgData, "PNG", 0, position, imgWidth, imgHeight)
      heightLeft -= pageHeight

      while (heightLeft > 0) {
        position = heightLeft - imgHeight
        pdf.addPage()
        pdf.addImage(imgData, "PNG", 0, position, imgWidth, imgHeight)
        heightLeft -= pageHeight
      }

      pdf.save("log-analysis-report.pdf")
    })
  }

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-6">AI 로그 분석 결과</h1>

      {/* 보고서 전체 */}
      <div ref={reportRef} className="bg-white p-6 rounded-lg shadow space-y-6">
        {/* 📑 분석 요약 */}
        <div className="bg-gray-100 p-4 rounded-lg shadow">
          <h2 className="text-lg font-semibold mb-2">📑 분석 요약</h2>
          <p>{report}</p>
        </div>

        {/* ⚠️ 보안 경고 */}
        {warning && (
          <div className="bg-red-100 p-4 rounded-lg shadow border border-red-400">
            <h2 className="text-lg font-semibold flex items-center text-red-700">
              <AlertTriangle className="w-5 h-5 mr-2" /> 보안 경고
            </h2>
            <p className="text-red-700">{warning}</p>
          </div>
        )}

        {/* 📊 차트 */}
        <div className="flex justify-center">
          <PieChart width={400} height={300}>
            <Pie
              data={pieData}
              cx="50%"
              cy="50%"
              outerRadius={100}
              label
              dataKey="value"
            >
              {pieData.map((entry, index) => (
                <Cell key={index} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </div>

        {/* 📑 상세 테이블*/}
        <table className="w-full border">
          <thead>
            <tr className="bg-gray-200">
              <th className="p-2 border">Prediction</th>
              <th className="p-2 border">Score</th>
              <th className="p-2 border">Original Log</th>
            </tr>
          </thead>
          <tbody>
            {analysisData.map((row, idx) => (
              <tr key={idx}>
                <td className="p-2 border">{row.prediction}</td>
                <td className="p-2 border">{row.score.toFixed(4)}</td>
                <td className="p-2 border text-left">{row.log}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {/*📥 PDF 다운로드 버튼 */}
        <button
          onClick={downloadPDF}
          className="mt-6 bg-blue-600 text-white px-4 py-2 rounded-lg shadow"
        >
          📥 PDF 다운로드
        </button>
      </div>
    </div>
  )
}

export default Result
