import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import './styles/MainPage.css'
import './styles/Navbar.css'

// [수정] 컴포넌트 함수로 전체 코드를 감쌉니다.
function MainPage() {
  const navigate = useNavigate()
  const [file, setFile] = useState(null)
  const [fileContent, setFileContent] = useState('')
  const [loading, setLoading] = useState(false)

  //  Progress Bar 상태
  const [progress, setProgress] = useState(0)

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0]
    setFile(selectedFile)

    if (selectedFile) {
      const reader = new FileReader()
      reader.onload = () => setFileContent(reader.result)
      reader.readAsText(selectedFile)
    } else {
      setFileContent('')
    }
  }

  const handleUpload = async () => {
    if (!file) {
      alert('파일을 선택해 주세요.')
      return
    }

    setLoading(true)
    setProgress(0)

    //  30초 동안 90%까지 채우는 진행바 설정
    const targetProgress = 90
    const totalDuration = 30000 // 30초
    const updateInterval = 300 // 0.3초마다 업데이트
    const increment = targetProgress / (totalDuration / updateInterval) // 90 / 100 = 0.9%씩 증가

    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev + increment < targetProgress) {
          return prev + increment
        } else {
          return targetProgress
        }
      })
    }, updateInterval)

    const formData = new FormData()
    formData.append('logFile', file)

    try {
        // Vultr VPS 주소 (141.164.62.254:80)로 변경
      const response = await fetch('http://141.164.62.254/upload-log', {
        method: 'POST',
        body: formData,
      })

      const result = await response.json()

      if (response.ok) {
        setProgress(100) // 완료 시점에 100%
        alert('파일 업로드 및 분석이 성공적으로 완료되었습니다!')
        navigate('/logdashboard')
      } else {
        alert(`업로드 실패: ${result.message || '알 수 없는 서버 오류'}`)
      }
    } catch (err) {
      console.error('파일 업로드 중 네트워크 또는 서버 연결 오류:', err)
      alert('서버에 연결할 수 없거나 응답을 받지 못했습니다.')
    } finally {
      clearInterval(progressInterval)
      setLoading(false)
    }
  }

  return (
    <main className="main">
      <h1 className="title">AI 기반 로그 분석</h1>
      <div className="divider"></div>

      <label className="upload-box">
        <input type="file" className="file-input" onChange={handleFileChange} />
        <span className="upload-text">파일을 업로드해 주세요.</span>
      </label>

      {file && <p className="file-name">선택한 파일: {file.name}</p>}

      <div className="preview-box">
        <h3>파일 미리보기 (최대 10줄)</h3>
        <pre>{fileContent.split('\n').slice(0, 10).join('\n')}</pre>
      </div>

      <button onClick={handleUpload} className="upload-button">
        서버에 업로드 및 AI 분석
      </button>

      {loading && (
        <div className="loading-section">
          <p className="loading">⏳ 분석 중입니다... (약 30초)</p>
          <div className="progress-bar">
            <div
              className="progress-bar-fill"
              style={{ width: `${progress}%` }}
            />
          </div>
          <p className="progress-text">{Math.round(progress)}%</p>
        </div>
      )}
    </main>
  )
}

export default MainPage
