import React, { useState } from 'react';

import './styles/MainPage.css';
import './styles/Navbar.css';

// [수정] 컴포넌트 함수로 전체 코드를 감쌉니다.
function MainPage() {
  
  const [file, setFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [loading, setLoading] = useState(false);

  // Progress Bar 상태
  const [progress, setProgress] = useState(0);

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    setFile(selectedFile);

    if (selectedFile) {
      const reader = new FileReader();
      reader.onload = () => setFileContent(reader.result);
      reader.readAsText(selectedFile);
    } else {
      setFileContent('');
    }
  };

  const handleUpload = async () => {
    if (!file) {
      alert('파일을 선택해 주세요.');
      return;
    }

    setLoading(true);
    setProgress(0);

    // 30초 동안 90%까지 채우는 진행바 설정 (Background Function은 더 길어질 수 있음)
    const targetProgress = 90;
    const totalDuration = 30000; // 30초 (UI 표시용)
    const updateInterval = 300;
    const increment = targetProgress / (totalDuration / updateInterval);

    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev + increment < targetProgress) {
          return prev + increment;
        } else {
          // 서버 응답과 관계없이 UI 진행률은 90%까지만 표시
          clearInterval(progressInterval); // 90% 도달 시 인터벌 중지
          return targetProgress;
        }
      });
    }, updateInterval);

    const formData = new FormData();
    formData.append('logFile', file);

    try {
      // Netlify Functions 경로 사용 (/api/upload-log)
      const response = await fetch('/api/upload-log', {
        method: 'POST',
        body: formData,
        // FormData 사용 시 Content-Type 헤더는 브라우저가 자동 설정
      });

      // ★★★ [수정 시작] Background Function 응답 처리 (202 Accepted 확인) ★★★
      if (response.status === 202) {
        // Background Function이 요청을 성공적으로 수신했음을 의미
        setProgress(100); // UI 상 완료 표시
        alert(
          '파일 업로드 및 분석 요청이 시작되었습니다. 분석에는 시간이 걸릴 수 있으며, 완료 후 대시보드에서 결과를 확인하세요.'
        );
        // navigate('/logdashboard'); // 즉시 이동 대신, 나중에 확인하도록 유도하거나 폴링 로직 추가 고려
      } else {
        // Background Function 호출 자체 실패 또는 Vultr 서버의 즉각적인 오류 응답
        let errorMessage = '알 수 없는 서버 오류';
        try {
            // 실패 시에도 JSON 응답이 올 수 있음 (예: 함수 내부 오류)
            const result = await response.json();
            errorMessage = result.message || JSON.stringify(result);
        } catch (jsonError) {
             // JSON 파싱 실패 시 상태 텍스트 사용
             errorMessage = response.statusText || `HTTP Status ${response.status}`;
        }
        setProgress(0); // 오류 시 진행률 초기화
        alert(`업로드 요청 실패: ${errorMessage}`);
      }
      // ★★★ [수정 끝] ★★★

    } catch (err) {
      // 네트워크 오류 등 fetch 자체 실패
      console.error('파일 업로드 중 네트워크 또는 서버 연결 오류:', err);
      setProgress(0); // 오류 시 진행률 초기화
      alert('서버에 연결할 수 없거나 응답을 받지 못했습니다.');
    } finally {
      // 성공/실패 여부와 관계없이 인터벌 정리 및 로딩 상태 해제
      clearInterval(progressInterval);
      setLoading(false);
       // Background 처리이므로 progress를 100으로 유지할지 결정 필요
      // setProgress(0); 
    }
  };

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

      <button onClick={handleUpload} className="upload-button" disabled={loading}>
        {loading ? '분석 요청 중...' : '서버에 업로드 및 AI 분석'}
      </button>

      {loading && (
        <div className="loading-section">
          {/* Background 처리 시 "분석 중" 보다는 "요청 처리 중"이 더 적합할 수 있음 */}
          <p className="loading">⏳ 분석 요청 처리 중입니다...</p>
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
  );
}

export default MainPage;

