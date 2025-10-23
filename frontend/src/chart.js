import React, { useState, useEffect } from 'react';
// react-chartjs-2 라이브러리에서 필요한 컴포넌트들을 가져옴
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Pie } from 'react-chartjs-2';

// Chart.js에 필요한 요소들을 등록
ChartJS.register(ArcElement, Tooltip, Legend);

// 'logs'라는 이름으로 데이터를 props로 받는 차트 컴포넌트를 정의
function LogChart({ logs }) {
  // 차트에 표시할 데이터를 저장할 상태 변수를 만듬
  const [chartData, setChartData] = useState({
    labels: [],
    datasets: [],
  });

  // logs 데이터가 변경될 때마다 차트 데이터를 다시 계산
  useEffect(() => {
    // logs 데이터가 없으면 아무 작업도 하지 않음
    if (!logs || logs.length === 0) {
      return;
    }

    // --- 데이터 가공 ---
    // 'prediction' 값(예: normal, sql_injection) 별로 로그 개수 측정
    const counts = logs.reduce((acc, log) => {
      // 각 로그의 _source.prediction 값을 가져옴
      const prediction = log._source.prediction;
      // 해당 prediction의 카운트를 1 증가
      acc[prediction] = (acc[prediction] || 0) + 1;
      return acc;
    }, {});

    // Chart.js 형식으로 데이터 변환
    const labels = Object.keys(counts); // 차트의 라벨 (예: ['normal', 'sql_injection'])
    const dataValues = Object.values(counts); // 각 라벨에 해당하는 값 (예: [100, 5])

    // 가공된 데이터를 chartData 상태에 업데이트
    setChartData({
      labels: labels,
      datasets: [
        {
          label: '# of Logs',
          data: dataValues,
          backgroundColor: [ // 각 라벨에 대한 색상을 지정
            'rgba(75, 192, 192, 0.2)',
            'rgba(255, 99, 132, 0.2)',
            'rgba(255, 206, 86, 0.2)',
            'rgba(54, 162, 235, 0.2)',
            'rgba(153, 102, 255, 0.2)',
          ],
          borderColor: [
            'rgba(75, 192, 192, 1)',
            'rgba(255, 99, 132, 1)',
            'rgba(255, 206, 86, 1)',
            'rgba(54, 162, 235, 1)',
            'rgba(153, 102, 255, 1)',
          ],
          borderWidth: 1,
        },
      ],
    });
  }, [logs]); // useEffect는 'logs' 데이터가 바뀔 때마다 실행

  // Pie 컴포넌트를 사용해 원형 차트를 화면에 그림
  return (
    <div style={{ width: '400px', height: '400px' }}>
      <h2>Prediction Distribution</h2>
      {logs && logs.length > 0 ? (
        <Pie data={chartData} />
      ) : (
        <p>No data to display in chart.</p>
      )}
    </div>
  );
}

export default LogChart;