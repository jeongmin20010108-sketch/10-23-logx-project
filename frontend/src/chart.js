import React, { useState, useEffect } from 'react';
// react-chartjs-2 ���̺귯������ �ʿ��� ������Ʈ���� ������
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Pie } from 'react-chartjs-2';

// Chart.js�� �ʿ��� ��ҵ��� ���
ChartJS.register(ArcElement, Tooltip, Legend);

// 'logs'��� �̸����� �����͸� props�� �޴� ��Ʈ ������Ʈ�� ����
function LogChart({ logs }) {
  // ��Ʈ�� ǥ���� �����͸� ������ ���� ������ ����
  const [chartData, setChartData] = useState({
    labels: [],
    datasets: [],
  });

  // logs �����Ͱ� ����� ������ ��Ʈ �����͸� �ٽ� ���
  useEffect(() => {
    // logs �����Ͱ� ������ �ƹ� �۾��� ���� ����
    if (!logs || logs.length === 0) {
      return;
    }

    // --- ������ ���� ---
    // 'prediction' ��(��: normal, sql_injection) ���� �α� ���� ����
    const counts = logs.reduce((acc, log) => {
      // �� �α��� _source.prediction ���� ������
      const prediction = log._source.prediction;
      // �ش� prediction�� ī��Ʈ�� 1 ����
      acc[prediction] = (acc[prediction] || 0) + 1;
      return acc;
    }, {});

    // Chart.js �������� ������ ��ȯ
    const labels = Object.keys(counts); // ��Ʈ�� �� (��: ['normal', 'sql_injection'])
    const dataValues = Object.values(counts); // �� �󺧿� �ش��ϴ� �� (��: [100, 5])

    // ������ �����͸� chartData ���¿� ������Ʈ
    setChartData({
      labels: labels,
      datasets: [
        {
          label: '# of Logs',
          data: dataValues,
          backgroundColor: [ // �� �󺧿� ���� ������ ����
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
  }, [logs]); // useEffect�� 'logs' �����Ͱ� �ٲ� ������ ����

  // Pie ������Ʈ�� ����� ���� ��Ʈ�� ȭ�鿡 �׸�
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