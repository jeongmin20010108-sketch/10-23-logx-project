const express = require("express");
const bcrypt = require("bcrypt");
const mysql = require("mysql2");
const cors = require("cors");
const path = require("path");
const multer = require("multer");
const { Client } = require("@elastic/elasticsearch");
const { spawn } = require('child_process');

const app = express();
const PORT = 8000;

// ✅ 미들웨어
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true,
}));
app.use(express.json());

// ✅ MySQL 연결
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "1234",
  database: "my_database",
});

db.connect((err) => {
  if (err) {
    console.error("❌ MySQL 연결 실패:", err.message);
  } else {
    console.log("✅ MySQL 연결 성공!");
  }
});

// ✅ Elasticsearch 연결
const esClient = new Client({
  node: "http://localhost:9201",
  auth: {
    username: "elastic",
    password: "647100",
  },
  tls: {
    rejectUnauthorized: false,
  },
  
});


async function checkConnection() {
  try {
    const health = await esClient.cluster.health();
    const status = health?.body?.status || health?.status || "알 수 없음";
    console.log("✅ Elasticsearch 연결 성공! 상태:", status);
  } catch (err) {
    console.error("❌ Elasticsearch 연결 실패:", err.message);
  }
}

async function checkDocumentCount() {
  try {
    const exists = await esClient.indices.exists({ index: "analyzed-logs" });
    if (!exists) {
      console.log("'analyzed-logs' 인덱스가 없어 새로 생성합니다.");
      await esClient.indices.create({
        index: "analyzed-logs",
        body: {
          mappings: {
            properties: {
              "anomaly_score": { "type": "float" },
              "prediction": { "type": "keyword" },
              "original_log": { "type": "text" },
              "url": { "type": "keyword" },
              "status": { "type": "keyword" }
            }
          }
        }
      });
      console.log("'analyzed-logs' 인덱스 생성이 완료되었습니다.");
    }
    const response = await esClient.count({ index: "analyzed-logs" });
    console.log("'analyzed-logs' 인덱스의 문서 수:", response.count);
  } catch (error) {
    console.error('Elasticsearch 연결 또는 인덱스 확인 중 오류:', error);
  }
}

// --- API 라우트 정의 ---

// ✅ 사용자 인증 관련 API
app.post("/api/login", (req, res) => { /* ... */ });
app.get("/api/check-username", (req, res) => { /* ... */ });
app.post("/api/signup", async (req, res) => { /* ... */ });

// ✅ Multer 설정
const storage = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, 'AI/AI/logs/'); },
  filename: (req, file, cb) => { cb(null, file.originalname); }
});
const upload = multer({ storage: storage });

// ✅ 로그 파일 업로드, 삭제, AI 분석 실행 라우터
app.post("/upload-log", upload.single("logFile"), async (req, res) => {
    if (!req.file) {
        return res.status(400).send("파일이 업로드되지 않았습니다.");
    }
    try {
        console.log("🔄 기존 분석 데이터 삭제를 시작합니다...");
        await esClient.deleteByQuery({
            index: 'analyzed-logs',
            body: { query: { match_all: {} } }
        });
        console.log("✅ 기존 데이터 삭제 완료.");

        const logFilePath = req.file.path;
        console.log(`✅ 파일 저장 완료: ${logFilePath}`);
        console.log("▶ AI 분석을 시작합니다...");

        const pythonProcess = spawn('python', ['AI/AI/asdfg.py', logFilePath]);
        let analysisResult = '';
        let errorOutput = '';
        pythonProcess.stdout.on('data', (data) => { analysisResult += data.toString(); });
        pythonProcess.stderr.on('data', (data) => { errorOutput += data.toString(); });

        pythonProcess.on('close', async (code) => {
            if (code !== 0) {
                console.error(`❌ AI 분석 스크립트 오류 (종료 코드: ${code})`, errorOutput);
                return res.status(500).json({ message: "AI 분석 실패", error: errorOutput });
            }
            try {
                console.log("✅ AI 분석 완료. Elasticsearch에 저장을 시작합니다.");
                const results = JSON.parse(analysisResult);
                if (results.length > 0) {
                    const body = results.flatMap(doc => [{ index: { _index: 'analyzed-logs' } }, doc]);
                    await esClient.bulk({ refresh: true, body });
                }
                console.log("🎉 모든 작업 완료!");
                res.status(200).json({ message: "분석 및 저장 성공", data: results });
            } catch (e) {
                console.error("❌ 분석 결과를 파싱하거나 저장하는 중 오류 발생", e);
                res.status(500).json({ message: "결과 처리 실패", error: e.message });
            }
        });
    } catch (err) {
        console.error("❌ 데이터 삭제 또는 파일 처리 중 오류 발생:", err);
        res.status(500).json({ message: "데이터 처리 초기 단계에서 오류가 발생했습니다.", error: err });
    }
});

// [API] 모든 분석 로그를 조회
app.get('/api/logs', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const { body } = await esClient.search({
      index: 'analyzed-logs',
      body: {
        size: 1000,
        query: { match_all: {} },
        sort: [{ "anomaly_score": "asc" }]
      }
    });
    res.json(body && body.hits ? body.hits.hits : []);
  } catch (error) {
    console.error('전체 로그 조회 API 오류:', error);
    res.status(500).json({ message: '데이터 조회에 실패했습니다.', error });
  }
});


// [API] 취약점으로 의심되는 로그만 조회
app.get('/api/logs/vulnerabilities', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const { body } = await esClient.search({
      index: 'analyzed-logs',
      body: {
        size: 1000,
        query: {
          bool: {
            must_not: [{ match: { 'prediction.keyword': 'normal' } }]
          }
        },
        sort: [{ "anomaly_score": "asc" }]
      }
    });
    res.json(body && body.hits ? body.hits.hits : []);
  } catch (error) {
    console.error('취약점 로그 조회 API 오류:', error);
    res.status(500).json({ message: '취약점 데이터 조회에 실패했습니다.', error });
  }
});


// --- React 정적 파일 서빙 
app.use(express.static(path.join(__dirname, "../frontend/build")));
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/build/index.html"));
});


// --- 서버 시작 ---
app.listen(PORT, () => {
  console.log(`✅ 서버 실행됨: http://localhost:${PORT}`);
  checkConnection();
  checkDocumentCount();
});