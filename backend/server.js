const express = require("express");
const bcrypt = require("bcrypt");
const mysql = require("mysql2");
const cors = require("cors");
const path = require("path");
const multer = require("multer");
const { Client } = require("@elastic/elasticsearch");
const { spawn } = require('child_process');

const app = express();
// 포트는 80번 사용
const PORT = 80;

// CORS 설정 (Netlify 사이트 허용 - 올바름)
app.use(cors({
  origin: "https://10-23-logx-project.netlify.app",
  credentials: true,
}));
app.use(express.json());

// MySQL 연결 (localhost 사용 - 올바름)
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "1234", // MySQL 설정 시 사용한 비밀번호
  database: "my_database",
});

db.connect((err) => {
  if (err) {
    console.error("❌ MySQL 연결 실패:", err.message);
  } else {
    console.log("✅ MySQL 연결 성공!");
  }
});

// Elasticsearch 클라이언트 설정
const esClient = new Client({
  // [수정 완료] 포트 9200 사용
  node: "http://141.164.62.254:9200",
  // [수정 완료] auth 블록 제거
  tls: {
    rejectUnauthorized: false, // 개발 환경에서는 false 유지 가능
  },
});

// Elasticsearch 연결 확인 함수
async function checkConnection() {
  try {
    // client.ping() 사용 권장
    await esClient.ping();
    console.log("✅ Elasticsearch 연결 성공!");
  } catch (err) {
    console.error("❌ Elasticsearch 연결 실패:", err.message);
  }
}

// Elasticsearch 인덱스 및 문서 수 확인 함수
async function checkDocumentCount() {
  const indexName = "analyzed-logs";
  try {
    // indices.exists() 반환 값은 boolean이 아니라 status code 기반 응답 객체일 수 있음
    const { body: exists } = await esClient.indices.exists({ index: indexName });
    if (!exists) {
      console.log(`'${indexName}' 인덱스가 없어 새로 생성합니다.`);
      await esClient.indices.create({
        index: indexName,
        // Elasticsearch 8.x 이상에서는 body 제거 (index 설정만 전달)
        // body: { // <-- 이 body 제거
        mappings: {
          properties: {
            "anomaly_score": { "type": "float" },
            "prediction": { "type": "keyword" },
            "original_log": { "type": "text" },
            "url": { "type": "keyword" },
            "status": { "type": "keyword" }
          }
        }
        // } // <-- 이 body 닫는 괄호 제거
      });
      console.log(`'${indexName}' 인덱스 생성이 완료되었습니다.`);
    }
    const { body: response } = await esClient.count({ index: indexName }); // body 구조 분해 할당 사용
    console.log(`'${indexName}' 인덱스의 문서 수:`, response.count);
  } catch (error) {
    // 오류 객체의 meta.body를 확인하여 상세 정보 로깅
    console.error('Elasticsearch 연결 또는 인덱스 확인 중 오류:', error.meta ? error.meta.body : error);
  }
}

// --- API 라우터 ---

// 사용자 인증 관련 API (변경 없음)
app.post("/api/login", (req, res) => { /* 실제 구현 필요 */ res.status(501).send('Not Implemented'); });
app.get("/api/check-username", (req, res) => { /* 실제 구현 필요 */ res.status(501).send('Not Implemented'); });
app.post("/api/signup", async (req, res) => { /* 실제 구현 필요 */ res.status(501).send('Not Implemented'); });

// Multer 설정 (경로 확인 필요)
const storage = multer.diskStorage({
  // [확인 필요] server.js 위치 기준으로 'AI/AI/logs/' 경로가 맞는지 확인
  // server.js가 backend 폴더 안에 있다면 이 경로는 backend/AI/AI/logs/가 됩니다.
  destination: (req, file, cb) => {
    const destPath = path.join(__dirname, 'backend/AI/AI/logs/');
    console.log(`파일 저장 경로: ${destPath}`); // 경로 로깅 추가
    cb(null, destPath);
   },
  filename: (req, file, cb) => { cb(null, file.originalname); }
});
const upload = multer({ storage: storage });

// 로그 파일 업로드, 삭제, AI 분석 실행 라우터
app.post("/upload-log", upload.single("logFile"), async (req, res) => {
    if (!req.file) {
        console.log("⚠️ /upload-log: 파일이 업로드되지 않음");
        return res.status(400).send("파일이 업로드되지 않았습니다.");
    }
    try {
        console.log("🔄 /upload-log: 기존 분석 데이터 삭제 시작...");
        await esClient.deleteByQuery({
            index: 'analyzed-logs',
            body: { query: { match_all: {} } },
            refresh: true // 즉시 반영
        });
        console.log("✅ /upload-log: 기존 데이터 삭제 완료.");

        const logFilePath = req.file.path;
        console.log(`✅ /upload-log: 파일 저장 완료: ${logFilePath}`);
        console.log("▶ /upload-log: AI 분석 시작...");

        // [확인 필요] Python 가상 환경 경로 및 스크립트 경로가 정확한지 확인
        // server.js가 backend 폴더 안에 있다고 가정하고 수정
        const venvPython = path.join(__dirname, '../../venv/bin/python3'); // 루트의 venv 사용
        const scriptPath = path.join(__dirname, 'AI/AI/asdfg.py');        // server.js 위치 기준

        console.log(`🐍 /upload-log: Python 경로: ${venvPython}`);
        console.log(`📜 /upload-log: 스크립트 경로: ${scriptPath}`);

        // Python 실행 파일 확인 (python3 또는 python)
        const pythonExecutable = 'python3'; // 또는 시스템에 따라 'python'

        const pythonProcess = spawn(venvPython, [scriptPath, logFilePath]); // venvPython 직접 사용
        let analysisResult = '';
        let errorOutput = '';

        pythonProcess.stdout.on('data', (data) => {
            const outputChunk = data.toString();
            console.log(`🐍 [stdout]: ${outputChunk}`); // [변경] stdout 로그 추가
            analysisResult += outputChunk;
        });
        pythonProcess.stderr.on('data', (data) => {
            const errorChunk = data.toString();
            console.error(`🐍 [stderr]: ${errorChunk}`); // [변경] stderr 로그 추가
            errorOutput += errorChunk;
        });

        pythonProcess.on('close', async (code) => {
            console.log(`🐍 /upload-log: Python 스크립트 종료 코드: ${code}`);
            if (code !== 0) {
                console.error(`❌ /upload-log: AI 분석 스크립트 오류 (종료 코드: ${code})`, errorOutput);
                // 프론트엔드에 오류 메시지 전달 시 errorOutput 포함
                return res.status(500).json({ message: "AI 분석 실패", error: errorOutput || "스크립트 실행 중 오류 발생" });
            }
            try {
                console.log("✅ /upload-log: AI 분석 완료. 결과 파싱 및 Elasticsearch 저장 시작...");
                console.log("🐍 /upload-log: Python Raw Output (before parse):", analysisResult); // 파싱 전 원본 출력 확인

                // Python 스크립트가 유효한 JSON 배열을 출력하는지 확인
                const results = JSON.parse(analysisResult);
                if (!Array.isArray(results)) {
                    console.error("❌ /upload-log: 분석 결과가 JSON 배열 형식이 아님");
                    throw new Error("분석 결과가 JSON 배열 형식이 아닙니다.");
                }

                if (results.length > 0) {
                    const body = results.flatMap(doc => [{ index: { _index: 'analyzed-logs' } }, doc]);
                    console.log(`💾 /upload-log: Elasticsearch 벌크 저장 시도 (${results.length} 건)`);
                    await esClient.bulk({ refresh: true, body });
                    console.log("💾 /upload-log: Elasticsearch 벌크 저장 완료.");
                } else {
                    console.log("ℹ️ /upload-log: 분석 결과 데이터 없음. Elasticsearch 저장 생략.");
                }
                console.log("🎉 /upload-log: 모든 작업 완료!");
                res.status(200).json({ message: "분석 및 저장 성공", data: results });
            } catch (e) {
                console.error("❌ /upload-log: 분석 결과 파싱 또는 ES 저장 중 오류 발생", e);
                // 파싱 오류 시 원본 출력도 함께 전달
                res.status(500).json({ message: "결과 처리 실패", error: e.message, rawOutput: analysisResult });
            }
        });

         pythonProcess.on('error', (spawnError) => {
             console.error('❌ /upload-log: Python 프로세스 생성 실패:', spawnError);
             res.status(500).json({ message: "AI 분석 프로세스를 시작할 수 없습니다.", error: spawnError.message });
         });

    } catch (err) {
        console.error("❌ /upload-log: 파일 처리 또는 ES 데이터 삭제 중 오류 발생:", err);
        res.status(500).json({ message: "파일 처리 초기 단계에서 오류가 발생했습니다.", error: err.message });
    }
});

// 모든 분석 로그 조회 API (오류 로깅 추가)
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
    res.json(body?.hits?.hits ?? []); // Optional chaining 및 nullish coalescing 사용
  } catch (error) {
    console.error('❌ /api/logs: 전체 로그 조회 API 오류:', error.meta ? error.meta.body : error);
    res.status(500).json({ message: '데이터 조회에 실패했습니다.', error: error.message });
  }
});


// 취약점 로그 조회 API (오류 로깅 추가)
app.get('/api/logs/vulnerabilities', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const { body } = await esClient.search({
      index: 'analyzed-logs',
      body: {
        size: 1000,
        query: {
          bool: { // tbool -> bool 수정 (오타 가능성)
            must_not: [{ match: { 'prediction': 'normal' } }] // .keyword 제거 시도 (매핑 따라 다름)
          }
        },
        sort: [{ "anomaly_score": "asc" }]
      }
    });
    res.json(body?.hits?.hits ?? []);
  } catch (error) {
    console.error('❌ /api/logs/vulnerabilities: 취약점 로그 조회 API 오류:', error.meta ? error.meta.body : error);
    res.status(500).json({ message: '취약점 데이터 조회에 실패했습니다.', error: error.message });
  }
});

// 서버 시작
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ 서버 실행됨: http://141.164.62.254:${PORT}`);
  checkConnection(); // Elasticsearch 연결 확인
  checkDocumentCount(); // 인덱스 확인 및 생성
});

