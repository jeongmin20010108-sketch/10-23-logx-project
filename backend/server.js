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

// Elasticsearch 클라이언트 설정 (localhost:9200 사용 - 올바름)
const esClient = new Client({
  node: "http://localhost:9200",
  tls: {
    rejectUnauthorized: false,
  },
});

// Elasticsearch 연결 확인 함수
async function checkConnection() {
  try {
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
    const { body: exists } = await esClient.indices.exists({ index: indexName });
    if (!exists) {
      console.log(`'${indexName}' 인덱스가 없어 새로 생성합니다.`);
      await esClient.indices.create({
        index: indexName,
        mappings: {
          properties: {
            "anomaly_score": { "type": "float" },
            "prediction": { "type": "keyword" },
            "original_log": { "type": "text" },
            "url": { "type": "keyword" },
            "status": { "type": "keyword" }
          }
        }
      });
      console.log(`'${indexName}' 인덱스 생성이 완료되었습니다.`);
    }
    const { body: response } = await esClient.count({ index: indexName });
    console.log(`'${indexName}' 인덱스의 문서 수:`, response.count);
  } catch (error) {
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
  destination: (req, file, cb) => {
    // server.js가 backend 폴더 안에 있으므로, 상대 경로는 'AI/AI/logs/'가 맞음
    const destPath = path.join(__dirname, 'AI/AI/logs/');
    console.log(`파일 저장 경로: ${destPath}`);
    cb(null, destPath);
   },
  filename: (req, file, cb) => { cb(null, file.originalname); }
});
const upload = multer({ storage: storage });

// 로그 파일 업로드, 삭제, AI 분석 실행 라우터
app.post("/upload-log", upload.single("logFile"), async (req, res) => {
    if (!req.file) { /* ... */ }
    try {
        console.log("🔄 /upload-log: 요청 수신됨."); // 요청 수신 로그 추가
        const indexName = 'analyzed-logs';
        // indices.exists() 반환 값은 boolean이 아닐 수 있으므로 body 확인
        const existsResponse = await esClient.indices.exists({ index: indexName });
        const exists = existsResponse.body; // Elasticsearch 8.x 이상

        if (exists) {
            console.log(`🔄 /upload-log: '${indexName}' 인덱스 존재 확인. 기존 데이터 삭제 시작...`);
            await esClient.deleteByQuery({
                index: indexName,
                body: { query: { match_all: {} } },
                refresh: true
            });
            console.log("✅ /upload-log: 기존 데이터 삭제 완료.");
        } else {
            console.log(`ℹ️ /upload-log: '${indexName}' 인덱스가 없어 새로 생성합니다.`);
             await esClient.indices.create({ 
                index: indexName,
                mappings: {
                 properties: {
                    "anomaly_score": { "type": "float" },
                    "prediction": { "type": "keyword" },
                    "original_log": { "type": "text" },
                    "url": { "type": "keyword" },
                    "status": { "type": "keyword" }
                 }
                }
             });
             console.log(`✅ /upload-log: '${indexName}' 인덱스 생성 완료.`);
        }

        const logFilePath = req.file.path;
        console.log(`✅ /upload-log: 파일 저장 완료: ${logFilePath}`);
        console.log("▶ /upload-log: AI 분석 시작...");

        // [확인 완료] Python 가상 환경 경로 및 스크립트 경로 정의
        const scriptPath = path.join(__dirname, 'AI/AI/asdfg.py'); // server.js 위치 기준

        // 🚨 [수정 완료] Shell 명령어로 가상 환경 활성화 및 스크립트 실행을 강제합니다.
        const pythonExecutable = '/bin/bash'; // 쉘 실행 파일
        const pythonArgs = [
            '-c',
            // 쉘에서 'source venv/bin/activate'로 가상 환경 활성화 후, Python 실행 파일과 스크립트를 실행
            `source /root/10-23-logx-project/venv/bin/activate && /usr/bin/python3 ${scriptPath} ${logFilePath}`
        ];

        console.log(`📜 /upload-log: 스크립트 경로: ${scriptPath}`);
        console.log(`🐍 /upload-log: 실행될 Shell 명령: ${pythonArgs[1]}`); // 실행될 최종 명령 로그

        // ⚠️ [수정 완료] spawn 호출: Shell 실행 파일과 인자 배열을 사용하고, { shell: true } 옵션을 추가
        const pythonProcess = spawn(pythonExecutable, pythonArgs, { shell: true }); // <--- { shell: true } 추가!

        let analysisResult = '';
        let errorOutput = '';

        pythonProcess.stdout.on('data', (data) => {
            const outputChunk = data.toString();
            console.log(`🐍 [stdout]: ${outputChunk}`); // stdout 로그 추가
            analysisResult += outputChunk;
        });
        pythonProcess.stderr.on('data', (data) => {
            const errorChunk = data.toString();
            console.error(`🐍 [stderr]: ${errorChunk}`); // stderr 로그 추가
            errorOutput += errorChunk;
        });

        pythonProcess.on('close', async (code) => {
            console.log(`🐍 /upload-log: Python 스크립트 종료 코드: ${code}`);
            if (code !== 0) {
                console.error(`❌ /upload-log: AI 분석 스크립트 오류 (종료 코드: ${code})`, errorOutput);
                return res.status(500).json({ message: "AI 분석 실패", error: errorOutput || "스크립트 실행 중 오류 발생" });
            }
            try {
                console.log("✅ /upload-log: AI 분석 완료. 결과 파싱 및 Elasticsearch 저장 시작...");
                console.log("🐍 /upload-log: Python Raw Output (before parse):", analysisResult); // 파싱 전 원본 출력 확인

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
                res.status(500).json({ message: "결과 처리 실패", error: e.message, rawOutput: analysisResult });
            }
        });

         pythonProcess.on('error', (spawnError) => {
             console.error('❌ /upload-log: Python 프로세스 생성 실패:', spawnError);
             res.status(500).json({ message: "AI 분석 프로세스를 시작할 수 없습니다.", error: spawnError.message });
         });

    } catch (err) {
        console.error("❌ /upload-log: 파일 처리 또는 ES 데이터 삭제 중 오류 발생:", err);
        res.status(500).json({ message: "데이터 처리 초기 단계에서 오류가 발생했습니다.", error: err.message });
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
    res.json(body?.hits?.hits ?? []);
  } catch (error) {
    console.error('❌ /api/logs: 전체 로그 조회 API 오류:', error.meta ? error.meta.body : error);
    res.status(500).json({ message: '데이터 조회에 실패했습니다.', error: error.message });
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
          bool: { // tbool -> bool 수정
            must_not: [{ match: { 'prediction': 'normal' } }]
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

