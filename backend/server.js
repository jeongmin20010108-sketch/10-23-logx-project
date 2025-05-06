const express = require("express")
const bcrypt = require("bcrypt")
const mysql = require("mysql2")
const cors = require("cors")
const path = require("path")

const app = express() // ✅ 먼저 app 생성
const PORT = 8000

// ✅ 미들웨어 설정
app.use(cors())
app.use(express.json())

// ✅ MySQL 연결 설정
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "rladnwhd2!",
  database: "user_db",
})

// ✅ MySQL 연결 테스트
db.connect((err) => {
  if (err) {
    console.error("❌ MySQL 연결 실패:", err.message)
  } else {
    console.log("✅ MySQL 연결 성공!")
  }
})

// ✅ 회원가입 라우터
app.post("/api/signup", async (req, res) => {
  const { username, password, email, phone } = req.body

  if (!email.includes("@")) {
    return res.status(400).json({ message: "유효한 이메일 형식이 아닙니다." })
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10)
    db.query(
      "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
      [username, hashedPassword, email, phone],
      (err, result) => {
        if (err) return res.status(500).json({ message: "DB 저장 오류" })
        res.status(200).json({ message: "회원가입 성공" })
      }
    )
  } catch (err) {
    res.status(500).json({ message: "서버 오류" })
  }
})

// ✅ 로그인 라우터
app.post("/api/login", (req, res) => {
  const { username, password } = req.body

  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, results) => {
      if (err) return res.status(500).json({ message: "DB 조회 오류" })
      if (results.length === 0) {
        return res.status(401).json({ message: "사용자를 찾을 수 없습니다." })
      }

      const isMatch = await bcrypt.compare(password, results[0].password)
      if (isMatch) {
        res.status(200).json({ message: "로그인 성공" })
      } else {
        res.status(401).json({ message: "비밀번호가 일치하지 않습니다." })
      }
    }
  )
})

// ✅ React 정적 파일 제공
app.use(express.static(path.join(__dirname, "../frontend/build")))
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/build/index.html"))
})

// ✅ 서버 실행
app.listen(PORT, () => {
  console.log(`✅ 서버 실행됨: http://localhost:${PORT}`)
})
