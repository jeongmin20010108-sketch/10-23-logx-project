import React, { useState } from "react"
import { useNavigate } from "react-router-dom"
import "./styles/LoginPage.css"

function LoginPage({ setIsLoggedIn }) {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const navigate = useNavigate()

  const handleLogin = async (e) => {
    e.preventDefault()

    try {
      const response = await fetch("http://localhost:8000/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username, password }),
      })

      const data = await response.json()

      if (response.ok) {
        alert("로그인 성공")
        setIsLoggedIn(true)
        navigate("/") // 메인 페이지로 이동
      } else {
        alert(data.message) // 에러 메시지 표시
      }
    } catch (err) {
      console.error("로그인 중 에러 발생:", err)
      alert("서버 연결 실패")
    }
  }

  return (
    <div className="login-container">
      <div className="login-box">
        <h2>로그인</h2>
        <form onSubmit={handleLogin}>
          <div className="input-group">
            <label>아이디</label>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div className="input-group">
            <label>비밀번호</label>
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <button type="submit" className="login-button">
            로그인
          </button>
        </form>
      </div>
    </div>
  )
}

export default LoginPage
