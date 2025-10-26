import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import './styles/SignupPage.css'

function SignupPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [email, setEmail] = useState('')
  const [phone, setPhone] = useState('')
  const [usernameAvailable, setUsernameAvailable] = useState(null)
  const [errorMessage, setErrorMessage] = useState('')
  const navigate = useNavigate()

  const handleCheckUsername = async () => {
    if (!username) return

    // [수정] localhost:8000 -> Vultr VPS IP로 변경
    const response = await fetch(
      `http://141.164.62.254/api/check-username?username=${username}`
    )
    const data = await response.json()

    if (data.exists) {
      setUsernameAvailable(false)
      setErrorMessage('이미 사용 중인 아이디입니다.')
    } else {
      setUsernameAvailable(true)
      setErrorMessage('사용 가능한 아이디입니다.')
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()

    if (!email.includes('@')) {
      setErrorMessage('유효한 이메일 주소를 입력하세요.')
      return
    }

    if (password !== confirmPassword) {
      setErrorMessage('비밀번호가 일치하지 않습니다.')
      return
    }

    // [수정] localhost:8000 -> Vultr VPS IP로 변경
    const response = await fetch('http://141.164.62.254/api/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, email, phone }),
    })

    const data = await response.json()
    if (response.ok) {
      alert('회원가입 성공!')
      navigate('/login')
    } else {
      setErrorMessage(`회원가입 실패: ${data.message}`)
    }
  }

  return (
    <div className="signup-container">
      <div className="signup-box">
        <h2>회원가입</h2>
        <form onSubmit={handleSubmit}>
          <div className="input-group">
            <label>아이디</label>
            <div className="input-with-button">
              <input
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value)
                  setUsernameAvailable(null)
                  setErrorMessage('')
                }}
                required
              />
              <button type="button" onClick={handleCheckUsername}>
                중복 확인
              </button>
            </div>
            {usernameAvailable === false && (
              <p className="error">이미 사용 중입니다.</p>
            )}
            {usernameAvailable === true && (
              <p className="success">사용 가능합니다.</p>
            )}
          </div>

          <div className="input-group">
            <label>비밀번호</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          <div className="input-group">
            <label>비밀번호 확인</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>

          <div className="input-group">
            <label>이메일</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          <div className="input-group">
            <label>전화번호</label>
            <input
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              required
            />
          </div>

          {errorMessage && <p className="error">{errorMessage}</p>}

          <button type="submit" className="signup-button">
            회원가입
          </button>
        </form>
      </div>
    </div>
  )
}

export default SignupPage
