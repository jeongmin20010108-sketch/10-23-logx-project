import React, { useState, useEffect } from 'react'
import { Routes, Route, Link, useNavigate } from 'react-router-dom'
import MainPage from './MainPage'
import Result from './Result'
import Log from './Log'
import Login from './LoginPage'
import Signup from './SignupPage'
import './App.css'
import './styles/MainPage.css'
import './styles/Navbar.css'
import LogDashboard from './LogDashboard'

function NavBar({ isLoggedIn, username, setIsLoggedIn, setUsername }) {
  const navigate = useNavigate()

  return (
    <nav className="nav-bar">
      <Link to="/" className="nav-bar-item">
        <span className="nav-label">홈</span>
      </Link>
      <Link to="/log" className="nav-bar-item">
        <span className="nav-label">로그 안내</span>
      </Link>
      <Link to="/result" className="nav-bar-item">
        <span className="nav-label">분석결과</span>
      </Link>
    </nav>
  )
}

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [username, setUsername] = useState('')

  return (
    <div className="container">
      <header className="header">
        <span className="logo">LogX</span>
        <AuthButtons
          isLoggedIn={isLoggedIn}
          username={username}
          setIsLoggedIn={setIsLoggedIn}
          setUsername={setUsername}
        />
        <NavBar
          isLoggedIn={isLoggedIn}
          username={username}
          setIsLoggedIn={setIsLoggedIn}
          setUsername={setUsername}
        />
      </header>

      <main className="main">
        <Routes>
          <Route
            path="/"
            element={
              <MainPage
                isLoggedIn={isLoggedIn}
                username={username}
                setIsLoggedIn={setIsLoggedIn}
                setUsername={setUsername}
              />
            }
          />
          <Route path="/log" element={<Log />} />
          <Route path="/result" element={<Result />} />
          <Route
            path="/login"
            element={
              <Login setIsLoggedIn={setIsLoggedIn} setUsername={setUsername} />
            }
          />
          <Route path="/signup" element={<Signup />} />
          <Route path="/LogDashboard" element={<LogDashboard />} />
        </Routes>
      </main>
    </div>
  )
}

function AuthButtons({ isLoggedIn, username, setIsLoggedIn, setUsername }) {
  const navigate = useNavigate()

  const handleLogout = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/logout', {
        method: 'POST',
        credentials: 'include',
      })
      const data = await res.json()
      setIsLoggedIn(false)
      setUsername('')
      alert(data.message || '로그아웃 완료')
      navigate('/')
    } catch (err) {
      console.error(err)
      setIsLoggedIn(false)
      setUsername('')
      alert('서버 연결 실패, 로그아웃 처리 완료')
      navigate('/')
    }
  }

  if (isLoggedIn) {
    return (
      <>
        <span>{username}님, 반갑습니다</span>
        <button onClick={handleLogout} className="main-login-button">
          로그아웃
        </button>
      </>
    )
  }

  return (
    <>
      <div className="auth-buttons">
        <button
          onClick={() => navigate('/login')}
          className="main-login-button"
        >
          로그인
        </button>
        <button
          onClick={() => navigate('/signup')}
          className="main-signup-button"
        >
          회원가입
        </button>
      </div>
    </>
  )
}

export default App
