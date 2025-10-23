import React from 'react'
import ReactDOM from 'react-dom/client'
import './index.css'
import App from './App'
import reportWebVitals from './reportWebVitals'
import { BrowserRouter } from 'react-router-dom' // ← 추가

const root = ReactDOM.createRoot(document.getElementById('root'))
root.render(
  <React.StrictMode>
    <BrowserRouter>
      <App /> {/* 이제 App 내부에서 useNavigate 사용 가능 */}
    </BrowserRouter>
  </React.StrictMode>
)

reportWebVitals()
