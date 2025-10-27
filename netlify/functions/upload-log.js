// netlify/functions/upload-proxy.js
const fetch = require('node-fetch');

// Vultr VPS의 파일 업로드 API 주소 (HTTP)
const VULTR_UPLOAD_URL = 'http://141.164.62.254/upload-log'; 

exports.handler = async (event) => {
    // ★★★ [디버깅 로그 추가 1] 함수 호출 확인 ★★★
    console.log("[upload-proxy] Function invoked. HTTP Method:", event.httpMethod);
    console.log("[upload-proxy] Request path:", event.path);
    console.log("[upload-proxy] Request headers:", JSON.stringify(event.headers, null, 2)); // 헤더 상세 출력
    // console.log("[upload-proxy] Request body (first 100 chars):", event.body ? event.body.substring(0, 100) : "No body"); // 바디 일부 출력 (주의: FormData일 경우 의미 없음)

    // POST 요청만 허용
    if (event.httpMethod !== 'POST') {
        console.log("[upload-proxy] Error: Method not allowed.");
        return { 
            statusCode: 405, 
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ error: 'Method Not Allowed' }) 
        };
    }

    try {
        // ★★★ [디버깅 로그 추가 2] Vultr로 요청 보내기 직전 확인 ★★★
        console.log("[upload-proxy] Attempting to proxy request to:", VULTR_UPLOAD_URL);
        console.log("[upload-proxy] Forwarding Content-Type header:", event.headers['content-type']);

        const response = await fetch(VULTR_UPLOAD_URL, {
            method: 'POST',
            headers: {
                 'Content-Type': event.headers['content-type'], 
                 // 필요시 다른 헤더도 전달 가능 (예: 'Authorization')
            },
            // Netlify는 body를 Base64 인코딩할 수 있으므로 디코딩 필요
            body: event.isBase64Encoded ? Buffer.from(event.body, 'base64') : event.body 
        });

        // ★★★ [디버깅 로그 추가 3] Vultr 응답 확인 ★★★
        console.log("[upload-proxy] Received response from Vultr. Status:", response.status);
        const responseBodyText = await response.text(); // 응답을 텍스트로 먼저 받음
        console.log("[upload-proxy] Vultr response body:", responseBodyText); 

        // Vultr 서버 응답 처리 (JSON 파싱 시도)
        let data;
        try {
            data = JSON.parse(responseBodyText);
        } catch (parseError) {
             console.error("[upload-proxy] Failed to parse Vultr response as JSON:", parseError);
             // JSON 파싱 실패 시, 원본 텍스트 응답과 함께 오류 반환
             return {
                 statusCode: 500, // 또는 response.status 사용
                 headers: { 'Content-Type': 'application/json' },
                 body: JSON.stringify({ error: 'Failed to parse Vultr response.', details: responseBodyText })
             };
        }

        return {
            statusCode: response.status,
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*' 
            },
            body: JSON.stringify(data)
        };

    } catch (error) {
        // ★★★ [디버깅 로그 추가 4] 프록시 중 심각한 오류 발생 ★★★
        console.error('[upload-proxy] Fatal Proxy Error:', error.message, error.stack);
        return {
            statusCode: 500,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ error: 'Failed to proxy upload request to Vultr.', details: error.message })
        };
    }
};