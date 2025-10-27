// Netlify Functions의 CommonJS 환경에 맞추어 require()를 사용합니다.
const fetch = require('node-fetch');

// Vultr VPS의 공개 IP 주소와 Elasticsearch 포트 (9200)를 직접 지정
const ELASTICSEARCH_HOST = 'http://141.164.62.254:9200';
const CONNECTION_ERROR_MESSAGE = 'Failed to connect to Elasticsearch.';

exports.handler = async (event) => {
    // 1. 요청 유효성 검사 (POST 요청만 처리)
    if (event.httpMethod !== 'POST' || !event.body) {
        return { 
            statusCode: 405, 
            body: JSON.stringify({ error: 'Method Not Allowed' }) 
        };
    }

    try {
        // 2. 프론트엔드에서 보낸 JSON 데이터 파싱
        const { endpoint, query } = JSON.parse(event.body);

        // Vultr Elasticsearch 서버로 요청 전달
        const requestHeaders = { 
            'Content-Type': 'application/json',
        };
        
        // 3. Vultr Elasticsearch 서버로 요청 전달
        const esResponse = await fetch(`${ELASTICSEARCH_HOST}/${endpoint}`, {
            method: 'POST',
            headers: requestHeaders,
            body: JSON.stringify(query) // Elasticsearch 쿼리 본문
        });
        
        // 4. 오류 응답 처리: Elasticsearch에서 4xx/5xx 오류 발생 시 상태 코드를 그대로 전달
        if (!esResponse.ok) {
            const errorBody = await esResponse.text();
            console.error(`Elasticsearch returned error ${esResponse.status}: ${errorBody}`);
            
            // 오류 발생 시 JSON 응답 형식을 맞추어 프론트엔드로 전달
            try {
                return {
                    statusCode: esResponse.status,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        error: `Elasticsearch API Error (${esResponse.status})`, 
                        details: JSON.parse(errorBody) 
                    })
                };
            } catch (e) {
                // JSON이 아닌 일반 텍스트 오류가 넘어올 경우
                return {
                    statusCode: esResponse.status,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        error: `Elasticsearch API Error (${esResponse.status})`, 
                        details: errorBody 
                    })
                };
            }
        }

        // 5. 성공 응답 데이터 처리 및 반환
        const data = await esResponse.json();

        return {
            statusCode: 200,
            // CORS 문제를 해결하기 위해 Access-Control-Allow-Origin: * 헤더를 추가
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*' 
            },
            body: JSON.stringify(data)
        };

    } catch (error) {
        // 6. 연결 실패 등 예상치 못한 오류 발생 시 처리
        console.error('Fatal Proxy Error (e.g., network failure):', error.message);
        return {
            statusCode: 500,
            body: JSON.stringify({ 
                error: CONNECTION_ERROR_MESSAGE, 
                details: error.message 
            })
        };
    }
};