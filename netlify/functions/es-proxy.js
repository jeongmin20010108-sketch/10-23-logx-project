const fetch = require('node-fetch');

// ★★★ Vultr VPS의 공개 IP 주소와 Elasticsearch 포트 (9200) ★★★
// Vultr IP: 141.164.62.254
const ELASTICSEARCH_HOST = 'http://141.164.62.254:9200';

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
        // 프론트엔드에서는 { endpoint: "인덱스명/_search", query: {...} } 형태를 보낼 예정입니다.
        const { endpoint, query } = JSON.parse(event.body);

        // Vultr Elasticsearch로 요청 시 Content-Type 헤더를 포함
        const requestHeaders = { 
            'Content-Type': 'application/json',
        };
        
        // 3. Vultr Elasticsearch 서버로 요청 전달
        const esResponse = await fetch(`${ELASTICSEARCH_HOST}/${endpoint}`, {
            method: 'POST',
            headers: requestHeaders, // 헤더 사용
            body: JSON.stringify(query) // Elasticsearch 쿼리 본문
        });
        
        // 4. 오류 응답 처리: Elasticsearch에서 4xx/5xx 오류 발생 시 상태 코드를 그대로 전달
        if (!esResponse.ok) {
            const errorBody = await esResponse.text();
            console.error(`Elasticsearch returned error ${esResponse.status}: ${errorBody}`);
            return {
                statusCode: esResponse.status,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    error: `Elasticsearch API Error (${esResponse.status})`, 
                    details: JSON.parse(errorBody) 
                })
            };
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
                error: 'Failed to connect to Elasticsearch.', 
                details: error.message 
            })
        };
    }
};
