// netlify/functions/es-proxy.js

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



        // 3. Vultr Elasticsearch 서버로 요청 전달

        const esResponse = await fetch(`${ELASTICSEARCH_HOST}/${endpoint}`, {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify(query) // Elasticsearch 쿼리 본문

        });

        

        // 4. 응답 데이터 처리

        const data = await esResponse.json();



        // 5. 응답을 프론트엔드로 반환

        return {

            statusCode: esResponse.status,

            // CORS 문제를 해결하기 위해 Access-Control-Allow-Origin: * 헤더를 추가

            headers: {

                'Content-Type': 'application/json',

                'Access-Control-Allow-Origin': '*' 

            },

            body: JSON.stringify(data)

        };



    } catch (error) {

        // 6. 오류 발생 시 처리

        console.error('Elasticsearch Proxy Error:', error);

        return {

            statusCode: 500,

            body: JSON.stringify({ 

                error: 'Failed to proxy request to Elasticsearch.', 

                details: error.message 

            })

        };

    }

};