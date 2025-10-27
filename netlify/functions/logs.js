// Netlify Functions�� CommonJS ȯ�濡 ���߾� require()�� ����մϴ�.
const fetch = require('node-fetch');

// Vultr VPS�� ���� IP �ּҿ� Elasticsearch ��Ʈ (9200)�� ���� ����
const ELASTICSEARCH_HOST = 'http://141.164.62.254:9200';
const CONNECTION_ERROR_MESSAGE = 'Failed to connect to Elasticsearch.';

exports.handler = async (event) => {
    // 1. ��û ��ȿ�� �˻� (POST ��û�� ó��)
    if (event.httpMethod !== 'POST' || !event.body) {
        return { 
            statusCode: 405, 
            body: JSON.stringify({ error: 'Method Not Allowed' }) 
        };
    }

    try {
        // 2. ����Ʈ���忡�� ���� JSON ������ �Ľ�
        const { endpoint, query } = JSON.parse(event.body);

        // Vultr Elasticsearch ������ ��û ����
        const requestHeaders = { 
            'Content-Type': 'application/json',
        };
        
        // 3. Vultr Elasticsearch ������ ��û ����
        const esResponse = await fetch(`${ELASTICSEARCH_HOST}/${endpoint}`, {
            method: 'POST',
            headers: requestHeaders,
            body: JSON.stringify(query) // Elasticsearch ���� ����
        });
        
        // 4. ���� ���� ó��: Elasticsearch���� 4xx/5xx ���� �߻� �� ���� �ڵ带 �״�� ����
        if (!esResponse.ok) {
            const errorBody = await esResponse.text();
            console.error(`Elasticsearch returned error ${esResponse.status}: ${errorBody}`);
            
            // ���� �߻� �� JSON ���� ������ ���߾� ����Ʈ����� ����
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
                // JSON�� �ƴ� �Ϲ� �ؽ�Ʈ ������ �Ѿ�� ���
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

        // 5. ���� ���� ������ ó�� �� ��ȯ
        const data = await esResponse.json();

        return {
            statusCode: 200,
            // CORS ������ �ذ��ϱ� ���� Access-Control-Allow-Origin: * ����� �߰�
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*' 
            },
            body: JSON.stringify(data)
        };

    } catch (error) {
        // 6. ���� ���� �� ����ġ ���� ���� �߻� �� ó��
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