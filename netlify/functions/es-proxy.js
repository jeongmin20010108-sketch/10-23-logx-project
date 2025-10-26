const fetch = require('node-fetch');

// �ڡڡ� Vultr VPS�� ���� IP �ּҿ� Elasticsearch ��Ʈ (9200) �ڡڡ�
// Vultr IP: 141.164.62.254
const ELASTICSEARCH_HOST = 'http://141.164.62.254:9200';

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
        // ����Ʈ���忡���� { endpoint: "�ε�����/_search", query: {...} } ���¸� ���� �����Դϴ�.
        const { endpoint, query } = JSON.parse(event.body);

        // Vultr Elasticsearch�� ��û �� Content-Type ����� ����
        const requestHeaders = { 
            'Content-Type': 'application/json',
        };
        
        // 3. Vultr Elasticsearch ������ ��û ����
        const esResponse = await fetch(`${ELASTICSEARCH_HOST}/${endpoint}`, {
            method: 'POST',
            headers: requestHeaders, // ��� ���
            body: JSON.stringify(query) // Elasticsearch ���� ����
        });
        
        // 4. ���� ���� ó��: Elasticsearch���� 4xx/5xx ���� �߻� �� ���� �ڵ带 �״�� ����
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
                error: 'Failed to connect to Elasticsearch.', 
                details: error.message 
            })
        };
    }
};
