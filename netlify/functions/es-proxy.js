// netlify/functions/es-proxy.js

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



        // 3. Vultr Elasticsearch ������ ��û ����

        const esResponse = await fetch(`${ELASTICSEARCH_HOST}/${endpoint}`, {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify(query) // Elasticsearch ���� ����

        });

        

        // 4. ���� ������ ó��

        const data = await esResponse.json();



        // 5. ������ ����Ʈ����� ��ȯ

        return {

            statusCode: esResponse.status,

            // CORS ������ �ذ��ϱ� ���� Access-Control-Allow-Origin: * ����� �߰�

            headers: {

                'Content-Type': 'application/json',

                'Access-Control-Allow-Origin': '*' 

            },

            body: JSON.stringify(data)

        };



    } catch (error) {

        // 6. ���� �߻� �� ó��

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