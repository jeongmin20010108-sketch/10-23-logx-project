// netlify/functions/upload-proxy.js
const fetch = require('node-fetch');

// Vultr VPS�� ���� ���ε� API �ּ� (HTTP)
const VULTR_UPLOAD_URL = 'http://141.164.62.254/upload-log'; 

exports.handler = async (event) => {
    // �ڡڡ� [����� �α� �߰� 1] �Լ� ȣ�� Ȯ�� �ڡڡ�
    console.log("[upload-proxy] Function invoked. HTTP Method:", event.httpMethod);
    console.log("[upload-proxy] Request path:", event.path);
    console.log("[upload-proxy] Request headers:", JSON.stringify(event.headers, null, 2)); // ��� �� ���
    // console.log("[upload-proxy] Request body (first 100 chars):", event.body ? event.body.substring(0, 100) : "No body"); // �ٵ� �Ϻ� ��� (����: FormData�� ��� �ǹ� ����)

    // POST ��û�� ���
    if (event.httpMethod !== 'POST') {
        console.log("[upload-proxy] Error: Method not allowed.");
        return { 
            statusCode: 405, 
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ error: 'Method Not Allowed' }) 
        };
    }

    try {
        // �ڡڡ� [����� �α� �߰� 2] Vultr�� ��û ������ ���� Ȯ�� �ڡڡ�
        console.log("[upload-proxy] Attempting to proxy request to:", VULTR_UPLOAD_URL);
        console.log("[upload-proxy] Forwarding Content-Type header:", event.headers['content-type']);

        const response = await fetch(VULTR_UPLOAD_URL, {
            method: 'POST',
            headers: {
                 'Content-Type': event.headers['content-type'], 
                 // �ʿ�� �ٸ� ����� ���� ���� (��: 'Authorization')
            },
            // Netlify�� body�� Base64 ���ڵ��� �� �����Ƿ� ���ڵ� �ʿ�
            body: event.isBase64Encoded ? Buffer.from(event.body, 'base64') : event.body 
        });

        // �ڡڡ� [����� �α� �߰� 3] Vultr ���� Ȯ�� �ڡڡ�
        console.log("[upload-proxy] Received response from Vultr. Status:", response.status);
        const responseBodyText = await response.text(); // ������ �ؽ�Ʈ�� ���� ����
        console.log("[upload-proxy] Vultr response body:", responseBodyText); 

        // Vultr ���� ���� ó�� (JSON �Ľ� �õ�)
        let data;
        try {
            data = JSON.parse(responseBodyText);
        } catch (parseError) {
             console.error("[upload-proxy] Failed to parse Vultr response as JSON:", parseError);
             // JSON �Ľ� ���� ��, ���� �ؽ�Ʈ ����� �Բ� ���� ��ȯ
             return {
                 statusCode: 500, // �Ǵ� response.status ���
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
        // �ڡڡ� [����� �α� �߰� 4] ���Ͻ� �� �ɰ��� ���� �߻� �ڡڡ�
        console.error('[upload-proxy] Fatal Proxy Error:', error.message, error.stack);
        return {
            statusCode: 500,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ error: 'Failed to proxy upload request to Vultr.', details: error.message })
        };
    }
};