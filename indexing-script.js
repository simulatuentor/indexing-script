document.getElementById('indexing-form').addEventListener('submit', async function(event) {
    event.preventDefault(); // Evita que la página se recargue al enviar el formulario

    const credentialsFile = document.getElementById('credentials').files[0];
    const requestType = document.getElementById('request-type').value;
    const urls = document.getElementById('urls').value.split('\n').map(url => url.trim()).filter(url => url);
    const responseElement = document.getElementById('response');

    if (!credentialsFile || urls.length === 0) {
        responseElement.textContent = 'Por favor, sube el archivo JSON y agrega al menos una URL.';
        return;
    }

    try {
        // Leer el archivo de credenciales
        const credentials = await credentialsFile.text();
        const { client_email, private_key } = JSON.parse(credentials);

        // Obtener el token de autenticación de Google
        const token = await getAccessToken(client_email, private_key);
        if (!token) {
            throw new Error('Error al obtener el token de autenticación');
        }

        // Enviar solicitudes a la API de Indexación
        const results = await Promise.all(urls.map(url => sendIndexingRequest(token, requestType, url)));

        responseElement.textContent = 'Solicitudes completadas:\n' + results.join('\n');
    } catch (error) {
        responseElement.textContent = 'Error: ' + error.message;
    }
});

// Obtener el token de acceso de Google usando la API
async function getAccessToken(clientEmail, privateKey) {
    const tokenEndpoint = 'https://oauth2.googleapis.com/token';

    const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            client_id: clientEmail,
            client_secret: privateKey,
            scope: 'https://www.googleapis.com/auth/indexing'
        })
    });

    const data = await response.json();
    return data.access_token;
}

// Enviar la solicitud de indexación a Google
async function sendIndexingRequest(token, type, url) {
    const apiUrl = 'https://indexing.googleapis.com/v3/urlNotifications:publish';

    const response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ url, type })
    });

    if (!response.ok) throw new Error(`Error con la URL ${url}`);
    return `Indexación exitosa: ${url}`;
}
