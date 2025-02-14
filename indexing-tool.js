// indexing-tool.js
async function handleSubmit() {
  const credentialsFile = document.getElementById('credentials').files[0];
  const urls = document.getElementById('urls').value.split('\n').filter(url => url.trim() !== '');
  const requestType = document.getElementById('request-type').value;
  const responseDiv = document.getElementById('response');

  if (!credentialsFile || urls.length === 0) {
    responseDiv.innerHTML = '❌ Faltan credenciales o URLs';
    return;
  }

  try {
    // Autenticación con Google
    const credentials = JSON.parse(await credentialsFile.text());
    const authToken = await authenticate(credentials);
    
    // Enviar solicitudes a la API
    const results = await Promise.all(
      urls.map(url => sendRequest(url, requestType, authToken))
    );

    // Mostrar resultados
    responseDiv.innerHTML = results.map(result => 
      `✅ ${result.url}: ${result.status}`
    ).join('<br>');

  } catch (error) {
    responseDiv.innerHTML = `❌ Error: ${error.message}`;
  }
}

async function authenticate(credentials) {
  const { private_key, client_email } = credentials;
  const header = { alg: 'RS256', typ: 'JWT' };
  const claimSet = {
    iss: client_email,
    scope: 'https://www.googleapis.com/auth/indexing',
    aud: 'https://oauth2.googleapis.com/token',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000)
  };

  // Generar JWT
  const encodedHeader = btoa(JSON.stringify(header));
  const encodedClaimSet = btoa(JSON.stringify(claimSet));
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    await importPKCS8(private_key),
    new TextEncoder().encode(`${encodedHeader}.${encodedClaimSet}`)
  );

  const jwt = `${encodedHeader}.${encodedClaimSet}.${btoa(String.fromCharCode(...new Uint8Array(signature))}`;

  // Obtener token de acceso
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });

  const data = await response.json();
  return data.access_token;
}

async function sendRequest(url, type, token) {
  const response = await fetch('https://indexing.googleapis.com/v3/urlNotifications:publish', {
    method: 'POST',
    body: JSON.stringify({ url: url.trim(), type: type }),
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    }
  });

  return { url, status: response.status };
}

// Helper para importar clave privada
async function importPKCS8(pem) {
  const pemContents = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\n/g, '');
  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['sign']
  );
}