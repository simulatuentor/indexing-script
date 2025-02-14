// indexing-tool.js - Versión corregida
(function(){
  const API_URL = 'https://indexing.googleapis.com/v3/urlNotifications:publish';
  const AUTH_URL = 'https://oauth2.googleapis.com/token';

  window.procesarSolicitud = async function() {
    const credentials = document.getElementById('credentials').files[0];
    const urls = document.getElementById('urls').value.split('\n').filter(u => u.trim());
    const type = document.getElementById('request-type').value;
    const response = document.getElementById('response');

    try {
      if (!credentials || urls.length === 0) throw new Error('Faltan datos requeridos');

      // Autenticación
      const { client_email, private_key } = JSON.parse(await credentials.text());
      const jwt = await generateJWT(client_email, private_key);
      const { access_token } = await getAuthToken(jwt);

      // Procesar URLs
      const results = [];
      for (const url of urls) {
        const result = await processURL(url.trim(), type, access_token);
        results.push(result);
      }

      response.innerHTML = results.map(r => 
        `${r.success ? '✅' : '❌'} ${r.url}: ${r.status}`
      ).join('<br>');

    } catch (error) {
      response.innerHTML = `⚠️ Error: ${error.message}`;
    }
  };

  async function generateJWT(client_email, private_key) {
    const header = { alg: "RS256", typ: "JWT" };
    const now = Math.floor(Date.now() / 1000);
    const claimSet = {
      iss: client_email,
      scope: "https://www.googleapis.com/auth/indexing",
      aud: AUTH_URL,
      exp: now + 3600,
      iat: now
    };

    const encodedHeader = btoa(JSON.stringify(header)).replace(/=+$/,'');
    const encodedClaim = btoa(JSON.stringify(claimSet)).replace(/=+$/,'');
    const signature = await signData(`${encodedHeader}.${encodedClaim}`, private_key);

    return `${encodedHeader}.${encodedClaim}.${signature}`;
  }

  async function signData(input, key) {
    const pem = key.replace(/(-----(BEGIN|END) PRIVATE KEY-----|\n)/g,'');
    const binaryKey = Uint8Array.from(atob(pem), c => c.charCodeAt(0));

    const importedKey = await crypto.subtle.importKey(
      'pkcs8',
      binaryKey,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      importedKey,
      new TextEncoder().encode(input)
    );

    return btoa(String.fromCharCode(...new Uint8Array(signature)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  async function getAuthToken(jwt) {
    const response = await fetch(AUTH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });
    return response.json();
  }

  async function processURL(url, type, token) {
    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: url.includes('://') ? url : `http://${url}`,
          type: type
        })
      });

      return {
        success: response.ok,
        url: url,
        status: response.status
      };
    } catch (error) {
      return { success: false, url: url, status: error.message };
    }
  }
})();
