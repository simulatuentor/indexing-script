// indexing-tool.js - Código completo funcional
(function(){
  const API_ENDPOINT = 'https://indexing.googleapis.com/v3/urlNotifications:publish';
  const METADATA_ENDPOINT = 'https://indexing.googleapis.com/v3/urlNotifications/metadata?url=';
  
  window.procesarSolicitud = async function() {
    const credentials = document.getElementById('credentials').files[0];
    const urls = document.getElementById('urls').value.split('\n').filter(u => u.trim());
    const type = document.getElementById('request-type').value;
    const responseDiv = document.getElementById('response');
    
    responseDiv.innerHTML = '<div style="color:#4a5568;">Procesando solicitudes...</div>';
    
    try {
      // 1. Validación básica
      if (!credentials) throw new Error('Debes subir el archivo JSON de credenciales');
      if (urls.length === 0) throw new Error('Debes ingresar al menos una URL');
      
      // 2. Autenticación
      const { client_email, private_key } = JSON.parse(await credentials.text());
      const jwt = await generarJWT(client_email, private_key);
      const { access_token } = await obtenerTokenAcceso(jwt);
      
      // 3. Procesar URLs
      const resultados = [];
      for (const url of urls) {
        const resultado = await procesarURL(url, type, access_token);
        resultados.push(resultado);
      }
      
      // 4. Mostrar resultados
      responseDiv.innerHTML = resultados.map(res => {
        let icono = '❌';
        if (res.status === 200) icono = '✅';
        if (res.status === 429) icono = '⚠️';
        
        return `${icono} <strong>${res.url}</strong> - ${res.mensaje}`;
      }).join('<br>');
      
    } catch (error) {
      responseDiv.innerHTML = `❌ Error crítico: ${error.message}`;
    }
  };

  async function generarJWT(client_email, private_key) {
    const header = { alg: 'RS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    
    const claimSet = {
      iss: client_email,
      scope: 'https://www.googleapis.com/auth/indexing',
      aud: 'https://oauth2.googleapis.com/token',
      exp: now + 3600,
      iat: now
    };
    
    // Codificar componentes JWT
    const base64Header = btoa(JSON.stringify(header)).replace(/=+$/, '');
    const base64Claim = btoa(JSON.stringify(claimSet)).replace(/=+$/, '');
    const firma = await firmarDatos(`${base64Header}.${base64Claim}`, private_key);
    
    return `${base64Header}.${base64Claim}.${firma}`;
  }

  async function firmarDatos(data, privateKey) {
    const pemContents = privateKey
      .replace(/-----BEGIN PRIVATE KEY-----/, '')
      .replace(/-----END PRIVATE KEY-----/, '')
      .replace(/\n/g, '');
    
    const binaryKey = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
    
    const key = await crypto.subtle.importKey(
      'pkcs8',
      binaryKey,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      key,
      new TextEncoder().encode(data)
    );
    
    return btoa(String.fromCharCode(...new Uint8Array(signature)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  async function obtenerTokenAcceso(jwt) {
    const respuesta = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });
    
    if (!respuesta.ok) {
      const error = await respuesta.json();
      throw new Error(error.error_description || 'Error de autenticación');
    }
    
    return respuesta.json();
  }

  async function procesarURL(url, tipo, token) {
    try {
      let endpoint, metodo, cuerpo;
      
      if (tipo === 'URL_STATUS') {
        endpoint = `${METADATA_ENDPOINT}${encodeURIComponent(url)}`;
        metodo = 'GET';
        cuerpo = null;
      } else {
        endpoint = API_ENDPOINT;
        metodo = 'POST';
        cuerpo = JSON.stringify({
          url: url.includes('://') ? url : `http://${url}`,
          type: tipo
        });
      }
      
      const respuesta = await fetch(endpoint, {
        method: metodo,
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: cuerpo
      });
      
      const datos = await respuesta.json();
      
      return {
        url: url,
        status: respuesta.status,
        mensaje: tipo === 'URL_STATUS' 
          ? `Estado: ${datos.latestUpdate?.urlNotificationMetadata?.latestUpdate?.type || 'Desconocido'}`
          : datos.error?.message || 'Solicitud exitosa'
      };
      
    } catch (error) {
      return {
        url: url,
        status: 500,
        mensaje: error.message || 'Error desconocido'
      };
    }
  }
})();
