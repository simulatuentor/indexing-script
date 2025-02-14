// indexing-tool.js - Versión mejorada
const API_ENDPOINT = 'https://indexing.googleapis.com/v3/urlNotifications:publish';

async function procesarSolicitud() {
  const archivoCredenciales = document.getElementById('credentials').files[0];
  const listaURLs = document.getElementById('urls').value.split('\n').map(url => url.trim()).filter(Boolean);
  const tipoSolicitud = document.getElementById('request-type').value;
  const contenedorRespuesta = document.getElementById('response');

  try {
    // Validaciones básicas
    if (!archivoCredenciales || !listaURLs.length) {
      throw new Error('Faltan credenciales o URLs válidas');
    }

    // Autenticación
    const { token } = await obtenerTokenAcceso(archivoCredenciales);
    
    // Procesamiento en lote
    const resultados = [];
    for (const url of listaURLs) {
      const respuesta = await enviarPeticionAPI(url, tipoSolicitud, token);
      resultados.push(respuesta);
    }

    // Mostrar resultados
    contenedorRespuesta.innerHTML = resultados.map(res => 
      `${res.exito ? '✅' : '❌'} ${res.url}: ${res.mensaje}`
    ).join('<br>');

  } catch (error) {
    contenedorRespuesta.innerHTML = `⚠️ Error crítico: ${error.message}`;
    console.error('Detalles del error:', error);
  }
}

async function obtenerTokenAcceso(archivo) {
  const credenciales = JSON.parse(await archivo.text());
  const { private_key, client_email } = credenciales;
  
  // Generar JWT
  const encabezado = btoa(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const fechaActual = Math.floor(Date.now() / 1000);
  const cuerpo = btoa(JSON.stringify({
    iss: client_email,
    scope: "https://www.googleapis.com/auth/indexing",
    aud: "https://oauth2.googleapis.com/token",
    exp: fechaActual + 3500,
    iat: fechaActual
  }));

  const firma = await generarFirma(`${encabezado}.${cuerpo}`, private_key);
  const jwt = `${encabezado}.${cuerpo}.${firma}`;

  // Obtener token
  const respuesta = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });

  const datos = await respuesta.json();
  if (!respuesta.ok) throw new Error(datos.error || 'Error de autenticación');
  return datos;
}

async function generarFirma(datos, clavePrivada) {
  const clave = await crypto.subtle.importKey(
    'pkcs8',
    new Uint8Array([...atob(clavePrivada.replace(/-+(BEGIN|END) PRIVATE KEY-+/g, ''))].map(c => c.charCodeAt(0))),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const firma = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', clave, new TextEncoder().encode(datos));
  return btoa(String.fromCharCode(...new Uint8Array(firma))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function enviarPeticionAPI(url, tipo, token) {
  try {
    const respuesta = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        url: url.startsWith('http') ? url : `https://${url}`,
        type: tipo
      })
    });

    const datos = await respuesta.json();
    return {
      exito: respuesta.ok,
      url,
      mensaje: datos.error ? datos.error.message : 'Procesado correctamente'
    };

  } catch (error) {
    return { exito: false, url, mensaje: error.message };
  }
}
