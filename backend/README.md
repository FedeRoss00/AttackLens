# AttackLens

Nello sviluppo dell'utility mi sono servito di un piccolo **file in php** per la gestione di **frontend** e di un **workflow in n8n come backend.**

## Dettaglio del Codice di Attacco

**Nodo 1**
**Imposto un link di tipo webhook in grado di ricevere le richieste**
il link webhook è un indirizzo con la capacità di rimanere in ascolto e in attesa di recezione di dati (in questo caso col metodo POST).

```json
     {
      "parameters": {
        "httpMethod": "POST",
        "path": "723b643c-7a77-4c7e-92b9-05e523e5b8ea",
        "responseMode": "responseNode",
        "options": {}
      },
      "type": "n8n-nodes-base.webhook",
      "typeVersion": 2.1,
      "position": [
        -944,
        -160
      ],
      "id": "c0bf9e42-c5e7-4d4d-a7f0-33c9d4ef8f16",
      "name": "Webhook1",
      "webhookId": "723b643c-7a77-4c7e-92b9-05e523e5b8ea"
    }
```

**Nodo 2**
**Controllo i dati ricevuti per la richiesta**
con il seguente codice attraverso i const rawTarget e rawEmail reperisco i dati ricevuti salvandoli. Successivamente attraverso i replace ripulisco il dato del target (o dominio) da https e gli slash. Poi dichiaro le costanti ipRegex, domainRegex, emailRegex per controllare la formazione dei dati. Infine applico le regole definite, gestisco gli errori e restituisco i dati.

```json
    {
      "parameters": {
        "jsCode": "const body = $('Webhook1').first().json.body || $('Webhook1').first().json;
        \nconst rawTarget = body.target ? body.target.trim() : '';
        \nconst rawEmail = body.email ? body.email.trim() : '';
        
        \n\nlet cleanTarget = rawTarget\n  .replace(/^https?:\\/\\//i, '')\n  .replace(/\\/.*$/, '');
        
        \n\nconst ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        \nconst domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$/;
        \nconst emailRegex = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;\n\nconst isValidTarget = cleanTarget && (ipRegex.test(cleanTarget) || domainRegex.test(cleanTarget));
        \nconst isValidEmail = rawEmail && emailRegex.test(rawEmail);
        
        \n\nif (!isValidTarget) {
            \n  throw new Error(`Target non valido: \"${rawTarget}\".`);
            
            \n}\nif (!isValidEmail) {
                \n  throw new Error(`Indirizzo email non valido: \"${rawEmail}\".`);
                
                
                \n}\n\nreturn [{
                    \n  json: {
                        \n    target: cleanTarget,
                        \n    original_target: rawTarget,
                        \n    email: rawEmail,
                        \n    validated_at: new Date().toISOString()
                        \n  }
                        \n}];"
      },
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [
        -768,
        -160
      ],
      "id": "c8872c64-2bbc-45e8-88a7-9da921b088e4",
      "name": "Check Richiesta1"
    }
```

**Nodo 3**
**Simulazione di Attacchi al Dominio o IP**
dopo aver recuperato i dati di email e target attraverso il seguente modulo imposto la simulazione di attacchi.
1. Attraverso il https://${target} invio una richiesta alla home page per verificare che il server risponda includendo l'header HTTP.
2. Attraverso il https://${target}/.env tento di scaricare file .env solitamente usati per memorizzare chiavi API, password etc.
3. Attraverso https://${target}/.git/HEAD verifico se è presente e accessibile la cartella nascosta di git che contiene solitamente tutto il codice del sito.
4. Attraverso https://${target}/backup.sql cerco una possibile copia di backup nella cartella pubblica.
5. Attraverso https://${target}/config.php cerco di accedere al file di configurazione generico.
6. Attraverso https://${target}/wp-config.php cerco il file di configurazione di Wordpress che contiene credenziali di accesso e controlla che il login in Wordpress non sia pubblico.
7. Attraverso https://${target}/swagger-ui.html controllo se la documentazione API è pubblica, ciò fornirebbe una mappa dettagliata delle rotte possibili al server.
8. Attraverso di nuovo https://${target} esamino che la risposta del server non riveli l'infrastruttura (tipo l'utilizzo di Apache, Nginx etc).
9. Attraverso https://${target}/../../../../etc/passwd risalgo all'albero delle cartelle del server tentando di leggere i file con password su Linux.
10. Attraverso https://${target}/..%5c..%5c..%5cwindows%5cwin.ini eseguo lo stesso controllo del punto 9 ma per la controparte Windows.
11. Attraverso https://${target}/?id=1'%20OR%20'1'='1 invio una sintassi tipica per i database per verificare se è vulnerabile ad attacchi e restituisce errori.
12. Attraverso https://${target}/?search=%3Cscript%3Econsole.log('XSS_TEST')%3C%2Fscript%3E inietto nel codice JS all'interno del parametro search per vedere se il server restituisce senza sanitizzare.
13. Attraverso https://${target}/?cmd=127.0.0.1%3Bwhoami tento di eseguire un comando direttamente nel cmd e verifico se il server lo esegue direttamente.
14. Attraverso https://${target}/uploads/ tento di accedere alla cartella dei caricamenti.
15. Attraverso di nuovo https://${target} verifico che la connssione sia sicura attraverso l'header HTTPS.

```json
    {
      "parameters": {
        "jsCode": "
        \nconst target = $('Check Richiesta1').first().json.target;
        \nconst email = $('Check Richiesta1').first().json.email;

        \n\nconst testList = [
            \n  { tipo: 'HEADER_SECURITY', nome: 'Controllo Header di Sicurezza HTTP', url: `https://${target}`, metodo: 'GET' },
            \n  { tipo: 'EXPOSED_FILE', nome: 'File di Configurazione (.env)', url: `https://${target}/.env`, metodo: 'GET' },
            \n  { tipo: 'EXPOSED_FILE', nome: 'Repository Git Esposto (.git/HEAD)', url: `https://${target}/.git/HEAD`, metodo: 'GET' },
            \n  { tipo: 'EXPOSED_FILE', nome: 'Backup Database Esposto (.sql)', url: `https://${target}/backup.sql`, metodo: 'GET' },
            \n  { tipo: 'EXPOSED_FILE', nome: 'File di Configurazione (config.php)', url: `https://${target}/config.php`, metodo: 'GET' },
            \n  { tipo: 'EXPOSED_FILE', nome: 'File wp-config.php (WordPress)', url: `https://${target}/wp-config.php`, metodo: 'GET' },
            \n  { tipo: 'API_SWAGGER', nome: 'Documentazione API / Swagger Esposta', url: `https://${target}/swagger-ui.html`, metodo: 'GET' },
            \n  { tipo: 'INFO_DISCLOSURE', nome: 'Information Disclosure (Header tecnologici)', url: `https://${target}`, metodo: 'GET' },
            \n  { tipo: 'PATH_TRAVERSAL_LINUX', nome: 'Path Traversal Linux (/etc/passwd)', url: `https://${target}/../../../../etc/passwd`, metodo: 'GET' },
            \n  { tipo: 'PATH_TRAVERSAL_WIN',   nome: 'Path Traversal Windows (win.ini)', url: `https://${target}/..%5c..%5c..%5cwindows%5cwin.ini`, metodo: 'GET' },
            \n  { tipo: 'SQL_INJECTION', nome: 'SQL Injection (errori nel body)', url: `https://${target}/?id=1'%20OR%20'1'='1`, metodo: 'GET' },
            \n  { tipo: 'XSS_REFLECTED', nome: 'Cross-Site Scripting Riflesso (XSS)', url: `https://${target}/?search=%3Cscript%3Econsole.log('XSS_TEST')%3C%2Fscript%3E`, metodo: 'GET' },
            \n  { tipo: 'COMMAND_INJECTION', nome: 'Command Injection (OS)', url: `https://${target}/?cmd=127.0.0.1%3Bwhoami`, metodo: 'GET' },
            \n  { tipo: 'DIRECTORY_LISTING', nome: 'Directory Listing (cartella /uploads/)', url: `https://${target}/uploads/`, metodo: 'GET' },
            \n  { tipo: 'SSL_CHECK', nome: 'Verifica HTTPS e Certificato SSL', url: `https://${target}`, metodo: 'GET' }
            \n];\n\nreturn testList.map(test => ({
                \n  json: {
                    \n    ...test,
                    \n    target: target,
                    \n    email: email\n  }
                    \n}));
                    \n"
      },
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [
        -608,
        -160
      ],
      "id": "57d7674c-8eca-4946-928a-b4721ba25d5e",
      "name": "Simulate Attack1"
    }
```

**Nodo 4**
**Invio della simulazione di attacchi al target**
leggo i dati in ingresso ricevuti dal nodo precedente e restituisce per ogni test effettuato i risultati. Nel nodo imposto che ignori i certificati SSL/TLS così da non essere bloccato. Imposto un timeout di 1000 se per caso il server non risponde. Imposto il fullResponse per ricevere tutti i risultati. Ignoro anche gli errori ricevuti (tipo 404, 403 etc). Infine con followRedirects impedisco fli indirizzamenti automatici.

```json
    {
      "parameters": {
        "method": "={{ $json.metodo }}",
        "url": "={{ $json.url }}",
        "options": {
          "allowUnauthorizedCerts": true,
          "timeout": 10000,
          "response": {
            "response": {
              "fullResponse": true,
              "neverError": true
            }
          },
          "redirect": {
            "redirect": {
              "followRedirects": false
            }
          }
        }
      },
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.5,
      "position": [
        -432,
        -160
      ],
      "id": "916f5b3d-0745-48bb-9225-6a85fb8bf105",
      "name": "HTTP Request1",
      "onError": "continueRegularOutput"
    }
```

**Nodo 5**
**Prepazione Risultati Analisi**
Questo blocco di codice analizza i risultati dei test di sicurezza eseguiti, calcolo un punteggio da 0 a 100 e genera il report finale.

Funzionamento principale:
1.  Recupero dati: Prende le risposte HTTP ottenute e le associa ai test originali.
2.  Analisi: Per ogni test, verifica il `statusCode` (es. 200, 404), gli `headers` e il `body` alla ricerca di configurazioni errate o vulnerabilità note.
3.  Calcolo del punteggio: Si parte da 100 e si detraggono punti in base alla gravità dei problemi riscontrati:
    *   -5 a -10 punti: Problemi lievi (es. header di sicurezza mancanti, versioni software esposte).
    *   -15 a -20 punti: Problemi medi (es. directory listing, Swagger/API pubbliche, assenza di HTTPS).
    *   -30 a -35 punti: Vulnerabilità critiche (es. file sensibili esposti, Path Traversal, SQL o Command Injection).
4.  Generazione Report: In base al punteggio finale, assegno un livello (SICURO, A RISCHIO, CRITICO) e restituisce un singolo oggetto JSON contenente tutti i dettagli della scansione, pronto per essere inviato via email.

```json
{
  "parameters": {
    "jsCode": "
\nconst responses = $input.all();
\nconst originalTests = $('Simulate Attack1').all();
\n
\nlet score = 100;
\nlet findings = [];
\nlet detailedTests = [];
\n
\nconst target = $('Check Richiesta1').first().json.target || 'Target Sconosciuto';
\nconst email = $('Check Richiesta1').first().json.email || '';
\n
\noriginalTests.forEach((test, index) => {
\n  const original = test.json;
\n  const responseItem = responses[index] ? responses[index].json : {};
\n  
\n  const statusCode = responseItem.statusCode || 0;
\n  const headers = responseItem.headers || {};
\n  const rawBody = responseItem.body || '';
\n  const body = typeof rawBody === 'string' ? rawBody : JSON.stringify(rawBody);
\n  
\n  const h = (name) => headers[name.toLowerCase()] || '';
\n  
\n  if (original.tipo === 'HEADER_SECURITY') {
\n    let missingCount = 0;
\n    let headerIssues = [];
\n    
\n    if (!h('strict-transport-security')) {
\n      score -= 5;
\n      findings.push('[LIEVE] Manca header HSTS (Strict-Transport-Security).');
\n      headerIssues.push('HSTS');
\n      missingCount++;
\n    }
\n    if (!h('content-security-policy')) {
\n      score -= 10;
\n      findings.push('[MEDIO] Manca header Content-Security-Policy (CSP).');
\n      headerIssues.push('CSP');
\n      missingCount++;
\n    }
\n    if (!h('x-frame-options')) {
\n      score -= 5;
\n      findings.push('[LIEVE] Manca header X-Frame-Options.');
\n      headerIssues.push('X-Frame-Options');
\n      missingCount++;
\n    }
\n    if (!h('x-content-type-options')) {
\n      score -= 5;
\n      findings.push('[LIEVE] Manca header X-Content-Type-Options.');
\n      headerIssues.push('X-Content-Type-Options');
\n      missingCount++;
\n    }
\n    if (!h('referrer-policy')) {
\n      score -= 3;
\n      findings.push('[LIEVE] Manca header Referrer-Policy.');
\n      headerIssues.push('Referrer-Policy');
\n      missingCount++;
\n    }
\n    if (!h('permissions-policy') && !h('feature-policy')) {
\n      score -= 3;
\n      findings.push('[LIEVE] Manca header Permissions-Policy.');
\n      headerIssues.push('Permissions-Policy');
\n      missingCount++;
\n    }
\n    
\n    if (statusCode === 0) {
\n      detailedTests.push({ nome: original.nome, esito: '⚠️ Nessuna risposta ricevuta (timeout o errore)' });
\n    } else if (missingCount > 0) {
\n      detailedTests.push({ nome: original.nome, esito: `⚠️ ${missingCount} header mancanti: ${headerIssues.join(', ')}` });
\n    } else {
\n      detailedTests.push({ nome: original.nome, esito: '✅ Ottimale (tutti gli header presenti)' });
\n    }
\n  }
\n  
\n  if (original.tipo === 'EXPOSED_FILE') {
\n    if (statusCode === 200) {
\n      score -= 20;
\n      findings.push(`[ALTO] Risorsa sensibile esposta pubblicamente: ${original.url}`);
\n      detailedTests.push({ nome: original.nome, esito: `🚨 Esposto (200 OK)` });
\n    } else if (statusCode >= 301 && statusCode <= 302) {
\n      detailedTests.push({ nome: original.nome, esito: `ℹ️ Reindirizzamento (${statusCode}) - non direttamente esposto` });
\n    } else {
\n      detailedTests.push({ nome: original.nome, esito: `✅ Protetto (${statusCode})` });
\n    }
\n  }
\n  
\n  if (original.tipo === 'API_SWAGGER') {
\n    const swaggerPaths = [
\n      '/swagger-ui.html', '/swagger-ui/', '/api-docs',
\n      '/v2/api-docs', '/v3/api-docs', '/openapi.json', '/swagger.json'
\n    ];
\n    const bodyLower = body.toLowerCase();
\n    const isSwaggerBody = bodyLower.includes('swagger') || bodyLower.includes('openapi') || bodyLower.includes('api-docs');
\n    
\n    if (statusCode === 200 && isSwaggerBody) {
\n      score -= 15;
\n      findings.push(`[MEDIO] Documentazione API/Swagger esposta: ${original.url}`);
\n      detailedTests.push({ nome: original.nome, esito: '⚠️ Swagger/API docs esposti (200 OK)' });
\n    } else if (statusCode === 200) {
\n      detailedTests.push({ nome: original.nome, esito: `ℹ️ Risposta 200 ma non sembra Swagger` });
\n    } else {
\n      detailedTests.push({ nome: original.nome, esito: `✅ Non trovato / Protetto (${statusCode})` });
\n    }
\n  }
\n  
\n  if (original.tipo === 'INFO_DISCLOSURE') {
\n    const serverHeader = h('server');
\n    const poweredBy = h('x-powered-by');
\n    const aspNet = h('x-aspnet-version');
\n    const aspNetMvc = h('x-aspnetmvc-version');
\n    
\n    let disclosed = [];
\n    if (serverHeader) disclosed.push(`Server: ${serverHeader}`);
\n    if (poweredBy) disclosed.push(`X-Powered-By: ${poweredBy}`);
\n    if (aspNet) disclosed.push(`X-AspNet-Version: ${aspNet}`);
\n    if (aspNetMvc) disclosed.push(`X-AspNetMvc-Version: ${aspNetMvc}`);
\n    
\n    if (disclosed.length > 0) {
\n      score -= 5;
\n      findings.push(`[LIEVE] Information Disclosure: ${disclosed.join(', ')}`);
\n      detailedTests.push({ nome: original.nome, esito: `⚠️ Header tecnologici esposti: ${disclosed.join(', ')}` });
\n    } else {
\n      detailedTests.push({ nome: original.nome, esito: '✅ Nessuna informazione tecnica esposta' });
\n    }
\n  }
\n  
\n  if (original.tipo === 'PATH_TRAVERSAL_LINUX') {
\n    const isVulnerable = statusCode === 200 && (
\n      body.includes('root:x:0:0') ||
\n      body.includes('root:!:') ||
\n      body.includes('/bin/bash') ||
\n      body.includes('/bin/sh')
\n    );
\n    if (isVulnerable) {
\n      score -= 30;
\n      findings.push(`[CRITICO] Vulnerabile a Path Traversal Linux: ${original.url}`);
\n      detailedTests.push({ nome: original.nome, esito: '🚨 Vulnerabile - /etc/passwd accessibile' });
\n    } else {
\n      detailedTests.push({ nome: original.nome, esito: `✅ Sicuro (${statusCode})` });
\n    }
\n  }
\n  
\n  if (original.tipo === 'PATH_TRAVERSAL_WIN') {
\n    const isVulnerable = statusCode === 200 && (
\n      body.includes('[extensions]') ||
\n      body.includes('[fonts]') ||
\n      body.includes('[mci extensions]') ||
\n      body.toLowerCase().includes('for 16-bit app support')
\n    );
\n    if (isVulnerable) {
\n      score -= 30;
\n      findings.push(`[CRITICO] Vulnerabile a Path Traversal Windows: ${original.url}`);
\n      detailedTests.push({ nome: original.nome, esito: '🚨 Vulnerabile - win.ini accessibile' });
\n    } else {
\n      detailedTests.push({ nome: original.nome, esito: `✅ Sicuro (${statusCode})` });
\n    }
\n  }
\n  
\n  if (original.tipo === 'SQL_INJECTION') {
\n    const sqlErrors = [
\n      /you have an error in your sql syntax/i,
\n      /unclosed quotation mark/i,
\n      /sqlite3::/i,
\n      /pg_query\\(\\)/i,
\n      /ORA-\\d{5}/,
\n      /Microsoft OLE DB Provider for SQL/i,
\n      /Incorrect syntax near/i,
\n      /mysql_fetch_array\\(\\)/i,
\n      /supplied argument is not a valid MySQL/i,
\n      /Warning.*mysql_.*\\(\\)/i,
\n      /valid MySQL result/i,
\n      /MySqlException/i,
\n      /SqlException/i
\n    ];
\n    const isVulnerable = statusCode === 200 && sqlErrors.some(rx => rx.test(body));
\n    if (isVulnerable) {
\n      score -= 30;
\n      findings.push(`[CRITICO] Possibile SQL Injection rilevato: ${original.url}`);
\n      detailedTests.push({ nome: original.nome, esito: '🚨 Vulnerabile - errori SQL nel body' });
\n    } else {
\n      detailedTests.push({ nome: original.nome, esito: `✅ Sicuro (${statusCode})` });
\n    }
\n  }
\n  
\n  if (original.tipo === 'XSS_REFLECTED') {
\n    const xssPayload = \"<script>console.log('XSS_TEST')</script>\";
\n    const isVulnerable = statusCode === 200 && body.includes(xssPayload);
\n    if (isVulnerable) {
\n      score -= 20;
\n      findings.push(`[ALTO] Reflected XSS rilevato: ${original.url}`);
\n      detailedTests.push({ nome: original.nome, esito: '🚨 Vulnerabile - payload XSS riflesso' });
\n    } else {
\n      detailedTests.push({ nome: original.nome, esito: `✅ Sicuro (${statusCode})` });
\n    }
\n  }
\n  
\n  if (original.tipo === 'COMMAND_INJECTION') {
\n    const rcePatterns = [
\n      /uid=\\d+.*gid=\\d+/i,
\n      /root:x:0:0/,
\n      /www-data/,
\n      /nt authority/i,
\n      /WINDOWS\\\\system32/i
\n    ];
\n    const isVulnerable = statusCode === 200 && rcePatterns.some(rx => rx.test(body));
\n    if (isVulnerable) {
\n      score -= 35;
\n      findings.push(`[CRITICO] Command Injection rilevato: ${original.url}`);
\n      detailedTests.push({ nome: original.nome, esito: '🚨 Vulnerabile - output di sistema nel body' });
\n    } else {
\n      detailedTests.push({ nome: original.nome, esito: `✅ Sicuro (${statusCode})` });
\n    }
\n  }
\n  
\n  if (original.tipo === 'DIRECTORY_LISTING') {
\n    const isListing = statusCode === 200 && (
\n      body.includes('Index of /') ||
\n      body.includes('<title>Index of') ||
\n      body.includes('Directory listing for') ||
\n      /\\[DIR\\].*Parent Directory/i.test(body)
\n    );
\n    if (isListing) {
\n      score -= 15;
\n      findings.push(`[MEDIO] Directory Listing attivo: ${original.url}`);
\n      detailedTests.push({ nome: original.nome, esito: '⚠️ Directory Listing attivo' });
\n    } else {
\n      detailedTests.push({ nome: original.nome, esito: `✅ Disabilitato (${statusCode})` });
\n    }
\n  }
\n  
\n  if (original.tipo === 'SSL_CHECK') {
\n    if (statusCode >= 200 && statusCode < 400) {
\n      const hasHSTS = !!h('strict-transport-security');
\n      detailedTests.push({
\n        nome: original.nome,
\n        esito: hasHSTS ? '✅ HTTPS operativo + HSTS attivo' : '✅ HTTPS operativo (HSTS assente)'
\n      });
\n    } else if (statusCode === 0) {
\n      score -= 20;
\n      findings.push('[ALTO] Impossibile raggiungere il server via HTTPS - potrebbe non supportarlo.');
\n      detailedTests.push({ nome: original.nome, esito: '🚨 HTTPS non raggiungibile (timeout o errore SSL)' });
\n    } else {
\n      score -= 15;
\n      findings.push(`[MEDIO] HTTPS risponde con status anomalo: ${statusCode}`);
\n      detailedTests.push({ nome: original.nome, esito: `⚠️ HTTPS anomalo (${statusCode})` });
\n    }
\n  }
\n});
\n
\nscore = Math.max(0, score);
\n
\nconst livello = score >= 80 ? 'SICURO' : score >= 50 ? 'A RISCHIO' : 'CRITICO';
\n
\nreturn [{
\n  json: {
\n    target: target,
\n    email: email,
\n    esito: livello,
\n    punteggio: `${score}/100`,
\n    punteggio_numerico: score,
\n    vulnerabilita_trovate: findings.length,
\n    dettagli_vulnerabilita: findings,
\n    dettagli_test: detailedTests,
\n    data_scansione: new Date().toLocaleString('it-IT')
\n  }
\n}];
\n"
  }
}
```

**Nodo 6**
**Invio Risultato via email**
imposto le credenziali api per inviare un email tramite il mio indirizzo all'email inserita dall'utente con il risultato calcolato.

```json
   {
      "parameters": {
        "sendTo": "={{ $('Webhook1').item.json.body.email }}",
        "subject": "={{ \"Report di Sicurezza - \" + $('Prepare Result1').item.json.target }}",
        "message": "=<div style=\"font-family: Arial, sans-serif; background-color: #f4f4f7; padding: 20px;\">\n  <div style=\"max-width: 600px; background: #ffffff; padding: 30px; border-radius: 8px; margin: auto;\">\n    <h2 style=\"color: #333; text-align: center;\">Report di Sicurezza</h2>\n    <p><strong>Target analizzato:</strong> {{ $('Prepare Result1').first().json.target }}</p>\n    <p><strong>Data scansione:</strong> {{ $('Prepare Result1').first().json.data_scansione }}</p>\n    <hr style=\"border: none; border-top: 1px solid #eee;\">\n    \n    <div style=\"padding: 15px; border-radius: 6px; text-align: center; background-color: {{ $('Prepare Result1').first().json.esito === 'SICURO' ? '#d4edda' : '#f8d7da' }}; color: {{ $('Prepare Result1').first().json.esito === 'SICURO' ? '#155724' : '#721c24' }}; margin-bottom: 20px;\">\n      <h3 style=\"margin: 0;\">Stato: {{ $('Prepare Result1').first().json.esito }} (Punteggio: {{ $('Prepare Result1').first().json.punteggio }})</h3>\n    </div>\n\n    <h3 style=\"color: #444;\">📋 Riepilogo dei Test Eseguiti:</h3>\n    <table style=\"width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 14px;\">\n      <tr style=\"background-color: #f8f9fa; border-bottom: 2px solid #dee2e6;\">\n        <th style=\"padding: 10px; text-align: left;\">Controllo</th>\n        <th style=\"padding: 10px; text-align: left;\">Esito</th>\n      </tr>\n      {{ $('Prepare Result1').first().json.dettagli_test.map(t => `<tr style=\"border-bottom: 1px solid #eee;\"><td style=\"padding: 10px;\">${t.nome}</td><td style=\"padding: 10px;\">${t.esito}</td></tr>`).join('') }}\n    </table>\n\n    <h3 style=\"color: #444;\">⚠️ Anomalie e Vulnerabilità ({{ $('Prepare Result1').first().json.vulnerabilita_trovate }}):</h3>\n    <ul style=\"color: #555; font-size: 14px; line-height: 1.5;\">\n      {{ $('Prepare Result1').first().json.dettagli_vulnerabilita.map(item => `<li>${item}</li>`).join('') || '<li>Nessuna vulnerabilità critica rilevata. Ottimo lavoro!</li>' }}\n    </ul>\n  </div>\n</div>",
        "options": {}
      },
      "type": "n8n-nodes-base.gmail",
      "typeVersion": 2.2,
      "position": [
        -16,
        -160
      ],
      "id": "537e7892-1ff8-4bdc-9cf2-aeeb9a1cad12",
      "name": "Send a message1",
      "webhookId": "9883518e-0818-43f1-9f25-872eec5cf6b2",
      "credentials": {
        "gmailOAuth2": {
          "id": "fvJUO6Dfp5AQIjjN",
          "name": "Gmail account"
        }
      }
    }
```