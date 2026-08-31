# 🛡️AttackLens

AttackLens è uno strumento di security assessment automatizzato progettato per analizzare server, siti web e servizi esposti, individuare potenziali vulnerabilità e generare un report dettagliato dei risultati.
Prende in input un indirizzo web (dominio o IP) e un'email, esegue una serie di verifiche di vulnerabilità sul bersaglio, calcola un punteggio di rischio complessivo e invia un report riepilogativo via email.

## ⚙️ Come funziona?
Il flusso si sviluppa attraverso i seguenti passaggi:
1. **Ricezione e Validazione:** Un Webhook riceve i dati del target e dell'email, verificandone la correttezza formale.
2. **Pianificazione dei Test:** Vengono generati vari controlli di sicurezza mirati (es. verifica header, ricerca file esposti, tentativi di injection).
3. **Esecuzione e Analisi:** Il sistema effettua le richieste HTTP verso il bersaglio, analizza le risposte ricevute e calcola un punteggio di sicurezza (da 0 a 100).
4. **Notifica e Risposta:** Viene inviata un'email con il report formattato e viene restituita una conferma tramite webhook.

---

## 🔍 Cosa controlla?
L'analisi verifica la presenza di problemi comuni e vulnerabilità, tra cui:
* Configurazione degli header di sicurezza HTTP.
* Presenza di file sensibili o di configurazione esposti pubblicamente.
* Eventuali vulnerabilità applicative (come SQL Injection, XSS e Command Injection).
* Stato del certificato SSL e presenza di directory listing attivi.


**Provalo subito su https://rosscoding.com/AttackLens/**
