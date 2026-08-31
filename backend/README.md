# AttackLens

Nello sviluppo dell'utility mi sono servito di un piccolo **file in php** per la gestione di **frontend** e di un **workflow in n8n come backend.**

## Dettaglio del Codice di Attacco

**Imposto un link di tipo webhook in grado di ricevere le richieste**
il link webhook è un indirizzo con la capacità di rimanere in ascolto e in attesa di recezione di dati (in questo caso col metodo POST).
 ---------------
|               |
|     NODO 1    |
|               |
 ---------------
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

 