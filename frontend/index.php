<?php
$message = "";

// Assicurati che l'URL inizi tassativamente con HTTPS e contenga "n8n."
$webhook_url = "https://n8n.rosscoding.com/webhook/723b643c-7a77-4c7e-92b9-05e523e5b8ea"; 

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $target = htmlspecialchars(trim($_POST['target']));
    $email = htmlspecialchars(trim($_POST['email']));
    
    $data = json_encode([
        "target" => $target,
        "email" => $email
    ]);
    
    $ch = curl_init($webhook_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Content-Length: ' . strlen($data)
    ]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);
    curl_close($ch);
    
    if ($http_code >= 200 && $http_code < 300) {
        $message = "<div class='alert success'>✅ Richiesta inviata a n8n con successo!</div>";
    } else {
        $message = "<div class='alert error'>❌ Errore HTTP: $http_code<br><small>Errore cURL: $curl_error</small></div>";
    }
}
?>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scanner Sicurezza — RossCoding</title>
    <!-- Google Fonts Inter -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="stylesheet" href="style.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    
</head>
<body>

    <div class="navbar">
        <a href="https://rosscoding.com" class="logo">Ross<span>Coding</span></a>
    </div>

    <div class="container">
        <div class="badge">AttackLens</div>
        <h2>Avvia Scansione</h2>
        <p class="subtitle">Inserisci il target per analizzare la sicurezza e ricevere il report via email.</p>
        
        <?php echo $message; ?>
        
        <form method="POST" action="">
            <div class="form-group">
                <label for="target">Target (IP o Dominio)</label>
                <input type="text" id="target" name="target" placeholder="es. example.com" required>
            </div>
            
            <div class="form-group">
                <label for="email">Email per ricevere il report</label>
                <input type="email" id="email" name="email" placeholder="es. mario@example.com" required>
            </div>
            
            <button type="submit">Esegui Test</button>
        </form>
    </div>

</body>
</html>