# 🔐 Password Manager Flask App

Un gestionnaire de mots de passe sécurisé développé en **Python avec Flask**, offrant :
- Authentification avec **2FA (Google Authenticator)**
- Chiffrement des mots de passe avec **Fernet (AES-128)**
- Interface d'administration protégée
- Antibrute-force pour l'admin
- Stockage sécurisé avec **SQLite + bcrypt**
- Redirection HTTPS
- Sécurité CSRF
- Headers anti-cache

---

## 📦 Fonctionnalités principales

### 👤 Authentification utilisateur
- Formulaire de connexion avec `username` + `password`
- Intégration du **2FA avec TOTP** compatible Google Authenticator
- Vérification de l’utilisateur via session sécurisée
- Séparation des connexions "user" et "admin"

### 🔑 Gestion des mots de passe utilisateur
- Ajout de mots de passe (site, login, mot de passe)
- Chiffrement fort via `Fernet` avant stockage
- Recherche par site ou login
- Suppression individuelle des entrées

### 🛡️ Sécurité intégrée

#### 🔐 Hash des mots de passe utilisateur
- Utilise `bcrypt` avec un salt automatique
- Mot de passe stocké sous forme de hash non réversible
- Vérification avec `bcrypt.checkpw(...)`

#### 🔐 Chiffrement des données utilisateur (mot de passe)
- Chaque mot de passe est chiffré avant enregistrement avec `Fernet` (AES 128-bit en CBC + HMAC)
- Clé générée et stockée dans un fichier `secret.key`
- Déchiffrement à la volée uniquement pour l'affichage

#### 🔐 2FA via TOTP (Time-based One-Time Password)
- Génération d’un secret TOTP avec `pyotp.random_base32()`
- QR Code généré avec `qrcode` et encodé base64
- Vérification avec `pyotp.TOTP(secret).verify(code)`
- Le QR code est affiché une fois à l'inscription

#### 🔐 Anti-brute-force (admin)
- Page `/admin_login` bloquée après 5 tentatives invalides pendant 5 minutes
- IP tracking en mémoire (local)

#### 🔐 Protection CSRF
- Activée avec `Flask-WTF`
- Tous les formulaires utilisent `form.hidden_tag()` pour inclure le token CSRF

#### 🔐 Sécurité des sessions
- `session["username"]` utilisée pour identifier l'utilisateur connecté
- `session["admin_time"]` temporaire, dure 10 minutes maximum
- Après chaque logout ou changement d’utilisateur, la session est nettoyée
- L’interface admin nécessite **le mot de passe à chaque accès**, même après une précédente connexion

#### 🔐 Redirection HTTPS automatique
- Tout accès en HTTP est automatiquement redirigé en HTTPS
- Utilisation d’un certificat TLS auto-signé (`cert.pem` / `key.pem`)

#### 🔐 Headers anti-cache
- `Cache-Control: no-store`
- `Pragma: no-cache`
- Évite que des infos sensibles soient visibles via l’historique du navigateur

---

## 🧠 Structure du projet
```
├── app.py # Fichier principal Flask
├── forms.py # Définitions des formulaires (Login, Register, 2FA)
├── data.db # Base de données SQLite
├── secret.key # Clé de chiffrement Fernet
├── cert.pem / key.pem # Certificat SSL
├── templates/
│ ├── login.html
│ ├── register.html
│ ├── 2fa.html
│ ├── admin.html
│ ├── admin_login.html
│ └── home.html
├── static/ # Fichiers CSS/JS
├── requirements.txt
└── README.md
```

---

## 🗃️ Structure de la base de données

La base SQLite `data.db` contient deux tables :

### `users`

| id | username | password (bcrypt hash) | totp_secret |
|----|----------|-------------------------|-------------|

### `passwords`

| id | user_id | site | login | password (chiffré Fernet) |
|----|---------|------|-------|----------------------------|

---

## 🚀 Lancement de l'application

### 1. Cloner le projet

```bash
git clone https://github.com/MatisCelestin/projet_dev.git
```

### 2. Installer les dépendances
```
pip install -r requirements.txt
```
Contenu de requirements.txt :
```
Flask
flask-wtf
bcrypt
cryptography
pyotp
qrcode
```
### 3. Générer la clé de chiffrement
```
from cryptography.fernet import Fernet
with open("secret.key", "wb") as f:
    f.write(Fernet.generate_key())
```

### 4. Générer le certificat SSL auto-signé
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 5. Lancer l'application
```
python3 app.py
```