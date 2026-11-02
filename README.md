# Encryption & Decryption

A web-based application for encrypting and decrypting messages using **AES-256-GCM**.

The project provides a simple interface where users can enter text, provide a password, encrypt their messages, and decrypt encrypted data.

## Features

- AES-256-GCM authenticated encryption.
- Password-based key derivation using PBKDF2-HMAC-SHA256.
- Random salt and initialization vector for each encryption operation.
- Authentication tag to detect modified encrypted data.
- Password-protected decryption.
- Legacy substitution-cipher decryption compatibility.
- Separate encryption and decryption interfaces.
- Responsive design for desktop, tablet, and mobile.
- Copy encrypted or decrypted results.
- REST API powered by Node.js and Express.

## Technology Stack

**Frontend**
- HTML5
- CSS3
- JavaScript

**Backend**
- Node.js
- Express.js
- Node.js built-in Crypto module

**Testing**
- Node.js built-in test runner

## Project Structure

```text
Encryption_Decryption/
│
├── backend/
│   ├── server.js
│   ├── package.json
│   └── test/
│       └── encryption.test.js
│
├── frontend/
│   ├── index.html
│   ├── encrypt.html
│   ├── decrypt.html
│   ├── style.css
│   ├── encr.png
│   └── decr.png
│
└── README.md
```

## Requirements

- Node.js and npm
- Python 3 (for running the frontend locally)
- A modern web browser

## Installation

Clone the repository:

```bash
git clone https://github.com/248World/Encryption_Decryption.git
```

Enter the project directory:

```bash
cd Encryption_Decryption
```

### 1. Start the Backend

Open a terminal:

```bash
cd backend
npm install
npm start
```

The backend runs at:

```text
http://localhost:5000
```

### 2. Start the Frontend

Open another terminal from the project root:

```bash
cd frontend
python -m http.server 3000
```

On Windows, you can also use:

```powershell
py -m http.server 3000
```

Open the application in your browser:

```text
http://localhost:3000/index.html
```

## Application Pages

| Page | Description |
|---|---|
| Home | Choose encryption or decryption |
| Encrypt | Encrypt text using a password |
| Decrypt | Decrypt previously encrypted data |

## Encryption Details

The application uses AES-256-GCM.

The encryption process uses:

- **Algorithm:** AES-256-GCM
- **Key derivation:** PBKDF2-HMAC-SHA256
- **Iterations:** 600,000
- **Derived key length:** 32 bytes
- **Salt:** 16 random bytes
- **Initialization vector:** 12 random bytes
- **Authentication tag:** 16 bytes

Encrypted data uses the following prefix:

```text
AES256GCM:v1:
```

The encrypted payload contains the information required for decryption, including the salt, initialization vector, authentication tag, and ciphertext.

## API Endpoints

The backend provides the following endpoints:

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Check backend availability |
| POST | `/api/encrypt` | Encrypt text |
| POST | `/api/decrypt` | Decrypt encrypted text |

### Health Check

```http
GET /health
```

### Encryption

```http
POST /api/encrypt
Content-Type: application/json
```

### Decryption

```http
POST /api/decrypt
Content-Type: application/json
```

Successful encryption and decryption responses include a `result` field.

## Running Tests

From the backend directory:

```bash
npm test
```

The tests cover encryption, decryption, incorrect passwords, and encrypted-data integrity.

## Security Notes

- Use a strong, unique password.
- Keep your passwords private.
- Do not share sensitive encrypted data and passwords together.
- AES-GCM provides authenticated encryption and detects unauthorized modifications.
- The backend receives plaintext and passwords to perform encryption and decryption. This application is therefore not end-to-end encrypted.
- This project has not undergone an independent security audit. Do not rely on it as a production-grade secure messaging system without further security review.

## Future Improvements

- Add automated frontend tests.
- Improve password-strength guidance.
- Add optional browser-local encryption history without storing passwords.
- Improve accessibility and user experience.
- Add deployment and security documentation.

## License

Add your chosen open-source license before distributing this project under a specific license.
