# 🔐 Password Encryptor

A simple Python-based tool to encrypt and decrypt messages using a password. The password is used to derive a secure key for encryption — no storage, no database, just fast and secure encryption in memory.

---

## 🚀 Features

- Encrypt messages using a password
- Decrypt messages with the correct password
- Uses strong AES encryption (via Fernet)
- No storage – everything stays in memory
- Easy to run and modify

---

## 🛠️ Requirements

- Python 3.6+
- `cryptography` library

Install dependencies with:

```bash
pip install cryptography
````

---

## 🧪 How It Works

* A random salt is generated for each encryption session.
* The password + salt are used to generate a key via PBKDF2HMAC.
* The message is encrypted using the derived key (Fernet).
* To decrypt, the same password and salt must be used.

---

## ▶️ Usage

1. Clone or download the project.

2. Run the script:

```bash
python encryptor.py
```

3. Follow the prompts to:

   * Enter a message
   * Enter a password
   * See the encrypted message and salt
   * Re-enter the password to decrypt

---

## 📁 Project Structure

```
password-encryptor/
├── encryptor.py       # Main script
├── README.md          # Project documentation
```

---

## 🔒 Example Output

```
Enter a message to encrypt: hello world
Enter a password: mysecret

Encrypted: b'gAAAAABl...'
Salt: a0c5e1b7f812bc...

Enter the password to decrypt: mysecret
Decrypted: hello world
```

---

## 📌 Notes

* If you lose the salt or forget the password, the data **cannot be decrypted**.
* For production use, always secure your salt and encryption strategy.

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

Made with ❤️ in Python by \[Your Name]

```

---

Let me know if you'd like to generate this into a file or add features like a GUI or web interface.
```
