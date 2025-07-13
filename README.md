# Bleichenbacher Attack on PKCS#1 v1.5 RSA Encryption

## 📌 Description
This project demonstrates a practical implementation of the **Bleichenbacher attack**, a padding oracle attack on **RSA encryption using PKCS#1 v1.5**. The attack exploits a padding oracle vulnerability to decrypt RSA-encrypted messages without knowledge of the private key.

It includes:
- A PKCS#1 v1.5 Oracle
- The main logic of bleichenbacher attack
- Neccesary format transformation logic

## How the bleichenbacher attack works
- The attacker eavesdrops the generated cipher
- The attacker sends queries to the padding oracle to find out whether his/her inputs are PKCS#1 v1.5 conformant
- The attacker narrows the possible range of the plaintext by using the oracle
- The attacker obtains the plaintext in int, and then transforms it reveal the original message

## Requirements
- PyCryptodome Library(version 3.13.0)
- Python 3.8+

You can download and test your PyCryptodome
```bash
pip install pycryptodome
pip install pycryptodome-test-vectors
python -m Crypto.SelfTest
```

## 📚 References
- Bleichenbacher, Daniel. "Chosen ciphertext attacks against protocols based on the RSA encryption standard PKCS #1." CRYPTO 1998.
- [Official PyCryptodome API document](https://www.pycryptodome.org/src/api)
