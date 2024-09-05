# OTP
OTP is an open source GUI desktop application written in python that can decrypt and encrypt your texts with OTP (OneTimePad) cipher. 

The One-Time Pad (OTP) cipher is a theoretically unbreakable encryption method. When used correctly, it provides perfect secrecy, meaning that the ciphertext reveals no information about the plaintext without the key.

To ensure the security of the OTP, follow these guidelines: 

1. **Key Length**: The key must be at least as long as the plaintext message. If the message is 100 characters long, the key must also be 100 characters long. The length of passwords created with this program is equal to the length of the plaintext.

2. **Key Randomness**: The key must be generated using a truly random process. Pseudorandom number generators are not sufficient for OTP keys. Luckily this application uses python secrets module to make secure random passwords. 

3. **Key Uniqueness**: Each key must be used only once. Reusing keys can lead to vulnerabilities and can allow attackers to derive information about the plaintext. 

In this program, there is an option called use hex key.  If you enable this option, it will generate random passwords containing hexadecimal characters for you and convert it to bytes data before encrypting and decrypting.

This tool has no protection against side-channel attacks

# OTP-Key-Generator
This program can generate a number of keys and put them in a file to use them in OTP. Because the keys are disposable.

This command creates a file named a.txt and puts 100 keys with length of 1000 in it:
```
otp-key-generator.py -n 100 -l 1000 -o a.txt
```
