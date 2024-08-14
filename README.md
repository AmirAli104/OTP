# OTP
OTP is an open source GUI application written in python that can decrypt and encrypt your texts with OTP (OneTimePad) cipher. 

The One-Time Pad (OTP) cipher is a theoretically unbreakable encryption method. When used correctly, it provides perfect secrecy, meaning that the ciphertext reveals no information about the plaintext without the key. Here’s a detailed look at how the OTP works and how to use it correctly. 

To ensure the security of the OTP, follow these guidelines: 

1. **Key Length**: The key must be at least as long as the plaintext message. If the message is 100 characters long, the key must also be 100 characters long. 

2. **Key Randomness**: The key must be generated using a truly random process. Pseudorandom number generators are not sufficient for OTP keys. Luckily this application uses python secrets module to make secure random passwords. 

3. **Key Uniqueness**: Each key must be used only once. Reusing keys can lead to vulnerabilities and can allow attackers to derive information about the plaintext. 

4. **Key Distribution**: The key must be securely shared between the sender and the receiver before communication. This can be done through secure channels, but it is crucial that the key remains confidential. 

5. **Secure Storage**: Both the sender and receiver must securely store the key. If an attacker gains access to the key, they can decrypt any messages encrypted with it. 

6. **No Patterns**: Avoid any patterns in the plaintext that could be exploited. Since the OTP provides perfect secrecy, any patterns in the plaintext can lead to vulnerabilities if the key is not truly random.
