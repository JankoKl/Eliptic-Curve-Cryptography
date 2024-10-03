# Eliptic Curve Cryptography
This is a simple Elliptic Curve Cryptography (ECC) demo application built using Tkinter for the graphical user interface and cryptography library for ECC operations. It allows users to generate keys, sign messages, and verify digital signatures, simulating secure communication between two users.

# Features

# Generate ECC Keys: Generate a private and public key pair using the SECP256K1 elliptic curve.
# Message Signing: Sign a message using the generated private key and produce a digital signature.
# Send Message: Simulate sending a signed message in a conversation interface.
# Verify Public Key: Verify the format and correctness of a public key.
# Verify Signature: Verify the authenticity of the message using the public key and digital signature.

# How It Works

1. Key Generation
Clicking "Generiši ključeve" generates an ECC private key and public key.
The keys are displayed in PEM format.
2. Signing a Message
Enter a message in the provided text field and click "Potpiši poruku".
The message is hashed using SHA-256 and signed using the private key to produce a digital signature.
The signature is displayed in hexadecimal format.
3. Sending a Message
After signing, the message and signature can be "sent" using the "Pošalji tekstualnu poruku" and "Pošalji potpis poruke" buttons, which display the message and the conversation in the text field.
4. Verifying the Public Key
The recipient (Marko) can input their public key in the provided field.
Click "Verifikuj javni ključ" to check if the key is correctly formatted and valid.
5. Verifying the Signature
After sending the message and public key, click "Verifikuj potpis" to ensure that the message and signature match.
The app will indicate whether the verification succeeded or failed.

# Use requirements.txt to install required libraries:
 pip install -r requirements.txt 
