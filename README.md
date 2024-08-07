# NSE Encryption Tool

This Python application allows users to encrypt and decrypt text using the Fernet symmetric encryption algorithm. The program features:

Encryption: Users can input a message and a key, which the program uses to encrypt the message. The encrypted message, along with the key and timestamp, is saved to a temporary directory as a .pkl file.

History: Users can view previously encrypted messages stored in the temporary directory. The program reads and displays the contents of these files, showing the encrypted message, key, and timestamp.

The application uses a Tkinter-based GUI with a dark theme, providing a user-friendly interface for performing encryption and viewing encrypted messages.

# NSE Decryption Tool

This Python application allows users to decrypt encrypted text using the Fernet symmetric encryption algorithm. The program features:

Decryption: Users can input an encrypted message and a key, which the program uses to decrypt the message. The decrypted message, along with the key and timestamp, is saved to a temporary directory as a .pkl file. The decrypted message is also displayed on the interface.

History: Users can view the history of previously decrypted messages stored in the temporary directory. The program reads and displays the contents of these files, showing the decrypted message, key, and timestamp.

The application uses a Tkinter-based GUI with a dark theme, providing a user-friendly interface for performing decryption and viewing the history of decrypted messages.

