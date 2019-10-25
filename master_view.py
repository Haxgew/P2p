import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from lib.crypto_utils import ANSI_X923_pad, ANSI_X923_unpad

def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    
      # Import the private key and create the decrypt cipher
      # Decrypt cipher using the same PKCS1 OAEP
      privatekey = RSA.importKey(open('private.pem').read(),'REIGHT')
      rsa_cipher = PKCS1_OAEP.new(privatekey)
      
      # Find the length of the cipher info
      # Convert them to bytes by dividing by 8 (from bits)
      # Find out the length of the cipher info and convert it to integer
      info_len = int((privatekey.size() + 1)/8)
      
      # Separate the encrypted cipher info and the encrypted data
      encrypt_cipher_info = f[:info_len]
      encrypted_data   = f[info_len:]
      
      # Decrypt the encrypted AES info
      # AES info contains the iv and the symmetric key
      info    = rsa_cipher.decrypt(encrypt_cipher_info)
      iv      = info[:AES.block_size]
      symmkey = info[AES.block_size:(AES.block_size*2)]
      
      # Decrypt the message using the obtained iv and AES symmetric key
      cipher  = AES.new(symmkey, AES.MODE_CBC, iv)
      message = cipher.decrypt(encrypted_data)
      message = ANSI_X923_unpad(message, cipher.block_size)
      
      print(message)

if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
