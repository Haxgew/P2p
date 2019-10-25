import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS


def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!

    # Import the private key from the private.pem generated by OpenSSL
    # Using the passphrase of REIGHT when creating the private key
    # When we need to import, we have to input the passphrase as well
    privatekey = RSA.importKey(open('private.pem').read(),'REIGHT')

    # Hash the file using SHA 256
    # Using the PyCrypto Module PKCS1_PSSfor signatures
    # More robust than PKCS1_v1_5
    h = SHA256.new(f)
    signer = PKCS1_PSS.new(privatekey)
    signature = signer.sign(h)

    # Returning the signature and the file
    return signature + f


if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)