import os
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Cipher import AES
from lib.crypto_utils import ANSI_X923_pad, ANSI_X923_unpad

# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
# Valuable data to be sent to the botmaster
valuables = []

# Define the length of the signature which is 256
SIGN_LEN = 256


###

def save_valuable(data):
    valuables.append(data)

def encrypt_for_master(data):
    # Encrypt the file so it can only be read by the bot master

        # 1. Generate AES key separately and upload to repo
        # 2. Encrypt the data using AES key
        # 3. Encrypt the AES key using public key
        # 4. Add all together

    # Generate the iv using Crypto Random generator according to AES block size
    # Create symmetric key using Random library
    # Create the cipher
    iv              = Random.get_random_bytes(AES.block_size)
    symmetrickey    = Random.get_random_bytes(AES.block_size)
    cipher          = AES.new(symmetrickey, AES.MODE_CBC, iv)

    # Encrypt the data using the symmetric key
    data_to_encrypt = ANSI_X923_pad(data, cipher.block_size)
    encrypted_data  = cipher.encrypt(data_to_encrypt)

    # Define the public key variable
    publickey = RSA.importKey(open('public.pem').read())

    # Encrypt the AES symmetric key and iv using the public key
    rsa_cipher      = PKCS1_OAEP.new(publickey)
    encrypt_cipher  = rsa_cipher.encrypt(iv + symmetrickey)

    # Adding together the encrypted data and the encrypted AES key
    return encrypt_cipher + encrypted_data

def upload_valuables_to_pastebot(fn):
    # Encrypt the valuables so only the bot master can read them
    valuable_data = "\n".join(valuables)
    valuable_data = bytes(valuable_data, "ascii")
    encrypted_master = encrypt_for_master(valuable_data)

    # "Upload" it to pastebot (i.e. save in pastebot folder)
    f = open(os.path.join("pastebot.net", fn), "wb")
    f.write(encrypted_master)
    f.close()

    print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

###

def verify_file(f):
    # Verify the file was sent by the bot master
    # TODO: For Part 2, you'll use public key crypto here
    # Naive verification by ensuring the first line has the "passkey"

    # Define the signature, where it is no the front of the file
    # Import the public key
    # Create the hash using SHA256
    # Create the verifier using PKCS1_v1_5 verifier
    # Returning the value of the verification result

    signature = f[:SIGN_LEN]
    publickey = RSA.importKey(open('public.pem').read())
    h = SHA256.new(f[SIGN_LEN:])
    verifier = PKCS1_PSS.new(publickey)

    return verifier.verify(h, signature)

def process_file(fn, f):
    if verify_file(f):
        # If it was, store it unmodified
        # (so it can be sent to other bots)
        # Decrypt and run the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
    # "Download" the file from pastebot.net
    # (i.e. pretend we are and grab it from disk)
    # Open the file as bytes and load into memory
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        return
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    process_file(fn, f)

def p2p_download_file(sconn):
    # Download the file from the other bot
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f)

###

def p2p_upload_file(sconn, fn):
    # Grab the file and upload it to the other bot
    # You don't need to encrypt it only files signed
    # by the botnet master should be accepted
    # (and your bot shouldn't be able to sign like that!)
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)
    sconn.send(bytes(fn, 'ascii'))
    sconn.send(bytes(filestore[fn]))

def run_file(f):
    # If the file can be run,
    # run the commands
    pass
