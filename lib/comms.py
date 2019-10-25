import struct

from Crypto import Random
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from lib.helpers import read_hex
from lib.crypto_utils import ANSI_X923_pad, ANSI_X923_unpad

from dh import create_dh_key, calculate_dh_secret


# Using SHA256 means there are 64 bytes on each HMAC
HMAC_LEN = 64
# Define the counter length of 8
# 8 is used as a random value of counter instead of using 0
CTR_LEN  = 8

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.shared_hash = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.SH = None
        self.hmac_secret = None
        self.initiate_session()

        # Edit the number below to change the initial session ID
        self.session_counter = 8

    def __print_verbose__(self, string):
        if self.verbose:
            print(string)

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret 

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the clientasdsad
        if self.server or self.client:
            # Calculate Diffie-Hellman key pair
            my_public_key, my_private_key = create_dh_key()

            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))

            # Receive their public key
            their_public_key = int(self.recv())

            # Obtain our shared secret
            self.shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(self.shared_hash))
            self.shared_hash = bytes(self.shared_hash, "ascii")

        # Used AES instead of XOR for stronger encryption.
        iv = Random.new().read(AES.block_size)

        # Define the shared_hash and the cipher
        # Shared hash to be used as the key is declared as self.SH to make it reusable in other cipher
        # Used AES Mode of CBC
        self.SH                = self.shared_hash[:16]
        self.cipher            = AES.new(self.SH, AES.MODE_CBC, iv)

        # Create hmac_secret for HMAC
        # HMAC secret is taken from the shared key so the secret key is stronger
        self.hmac_secret       = self.shared_hash[17:]

    def send(self, data):
        if self.cipher:
            # Generate IV and Create the Cipher
            iv          = Random.new().read(AES.block_size)
            self.cipher = AES.new(self.SH, AES.MODE_CBC, iv)

            # Create HMAC for integrity check, with the secret
            hmac = HMAC.new(self.hmac_secret, digestmod=SHA256)
            hmac.update(bytes(str(self.session_counter), "ascii"))
            hmac.update(data)

            # Convert mac and counter to bytes
            # Pad the counter to the 8 byte length (counter length)
            hmac      = bytes(str(hmac.hexdigest()), "ascii")
            ctr       = bytes(str(self.session_counter), "ascii")
            ctr       = ANSI_X923_pad(ctr, CTR_LEN)

            # Add the counter, hmac, and original data together
            data_hmac = ctr + hmac + data
            
            # Add the iv to the data and pad the data to meet the required length of the AES
            # block size which is 128 bit
            encrypted_data = iv + self.cipher.encrypt(ANSI_X923_pad(data_hmac, AES.block_size))

            # Increment the counter
            self.session_counter += 1

            self.__print_verbose__("Original data: {}".format(data))
            self.__print_verbose__("Encrypted data: {}".format(repr(encrypted_data)))
            self.__print_verbose__("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed      = self.conn.recv(struct.calcsize('H'))
        unpacked_contents   = struct.unpack('H', pkt_len_packed)
        pkt_len             = unpacked_contents[0]
        packet              = self.conn.recv(pkt_len)

        if self.cipher:
            # Separate between the iv and the data
            # iv is on the front of the packet 
            # encrypted data is on the back of the package
            iv              = packet[:AES.block_size]
            encrypted_data  = packet[AES.block_size:]

            # Create the cipher using the same CBC mode
            self.cipher = AES.new(self.SH, AES.MODE_CBC, iv)
 
            # Decrypt the data and unpad the data
            data = self.cipher.decrypt(encrypted_data)
            data = ANSI_X923_unpad(data, AES.block_size)

            # Separate the data into HMAC, counter and the plaintext
            recv_ctr    = ANSI_X923_unpad(data[:CTR_LEN], CTR_LEN)
            recv_hmac   = data[CTR_LEN:(CTR_LEN + HMAC_LEN)]
            text        = data[(CTR_LEN + HMAC_LEN):]

            # Calculate HMAC to check the message integrity
            calc_hmac = HMAC.new(self.hmac_secret, digestmod=SHA256)
            calc_hmac.update(recv_ctr)
            calc_hmac.update(text)

            # Convert to byte to compare the data
            calc_hmac = bytes(str(calc_hmac.hexdigest()), "ascii")
            this_ctr = bytes(str(self.session_counter), "ascii")

            # Replay Attack Prevention
            # If the receiving counter is equal to the message counter, the message is valid
            if recv_ctr == this_ctr:
                # Check if the receiver HMAC is equal to the message HMAC
                if calc_hmac == recv_hmac:
                    data = text
                    self.__print_verbose__("Receiving packet of length {}".format(pkt_len))
                    self.__print_verbose__("Encrypted data: {}".format(repr(encrypted_data)))
                    self.__print_verbose__("Original data: {}".format(data))

                    # Increment the session counter after one message is done
                    self.session_counter += 1
                else:
                    # If the HMAC doesn't match, someone has altered the message
                    # And it will print Integrity Check Failed
                    data = None
                    self.__print_verbose__("*** Integrity Check Failed! Message has been altered! ***")
            else:
                # If the counter doesn't match, someone has replayed the message
                # It will print the warning
                data = None
                self.__print_verbose__("*** Replay Attack is detected! ***")
            
        else:
            data = packet

        return data

    def close(self):
        self.conn.close()
