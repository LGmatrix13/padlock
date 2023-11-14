from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

import secrets # Use this for generating random byte strings (keys, etc.)
from time import perf_counter
from inspect import cleandoc # Cleans up indenting in multi-line strings (""")
from os import urandom

#
# Returns: An rsa.RSAPrivateKey object (which contains both the private key
#   and its corresponding public key; use .public_key() to obtain it).
#
RSA_KEY_BITS = 4096
RSA_PUBLIC_EXPONENT = 65537
def rsa_gen_keypair():
    return rsa.generate_private_key(
            key_size = RSA_KEY_BITS,
            public_exponent = RSA_PUBLIC_EXPONENT
            )

#
# Argument: An rsa.RSAPrivateKey object
#
# Returns: An ASCII/UTF-8 string serialization of the private key using the
#   PKCS-8 format and PEM encoding. Does not encrypt the key for at-rest
#   storage.
#
def rsa_serialize_private_key(private_key: rsa.RSAPrivateKey):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

#
# Argument: A string containing an unencrypted RSA private key in PEM format.
#   Note that this also includes the matching public key (i.e., a PEM
#   "private key" serialization includes both halves of the keypair).
#
# Returns: An rsa.RSAPrivateKey object consisting of the deserialized key.
#
def rsa_deserialize_private_key(pem_privkey) -> rsa.RSAPrivateKey:
    return load_pem_private_key(pem_privkey.encode("utf-8"), None)



#
# Argument: An rsa.RSAPublicKey object
#
# Returns: An ASCII/UTF-8 serialization of the public key using the
#   SubjectPublicKeyInfo format and PEM encoding.
#
def rsa_serialize_public_key(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo 
    ).decode('utf-8')

#
# Argument: A string containing an RSA public key in PEM format.
#
# Returns: An rsa.RSAPublicKey object consisting of the deserialized key.
#
def rsa_deserialize_public_key(pem_pubkey: str) -> rsa.RSAPublicKey:
    return load_pem_public_key(pem_pubkey.encode("utf-8"), None)

#
# Arguments:
#   public_key: An rsa.RSAPublicKey object containing the public key of the
#       message recipient.
#   plaintext: The plaintext message to be encrypted (as a raw byte string).
#
# Returns: The encrypted message (ciphertext), as a raw byte string.
#
def rsa_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

#
# Arguments:
#   private_key: An rsa.RSAPrivateKey object containing the private key of the
#       message recipient.
#   plaintext: The ciphertext message to be decrypted (as a raw byte string).
#
# Returns: The decrypted message (plaintext), as a raw byte string.
#
def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: str) -> str:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

#
# Encrypts a plaintext message using AES-256 in CTR (Counter) mode.
#
# Arguments:
#   key: A 256-bit (32-byte) secret key. This should either be randomly
#       generated, or derived from a password using a secure key derivation
#       function.
#   nonce: A 128-bit (16-byte) nonce to use with CTR mode. It is imperative
#       that this be randomly generated, and NEVER reused after being used
#       once to encrypt a single message. (This is because each time you
#       encrypt a message with the same nonce in CTR mode, the counter starts
#       fresh from 0 again, meaning the initial blocks will have been XORed
#       with the same keystream as the previous message - allowing the key to
#       be trivially recovered by comparing the two.)
#           (N.B.: Even though we are using AES-256, i.e. a key size of 256
#           bits, the nonce is still 128 bits, because the block size of AES
#           is always 128 bits. A longer key just increases the number of
#           rounds performed.)
#   plaintext: The plaintext message to be encrypted (as a raw byte string).
#
# Returns: The encrypted message (ciphertext), as a raw byte string.
#
def aes_encrypt(key, nonce, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext
    
#
# Decrypts a plaintext message using AES-256 in CTR (Counter) mode.
#
# Arguments:
#   key: A 256-bit (32-byte) secret key.
#   nonce: A 128-bit (16-byte) nonce to use with CTR mode.
#   ciphertext: The ciphertext message to be decrypted (as a raw byte string).
#
# No restrictions are placed on the values of key and nonce, but obviously,
# if they don't match the ones used to encrypt the message, the result will
# be gibberish.
#
# Returns: The decrypted message (plaintext), as a raw byte string.
#
def aes_decrypt(key, nonce, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

#
# Encrypts a plaintext message using AES-256-CTR using a randomly generated
# session key and nonce.
#
# Argument: The plaintext message to be encrypted (as a raw byte string).
#
# Returns: A tuple containing the following elements:
#   session_key: The randomly-generated 256-bit session key used to encrypt
#       the message (as a raw byte string).
#   nonce: The randomly-generated 128-bit nonce used in the encryption (as a
#       raw byte string).
#   ciphertext: The encrypted message (as a raw byte string).
#
def aes_encrypt_with_random_session_key(plaintext: bytes) -> tuple[bytes,bytes,bytes]:
    random_key = urandom(32)
    random_nonce = urandom(16)
    return random_key, random_nonce, aes_encrypt(key=random_key, nonce=random_nonce, plaintext=plaintext)



#
# Encrypt a message using AES-256-CTR and a random session key, which in turn
# is encrypted with RSA so that it can be decrypted by the given public key.
#
# Arguments:
#   public_key: An rsa.RSAPublicKey object containing the public key of the
#       message recipient.
#   plaintext: The plaintext message to be encrypted (as a raw byte string).
#
# Returns: A tuple containing the following elements:
#   encrypted_session_key: The randomly-generated AES session key, encrypted
#       using RSA with the given public key (as a raw byte string).
#   nonce: The randomly-generated nonce used in the AES-CTR encrpytion (as a
#       raw byte string).
#   ciphertext: The AES-256-CTR-encrypted message (as a raw byte string).
#
def encrypt_message_with_aes_and_rsa(public_key: rsa.RSAPublicKey, plaintext: bytes) -> tuple[bytes,bytes,bytes]:
    session_key, nounce, ciphertext = aes_encrypt_with_random_session_key(plaintext)
    session_key = rsa_encrypt(public_key=public_key, plaintext=session_key)
    return session_key, nounce, ciphertext

#
# Decrypt a message that has been encrypted with AES-256-CTR, using an
# RSA-encrypted session key and an unencrypted nonce.
#
# Arguments:
#   private_key: An rsa.RSAPrivateKey object containing the private key that
#       will be used to decrypt the session key.
#   encrypted_session_key: The RSA-encrypted session key that will be used to
#       decrypt the actual message with AES-256-CTR (as a raw byte string).
#   nonce: The nonce that will be used to decrypt the message with
#       AES-256-CTR (as a raw byte string).
#   ciphertext: The AES-256-CTR-encrypted message (as a raw byte string).
#
# Returns: The decrypted message (plaintext), as a raw byte string.
#
def decrypt_message_with_aes_and_rsa(private_key: rsa.RSAPrivateKey, encrypted_session_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    decrypted_session_key = rsa_decrypt(private_key, encrypted_session_key)
    return aes_decrypt(key=decrypted_session_key, nonce=nonce, ciphertext=ciphertext)

#
# Benchmark the following operations:
#
#   1. Generate a 4096-bit RSA keypair
#
#   2. Generate an AES-256 session key
#
#   3. Encrypt 446 bytes (3568 bits) of data using RSA-4096
#           Why 446 bytes? This is a limitation of the way we are using the
#           RSA algorithm here: it cannot encrypt more than a single block
#           (4096 bits) of data at a time. AES has the same limitation, which
#           we deal with by using a block cipher mode to turn it into a
#           stream cipher. But the RSA implementation in OpenSSL (which is
#           used behind the scenes by the cryptography library) only supports
#           encrypting a single block at a time. Generally, this isn't a
#           problem in real-world scenarios, since we're only interested in
#           encrpyting a (much shorter) AES session key or a hash signature.
#           
#           Note also: we are further limited to 446 bytes (instead of 512
#           bytes, which would be the full 4096 bits) because of the OAEP
#           padding scheme we are using with RSA. OAEP has overhead of
#           2*<hash function length> + 2 bytes; since we are using SHA-256
#           for our hash function, this overhead is 2*32 + 2 = 66 bytes,
#           leaving 512 - 66 = 446 bytes free for our message.
#
#           AES-CTR, of course, has no problem encrypting an arbitrarily long
#           message, so for an apples-to-apples comparison we use the same
#           length message in our AES benchmark (below).
#
#   4. Encrypt 446 bytes (3568 bits) of data using AES-256-CTR
#
# Each operation will be run NUM_BENCHMARK_RUNS times, with the average
# reported.
#
# Returns: A multi-line string summarizing the results of the benchmarks (in
# a human-readable format for display to the user).
#
def benchmark():
    NUM_BENCHMARK_RUNS = 20
    TEST_DATA_SIZE = 446

    elapsed_begin = perf_counter()

    # Benchmark #1: generating a 4096-bit RSA keypair
    #
    # N.B.: We save a copy of the key generated in the last run so we can use
    # it for benchmark #3.
    rsa_keygen_results = []
    for i in range(0, NUM_BENCHMARK_RUNS):
        before = perf_counter()
        rsa_private_key = rsa_gen_keypair()
        after = perf_counter()

        rsa_keygen_results.append(after - before)

    rsa_keygen_avg = sum(rsa_keygen_results) / len(rsa_keygen_results)

    # Benchmark #2: generating a 256-bit AES session key
    #
    # N.B.: We save a copy of the key generated in the last run so we can use
    # it for benchmark #4.
    aes_keygen_results = []
    for i in range(0, NUM_BENCHMARK_RUNS):
        before = perf_counter()
        aes_session_key = secrets.token_bytes(32) # 32 bytes = 256 bits
        after = perf_counter()

        aes_keygen_results.append(after - before)

    aes_keygen_avg = sum(aes_keygen_results) / len(aes_keygen_results)

    # Generate TEST_DATA_SIZE bytes of random data to use as our plaintext
    # for the encryption benchmarks.
    plaintext = secrets.token_bytes(TEST_DATA_SIZE)

    # Benchmark #3: encrypting data using RSA
    rsa_encrypt_results = []
    rsa_public_key = rsa_private_key.public_key()
    for i in range(0, NUM_BENCHMARK_RUNS):
        before = perf_counter()
        rsa_encrypt(rsa_public_key, plaintext)
        after = perf_counter()

        rsa_encrypt_results.append(after - before)

    rsa_encrypt_avg = sum(rsa_encrypt_results) / len(rsa_encrypt_results)

    # Generate a random 128-bit (16-byte) nonce for use in our AES encryption
    # benchmark.
    nonce = secrets.token_bytes(16)

    # Benchmark #4: encrypting data using AES-256-CTR
    aes_encrypt_results = []
    for i in range(0, NUM_BENCHMARK_RUNS):
        before = perf_counter()
        aes_encrypt(aes_session_key, nonce, plaintext)
        after = perf_counter()

        aes_encrypt_results.append(after - before)

    aes_encrypt_avg = sum(aes_encrypt_results) / len(aes_encrypt_results)

    elapsed_end = perf_counter()

    # Output a human-readable report of the results (printing the floats to 6
    # significant digits).
    return cleandoc("""
    Benchmark results (average of {num_runs} runs each):

    #1 (Generate a 4096-bit RSA keypair):             {result1:.6g} seconds
    #2 (Generate a 256-bit AES session key):          {result2:.6g} seconds
    #3 (Encrypt {data_size} bytes of data using RSA-4096):    {result3:.6g} seconds
    #4 (Encrypt {data_size} bytes of data using AES-256-CTR): {result4:.6g} seconds

    Total elapsed time: {elapsed:.6g} seconds
    """).format(num_runs = NUM_BENCHMARK_RUNS, data_size = TEST_DATA_SIZE,
                result1 = rsa_keygen_avg, result2 = aes_keygen_avg,
                result3 = rsa_encrypt_avg, result4 = aes_encrypt_avg,
                elapsed = elapsed_end - elapsed_begin)
