import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .base import Cipher


class AESGCMCipher(Cipher):

    def __init__(self):
        self.key_size = 32
        self.nonce_size = 12

    @property
    def name(self) -> str:
        return "AESGCM"

    def encrypt(
        self,
        plaintext: bytes
    ) -> tuple[bytes, bytes]:

        key = os.urandom(self.key_size)

        nonce = os.urandom(self.nonce_size)

        aes = AESGCM(key)

        ciphertext = aes.encrypt(
            nonce,
            plaintext,
            None
        )

        return key, nonce + ciphertext

    def decrypt(
        self,
        key: bytes,
        ciphertext_blob: bytes
    ) -> bytes:

        nonce = ciphertext_blob[:self.nonce_size]

        ciphertext = ciphertext_blob[self.nonce_size:]

        aes = AESGCM(key)

        return aes.decrypt(
            nonce,
            ciphertext,
            None
        )
