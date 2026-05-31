import base64
import hashlib

from .crypto.base import Cipher


class CryptoLayer:
    """
    Handles:

        M  -> M'
        M' -> M

    Format:

        ALGO:L:KEY_B64:CIPHERTEXT_B64
    """

    HASH_SIZE = 32

    def __init__(self, cipher: Cipher):
        self.cipher = cipher

    @staticmethod
    def _sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def build_secret_for_sharing(
        self,
        message: str
    ) -> str:

        message_bytes = message.encode("utf-8")

        digest = self._sha256(message_bytes)

        plaintext = digest + message_bytes

        key_bytes, encrypted_bytes = self.cipher.encrypt(
            plaintext
        )

        key_b64 = base64.b64encode(
            key_bytes
        ).decode("ascii")

        encrypted_b64 = base64.b64encode(
            encrypted_bytes
        ).decode("ascii")

        length_tag = len(
            key_b64 + encrypted_b64
        )

        secret = (
            f"{self.cipher.name}:"
            f"{length_tag}:"
            f"{key_b64}:"
            f"{encrypted_b64}"
        )

        return secret

    def recover_message_from_secret(
        self,
        secret_str: str
    ) -> str:

        try:
            algo_name, length_str, key_b64, encrypted_b64 = (
                secret_str.split(":", 3)
            )

        except ValueError:
            raise ValueError(
                "Invalid secret format."
            )

        if algo_name != self.cipher.name:
            raise ValueError(
                f"Expected algorithm "
                f"{self.cipher.name}, "
                f"got {algo_name}"
            )

        expected_length = int(length_str)

        if len(key_b64 + encrypted_b64) != expected_length:
            raise ValueError(
                "Length tag mismatch."
            )

        key_bytes = base64.b64decode(
            key_b64
        )

        encrypted_bytes = base64.b64decode(
            encrypted_b64
        )

        plaintext = self.cipher.decrypt(
            key_bytes,
            encrypted_bytes
        )

        if len(plaintext) < self.HASH_SIZE:
            raise ValueError(
                "Plaintext too short."
            )

        stored_hash = plaintext[:self.HASH_SIZE]

        message_bytes = plaintext[self.HASH_SIZE:]

        calculated_hash = self._sha256(
            message_bytes
        )

        if stored_hash != calculated_hash:
            raise ValueError(
                "Hash verification failed."
            )

        return message_bytes.decode(
            "utf-8"
        )
