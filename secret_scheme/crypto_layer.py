import os
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoLayer:
    """
    Handles:
        M  -> M' (enveloped secret for sharing)
        M' -> M  (verification + decryption)
    """

    def __init__(self, key_size: int = 32, nonce_size: int = 12):
        self.key_size = key_size      # 32 bytes -> AES-256
        self.nonce_size = nonce_size  # 12 bytes for AES-GCM

    @staticmethod
    def _sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def _generate_key(self) -> bytes:
        return os.urandom(self.key_size)

    def _generate_nonce(self) -> bytes:
        return os.urandom(self.nonce_size)

    def build_secret_for_sharing(self, message: str) -> str:
        """
        M -> M' (ASCII): "L:K_b64:E_b64"
        """
        m_bytes = message.encode("utf-8")
        h_bytes = self._sha256(m_bytes)

        k_bytes = self._generate_key()
        aesgcm = AESGCM(k_bytes)
        nonce = self._generate_nonce()

        plaintext = h_bytes + m_bytes

        ct = aesgcm.encrypt(nonce, plaintext, None)
        e_bytes = nonce + ct

        k_b64 = base64.b64encode(k_bytes).decode("ascii")
        e_b64 = base64.b64encode(e_bytes).decode("ascii")

        L = len(k_b64 + e_b64)
        M_prime = f"{L}:{k_b64}:{e_b64}"
        return M_prime

    def recover_message_from_secret(self, secret_str: str) -> str:
        """
        M' -> M (verify hash, decrypt).
        """
        try:
            L_str, k_b64, e_b64 = secret_str.split(":", 2)
        except ValueError:
            raise ValueError("Invalid secret format (expected 'L:K_b64:E_b64').")

        L = int(L_str)
        if len(k_b64 + e_b64) != L:
            raise ValueError("Length tag L does not match K_b64+E_b64 length.")

        k_bytes = base64.b64decode(k_b64)
        e_bytes = base64.b64decode(e_b64)

        if len(e_bytes) < self.nonce_size:
            raise ValueError("Invalid E: too short to contain nonce.")

        nonce = e_bytes[:self.nonce_size]
        ct = e_bytes[self.nonce_size:]

        aesgcm = AESGCM(k_bytes)
        plaintext = aesgcm.decrypt(nonce, ct, None)

        if len(plaintext) < 32:
            raise ValueError("Invalid plaintext: too short for SHA-256 hash.")

        h_stored = plaintext[:32]
        m_bytes = plaintext[32:]

        h_calc = self._sha256(m_bytes)
        if h_calc != h_stored:
            raise ValueError("Hash mismatch: data corrupted or tampered.")

        return m_bytes.decode("utf-8")
