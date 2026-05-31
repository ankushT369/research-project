from abc import ABC, abstractmethod


class Cipher(ABC):

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        pass

    @abstractmethod
    def decrypt(
        self,
        key: bytes,
        ciphertext: bytes
    ) -> bytes:
        pass
