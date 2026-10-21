import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class KeyManager:
    """Manages Ed25519 keys for signing and verification."""

    def __init__(self, key_dir: str = "data/keys"):
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.priv_path = self.key_dir / "ledger_ed25519"
        self.pub_path = self.key_dir / "ledger_ed25519.pub"
        self._private_key = None
        self._public_key = None
        self.load_or_generate()

    def load_or_generate(self):
        if self.priv_path.exists() and self.pub_path.exists():
            with open(self.priv_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.pub_path, "rb") as f:
                self._public_key = serialization.load_pem_public_key(f.read())
        else:
            self._private_key = ed25519.Ed25519PrivateKey.generate()
            self._public_key = self._private_key.public_key()

            # Save private key
            priv_pem = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(self.priv_path, "wb") as f:
                f.write(priv_pem)

            # Save public key
            pub_pem = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            with open(self.pub_path, "wb") as f:
                f.write(pub_pem)

    @property
    def public_key_hex(self) -> str:
        raw_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw_bytes.hex()

    def sign(self, message: bytes) -> str:
        """Sign message and return hex-encoded signature."""
        sig = self._private_key.sign(message)
        return sig.hex()

    @staticmethod
    def verify(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
        """Verify hex-encoded signature using hex-encoded public key."""
        try:
            pub_bytes = bytes.fromhex(public_key_hex)
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            sig_bytes = bytes.fromhex(signature_hex)
            pub_key.verify(sig_bytes, message)
            return True
        except Exception:
            return False
