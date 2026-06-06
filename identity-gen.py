from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import os
import json

def generate_identity(university_name):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    folder = f"identities/{university_name}"
    os.makedirs(folder, exist_ok=True)

    with open(f"{folder}/private_key.pem", "wb") as f:
        f.write(private_bytes)

    with open(f"{folder}/public_key.pem", "wb") as f:
        f.write(public_bytes)

    info = {
        "university": university_name,
        "algorithm": "Ed25519"
    }
    with open(f"{folder}/info.json", "w") as f:
        json.dump(info, f, indent=2)

    print(f"✅ تم إنشاء هوية جامعة: {university_name}")

if __name__ == "__main__":
    generate_identity("UQU")
    generate_identity("KAU")
    generate_identity("MIT")
    generate_identity("Nora")
    