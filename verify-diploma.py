from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import hashlib
import json
import copy


def generate_sha256_hash(diploma_data):
    """Must match sign-diploma.py canonicalization."""
    canonical_json = json.dumps(diploma_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def load_diploma_package(path="diploma_package.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_public_key(university_id):
    key_path = f"identities/{university_id}/public_key.pem"
    with open(key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def verify_diploma(package):
    """
    Read M (diploma_data) + metadata + signature from package, re-hash, verify with public key.
    Returns 'Valid' or 'Invalid'.
    """
    try:
        diploma_data = package["diploma_data"]
        signature_hex = package["signature"]
        signed_by = package["signed_by"]
    except (KeyError, TypeError):
        return "Invalid"

    try:
        public_key = _load_public_key(signed_by)
        if not isinstance(public_key, Ed25519PublicKey):
            return "Invalid"
    except (FileNotFoundError, ValueError, TypeError):
        return "Invalid"

    recomputed_hash = generate_sha256_hash(diploma_data)
    message = recomputed_hash.encode("utf-8")

    try:
        signature_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        return "Invalid"

    try:
        public_key.verify(signature_bytes, message)
    except InvalidSignature:
        return "Invalid"

    return "Valid"


def run_tampering_tests(package_path="diploma_package.json"):
    """Exercise valid package and common tampering scenarios."""
    results = []

    original = load_diploma_package(package_path)
    results.append(("untampered package", verify_diploma(original)))

    tampered_data = copy.deepcopy(original)
    tampered_data["diploma_data"]["diploma"]["student_name"] = "Tampered Name"
    results.append(("tampered diploma fields", verify_diploma(tampered_data)))

    tampered_sig = copy.deepcopy(original)
    tampered_sig["signature"] = "00" * 64
    results.append(("tampered signature", verify_diploma(tampered_sig)))

    wrong_signer = copy.deepcopy(original)
    wrong_signer["signed_by"] = "UNKNOWN_UNI"
    results.append(("unknown signer id", verify_diploma(wrong_signer)))

    return results


if __name__ == "__main__":
    path = "diploma_package.json"
    package = load_diploma_package(path)
    print("--- UniVerify: Diploma Verification ---")
    print(f"Package: {path}")
    print(f"Signed by: {package.get('signed_by', 'N/A')}")
    print(f"Result: {verify_diploma(package)}")

    print("\n--- Tampering tests ---")
    for label, outcome in run_tampering_tests(path):
      print(f"  {label}: {outcome}")
