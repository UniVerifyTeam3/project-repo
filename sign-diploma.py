from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import hashlib
import json
from datetime import datetime, timezone

# 1. First Function: Build the certificate data
def build_diploma_data(student_name, degree, grad_date, university_name, uni_id):
    diploma_data = {
        "diploma": {
            "student_name": student_name,
            "degree": degree,
            "graduation_date": grad_date,
            "University_name": university_name,
        },
        "metadata": {
            "university_id": uni_id,
            "system_version": "1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }
    return diploma_data

# 2. Second Function: Generate the security hash
def generate_sha256_hash(diploma_data):
    canonical_json = json.dumps(diploma_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

# 3. Third Function : Sign and export the final diploma package
def sign_diploma(diploma_data, final_hash, university_id):
    
   
    key_path = f"identities/{university_id}/private_key.pem"
    
    
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None
        )
    
    
    signature = private_key.sign(final_hash.encode("utf-8"))
    
    
    diploma_package = {
        "diploma_data": diploma_data,
        "signature": signature.hex(),
        "signed_by": university_id
    }
    
    
    with open("diploma_package.json", "w") as f:
        json.dump(diploma_package, f, indent=2)
    
    print("Diploma Signed Successfully")
    return diploma_package


# --- Main Execution ---
if __name__ == "__main__":
    universities = {
        "1": {"name": "Umm Al-Qura University", "id": "UQU"},
        "2": {"name": "Massachusetts Institute of Technology", "id": "MIT"},
        "3": {"name": "King Abdulaziz University", "id": "KAU"}
    }
    
    print("--- UniVerify: Digital Diploma System ---")
    print("Select University:")
    for key, val in universities.items():
        print(f"{key}. {val['name']}")

    choice = input("Enter number (1-3): ")
    selected_uni = universities.get(choice)
    
    if selected_uni:
        university_name = selected_uni["name"]
        uni_id = selected_uni["id"]

        name = input("Student Name: ")
        major = input("Major: ")
        date = input("Grad Date (YYYY-MM): ")
        
        # Step 1: Prepare the data
        final_diploma_data = build_diploma_data(name, major, date, university_name, uni_id)
        print(f"\n diploma structured successfully..")
        # Step 2: Generate hash
        final_hash = generate_sha256_hash(final_diploma_data)

       
       # print(f"\n Digital Fingerprint (Hash): {final_hash}")
        print(f"\n signing diploma...")
        #  Step 3: Sign the diploma 
        diploma_package = sign_diploma(final_diploma_data, final_hash, uni_id)

    else:
        print("Invalid selection! try again.")