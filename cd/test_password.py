import json
from rpp4_scanner import hash_password, verify_password

# 1. सेट अप
password = "MyStrongPassword123"
hashed = hash_password(password)

# 2. डेटा डिक्शनरी (JSON साठी) तयार करा
password_test_result = {
    "module": "RPP.4 Password Security",
    "status": "Success",
    "data": {
        "original_password": password,
        "secure_bcrypt_hash": hashed,
        "tests": {
            "correct_password_verified": verify_password(password, hashed),
            "wrong_password_rejected": not verify_password("WrongPassword", hashed) 
        }
    }
}

# 3. JSON फॉरमॅटमध्ये प्रिंट करा
print(json.dumps(password_test_result, indent=4))