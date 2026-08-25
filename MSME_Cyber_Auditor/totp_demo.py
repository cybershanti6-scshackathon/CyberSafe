import pyotp


secret = pyotp.random_base32()

print("Secret Key:")
print(secret)


totp = pyotp.TOTP(secret)

print("\nCurrent OTP:")
print(totp.now())


user_otp = input("\nEnter OTP: ")


if totp.verify(user_otp):
    print("MFA Verification Successful!")
else:
    print("Invalid OTP!")