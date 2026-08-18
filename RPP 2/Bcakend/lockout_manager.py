
# Import datetime to work with dates and times.
from datetime import datetime, timedelta, timezone


# Maximum number of failed login attempts allowed.
# CERT-In RPP.2 requires a temporary lockout after 3 to 5 attempts.
MAX_FAILED_ATTEMPTS = 3


# Account will remain locked for 15 minutes.
LOCKOUT_DURATION = 15


# Dictionary used to store login information.
# Key = user email.
# Value = failed attempts and lockout information.
users = {}


# This function records every login attempt.
def record_login_attempt(email: str, is_successful: bool):

    # Convert email to lowercase.
    # This prevents treating User@gmail.com and user@gmail.com
    # as two different accounts.
    email = email.lower()

    # If the email doesn't exist, create a new record.
    if email not in users:

        users[email] = {
            "failed_attempts": 0,
            "locked_until": None
        }

    # Get the user's security information.
    user = users[email]

    # Get the current UTC time.
    now = datetime.now(timezone.utc)


    # -------------------------------------------------
    # CHECK WHETHER ACCOUNT IS ALREADY LOCKED
    # -------------------------------------------------

    if user["locked_until"] is not None:

        # Check whether the lockout period is still active.
        if now < user["locked_until"]:

            # Account is still locked.
            return {
                "success": False,
                "locked": True,
                "failed_attempts": user["failed_attempts"],
                "message": "Account is temporarily locked."
            }

        # If the lockout time has expired,
        # unlock the account.
        user["locked_until"] = None

        # Reset failed attempts.
        user["failed_attempts"] = 0


    # -------------------------------------------------
    # SUCCESSFUL LOGIN
    # -------------------------------------------------

    if is_successful:

        # Reset failed attempts after successful login.
        user["failed_attempts"] = 0

        # Make sure the account is unlocked.
        user["locked_until"] = None

        # Return successful login response.
        return {
            "success": True,
            "locked": False,
            "failed_attempts": 0,
            "message": "Login successful."
        }


    # -------------------------------------------------
    # FAILED LOGIN
    # -------------------------------------------------

    # Increase the failed login counter.
    user["failed_attempts"] += 1


    # Check whether the maximum failed attempts
    # have been reached.
    if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:

        # Calculate the lockout expiration time.
        user["locked_until"] = (
            now + timedelta(minutes=LOCKOUT_DURATION)
        )

        # Return account-lockout response.
        return {
            "success": False,
            "locked": True,
            "failed_attempts": user["failed_attempts"],
            "locked_until": user["locked_until"].isoformat(),
            "message": "Account locked for 15 minutes."
        }


    # Login failed but account isn't locked yet.
    return {
        "success": False,
        "locked": False,
        "failed_attempts": user["failed_attempts"],
        "message": "Invalid login."
    }