import re
COMMON_PASSWORDS = [
    "password", "123456", "qwerty", "abc123", "letmein",
    "monkey", "dragon", "master", "welcome", "admin",
    "password123", "iloveyou", "sunshine", "princess", "shadow"
]

def check_password(password):
    score = 0
    feedback = []

    # Check 1: length
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short — use at least 8 characters")

    # Check 2: uppercase letter
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter (A-Z)")

    # Check 3: lowercase letter
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter (a-z)")

    # Check 4: number
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Add at least one number (0-9)")

    # Check 5: symbol
    if re.search(r'[!@#$%^&*]', password):
        score += 1
    else:
        feedback.append("Add a symbol like !@#$%^&*")

    # Check 6: not a common password
    if password.lower() not in COMMON_PASSWORDS:
        score += 1
    else:
        feedback.append("This is a very common password — hackers try these first!")

    # Verdict
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Fair"
    elif score == 5:
        strength = "Good"
    else:
        strength = "Strong"

    return score, strength, feedback


# --- Run the checker ---
print("=" * 40)
print("   PASSWORD STRENGTH CHECKER")
print("=" * 40)

password = input("\nEnter a password to check: ")
score, strength, feedback = check_password(password)

print(f"\nStrength : {strength}")
print(f"Score    : {score}/6")

if feedback:
    print("\nHow to improve it:")
    for tip in feedback:
        print(f"  - {tip}")
else:
    print("\nPerfect! Your password passes all checks.")

print("=" * 40)