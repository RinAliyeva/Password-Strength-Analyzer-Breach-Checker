import hashlib
import re
import requests
from colorama import Fore, Style, init

init(autoreset=True)


def score_password(password: str) -> tuple[int, list[str]]:
    """
    Scores a password from 0 to 100 based on several criteria.
    Returns (score, list_of_feedback_messages).
    """
    score = 0
    feedback = []

    # Length scoring (up to 30 points)
    length = len(password)
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 10
    else:
        feedback.append("Use at least 8 characters (12+ is ideal).")

    # Character variety (up to 40 points)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*(),.?":{}|<>_\-\[\]\/\\]', password))

    if has_lower:
        score += 10
    else:
        feedback.append("Add lowercase letters.")

    if has_upper:
        score += 10
    else:
        feedback.append("Add uppercase letters.")

    if has_digit:
        score += 10
    else:
        feedback.append("Add numbers.")

    if has_symbol:
        score += 10
    else:
        feedback.append("Add special characters (e.g. !, @, #).")

    # Penalize common patterns (up to -30 points)
    common_patterns = [
        r'(012|123|234|345|456|567|678|789|890)',   # sequential digits
        r'(abc|bcd|cde|def|efg|fgh|ghi)',            # sequential letters
        r'(.)\1{2,}',                                  # repeated chars e.g. "aaa"
        r'(password|qwerty|letmein|welcome|admin|login)',  # common words
    ]
    for pattern in common_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            score -= 15
            feedback.append("Avoid sequential, repeated, or common patterns.")
            break  # only penalize once

    # Bonus: high variety reward (up to 30 points)
    variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
    if variety_count == 4 and length >= 12:
        score += 30
    elif variety_count >= 3 and length >= 10:
        score += 15

    # Clamp to 0–100
    score = max(0, min(100, score))
    return score, feedback


def get_strength_label(score: int) -> tuple[str, str]:
    """Returns a (label, color) tuple based on the score."""
    if score >= 80:
        return "Strong", Fore.GREEN
    elif score >= 50:
        return "Moderate", Fore.YELLOW
    elif score >= 25:
        return "Weak", Fore.RED
    else:
        return "Very Weak", Fore.RED + Style.BRIGHT



def check_breach(password: str) -> int:
    """
    Checks the password against the HaveIBeenPwned database using k-anonymity.
    Only the first 5 characters of the SHA-1 hash are ever sent over the network.
    Returns the number of times the password appeared in known data breaches.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5
        )
        response.raise_for_status()
    except requests.RequestException as e:
        print(Fore.YELLOW + f"[!] Could not reach breach API: {e}")
        return -1  # -1 signals a network error

    # Each line is "HASH_SUFFIX:COUNT"
    for line in response.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return int(count)

    return 0  # Not found in any breach



def draw_bar(score: int) -> str:
    """Draws a simple ASCII progress bar for the score."""
    filled = score // 5       # 20 segments total
    empty = 20 - filled
    return "[" + "█" * filled + "░" * empty + "]"


def analyze(password: str, skip_breach: bool = False):
    print()
    print(Style.BRIGHT + "── Password Analysis ──────────────────────")

    # Score
    score, feedback = score_password(password)
    label, color = get_strength_label(score)

    print(f"  Strength : {color}{label}{Style.RESET_ALL}")
    print(f"  Score    : {color}{score}/100{Style.RESET_ALL}  {draw_bar(score)}")
    print(f"  Length   : {len(password)} characters")

    # Feedback tips
    if feedback:
        print()
        print(Style.BRIGHT + "── Suggestions ─────────────────────────────")
        for tip in feedback:
            print(f"  {Fore.CYAN}→{Style.RESET_ALL} {tip}")

    # Breach check
    if not skip_breach:
        print()
        print(Style.BRIGHT + "── Breach Check (HaveIBeenPwned) ───────────")
        print(f"  {Fore.CYAN}Checking...{Style.RESET_ALL}", end="\r")
        count = check_breach(password)

        if count == -1:
            print(f"  {Fore.YELLOW}⚠  Could not connect to breach database.{Style.RESET_ALL}")
        elif count == 0:
            print(f"  {Fore.GREEN}✓  Not found in any known data breaches.{Style.RESET_ALL}   ")
        else:
            print(f"  {Fore.RED}✗  Found {count:,} times in known breaches! Do not use this password.{Style.RESET_ALL}")

    print()
    print("────────────────────────────────────────────")
    print()


def main():
    print(Style.BRIGHT + "\n  Password Strength Analyzer & Breach Checker")
    print("  " + "─" * 42)

    while True:
        password = input("\n  Enter a password to analyze (or 'q' to quit): ").strip()

        if password.lower() == "q":
            print(Fore.CYAN + "\n  Goodbye!\n")
            break

        if not password:
            print(Fore.YELLOW + "  Please enter a password.")
            continue

        analyze(password)

        print(Fore.CYAN + "  Analyze another password? (press Enter to continue or 'q' to quit)")
        again = input("  → ").strip()
        if again.lower() == "q":
            print(Fore.CYAN + "\n  Goodbye!\n")
            break


if __name__ == "__main__":
    main()
