import re
import getpass
import argparse  # Added import
import sys
import time
from datetime import datetime
from colorama import init, Fore, Style
import hashlib
import logging

# Initialize colorama for colored output
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='password_checker.log'
)

class PasswordChecker:
    def __init__(self, password):
        self.password = password
        self.common_passwords = {
            "password", "123456", "qwerty", "admin", "letmein", "welcome",
            "password123", "abc123", "111111", "monkey", "dragon", "baseball"
        }
        self.strength_score = 0
        self.suggestions = []
        self.CRACK_SPEED = 1e10  # 10 billion guesses per second (modern GPU)

    def check_length(self):
        """Check password length."""
        length = len(self.password)
        if length >= 16:
            self.strength_score += 2
        elif length >= 12:
            self.strength_score += 1
        else:
            self.suggestions.append("Use at least 12 characters (16+ for maximum strength)")

    def check_case(self):
        """Check for uppercase and lowercase."""
        if re.search(r'[A-Z].*[A-Z]', self.password):  # At least 2 uppercase
            self.strength_score += 1
        elif re.search(r'[A-Z]', self.password):
            self.strength_score += 0.5
        else:
            self.suggestions.append("Add uppercase letters (2+ recommended)")

        if re.search(r'[a-z].*[a-z]', self.password):  # At least 2 lowercase
            self.strength_score += 1
        elif re.search(r'[a-z]', self.password):
            self.strength_score += 0.5
        else:
            self.suggestions.append("Add lowercase letters (2+ recommended)")

    def check_numbers(self):
        """Check for digits."""
        digits = len(re.findall(r'[0-9]', self.password))
        if digits >= 2:
            self.strength_score += 1
        elif digits == 1:
            self.strength_score += 0.5
        else:
            self.suggestions.append("Include numbers (2+ recommended)")

    def check_special(self):
        """Check for special characters."""
        special = len(re.findall(r'[^A-Za-z0-9]', self.password))
        if special >= 2:
            self.strength_score += 1
        elif special == 1:
            self.strength_score += 0.5
        else:
            self.suggestions.append("Include special characters (2+ recommended)")

    def check_common(self):
        """Check against common passwords."""
        if self.password.lower() not in self.common_passwords:
            self.strength_score += 1
        else:
            self.suggestions.append(f"Avoid common passwords like '{self.password.lower()}'")

    def check_patterns(self):
        """Check for repetitive or sequential patterns."""
        if re.search(r'(.)\1{2,}', self.password):  # Repeated characters (3+)
            self.suggestions.append("Avoid repeating the same character multiple times")
            self.strength_score -= 1
        if re.search(r'(?:012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', self.password.lower()):
            self.suggestions.append("Avoid sequential patterns (e.g., '123' or 'abc')")
            self.strength_score -= 1

    def estimate_crack_time(self):
        """Estimate time to crack the password."""
        charset_size = 0
        if re.search(r'[a-z]', self.password): charset_size += 26
        if re.search(r'[A-Z]', self.password): charset_size += 26
        if re.search(r'[0-9]', self.password): charset_size += 10
        if re.search(r'[^A-Za-z0-9]', self.password): charset_size += 32

        if charset_size == 0:
            return "instantly", 0

        combinations = charset_size ** len(self.password)
        seconds = combinations / self.CRACK_SPEED

        if seconds < 1:
            return "instantly", seconds
        elif seconds < 60:
            return f"{int(seconds)} seconds", seconds
        elif seconds < 3600:
            return f"{int(seconds/60)} minutes", seconds
        elif seconds < 86400:
            return f"{int(seconds/3600)} hours", seconds
        elif seconds < 31536000:
            return f"{int(seconds/86400)} days", seconds
        elif seconds < 31536000 * 100:
            return f"{int(seconds/31536000)} years", seconds
        else:
            return f"{int(seconds/(31536000*100))} centuries", seconds

    def print_progress_bar(self, score, max_score=8):
        """Display a visual strength bar."""
        bar_length = 20
        filled = int(bar_length * score / max_score)
        bar = '█' * filled + '░' * (bar_length - filled)
        color = Fore.RED if score < 3 else (Fore.YELLOW if score < 6 else Fore.GREEN)
        print(f"{color}Strength: [{bar}] {score}/{max_score}{Style.RESET_ALL}")

    def analyze(self):
        """Run all checks and display results."""
        print(f"{Fore.CYAN}Analyzing password...{Style.RESET_ALL}")
        
        # Run checks
        self.check_length()
        self.check_case()
        self.check_numbers()
        self.check_special()
        self.check_common()
        self.check_patterns()

        # Cap strength score
        self.strength_score = max(0, min(self.strength_score, 8))  # 0-8 scale
        
        # Crack time
        crack_time, seconds = self.estimate_crack_time()
        
        # Rating
        ratings = {
            (0, 2): "Very Weak",
            (2, 4): "Weak",
            (4, 5): "Moderate",
            (5, 6): "Strong",
            (6, 7): "Very Strong",
            (7, 9): "Excellent"
        }
        rating = next(v for k, v in ratings.items() if k[0] <= self.strength_score < k[1])

        # Output
        print(f"\n{Fore.YELLOW}Password Analysis Results:{Style.RESET_ALL}")
        self.print_progress_bar(self.strength_score)
        print(f"Rating: {rating}")
        print(f"Estimated time to crack: {crack_time}")
        
        if self.suggestions:
            print(f"\n{Fore.RED}Suggestions to improve:{Style.RESET_ALL}")
            for suggestion in self.suggestions:
                print(f"  - {suggestion}")
        else:
            print(f"{Fore.GREEN}No suggestions - excellent password!{Style.RESET_ALL}")

        # Log results
        logging.info(f"Password strength: {rating}, Score: {self.strength_score}, Crack time: {crack_time}")

def main():
    parser = argparse.ArgumentParser(description="Advanced Password Strength Checker")
    parser.add_argument("--password", help="Password to check (if not provided, will prompt securely)")
    args = parser.parse_args()

    print(f"{Fore.CYAN}Password Strength Checker{Style.RESET_ALL}")
    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Enter password to check: ")

    if not password:
        print(f"{Fore.RED}[ERROR] Password cannot be empty{Style.RESET_ALL}")
        sys.exit(1)

    checker = PasswordChecker(password)
    checker.analyze()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO] Exited by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)