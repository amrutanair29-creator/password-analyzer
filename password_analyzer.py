"""
Password Strength Analyzer and Custom Wordlist Generator
A cybersecurity project for educational and awareness purposes
Author: Security Intern
"""

import re
import itertools
from datetime import datetime

# Since zxcvbn requires installation, we'll create a comprehensive manual analyzer
class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123', 
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'passw0rd', 'shadow', '123123', '654321'
        ]
        self.common_patterns = [
            r'(.)\1{2,}',  # Repeated characters
            r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
            r'^[a-z]+$',  # Only lowercase
            r'^[A-Z]+$',  # Only uppercase
            r'^\d+$',     # Only numbers
        ]
    
    def analyze_password(self, password):
        """Analyze password strength and return detailed feedback"""
        score = 0
        feedback = []
        strength = ""
        
        # Length check
        length = len(password)
        if length < 6:
            feedback.append("❌ Password is too short (minimum 8 characters recommended)")
        elif length < 8:
            feedback.append("⚠️ Password length is acceptable but could be longer")
            score += 1
        elif length < 12:
            feedback.append("✓ Good password length")
            score += 2
        else:
            feedback.append("✓ Excellent password length")
            score += 3
        
        # Character variety check
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password))
        
        char_types = sum([has_lower, has_upper, has_digit, has_special])
        
        if char_types == 1:
            feedback.append("❌ Uses only one character type (very weak)")
        elif char_types == 2:
            feedback.append("⚠️ Uses two character types (add more variety)")
            score += 1
        elif char_types == 3:
            feedback.append("✓ Uses three character types (good)")
            score += 2
        else:
            feedback.append("✓ Uses all character types (excellent)")
            score += 3
        
        # Common password check
        if password.lower() in self.common_passwords:
            feedback.append("❌ This is a commonly used password")
            score -= 2
        
        # Pattern detection
        for pattern in self.common_patterns:
            if re.search(pattern, password.lower()):
                feedback.append("⚠️ Contains predictable patterns or sequences")
                score -= 1
                break
        
        # Dictionary word check (simple)
        if len(password) >= 4 and password.lower().isalpha():
            feedback.append("⚠️ Appears to be a dictionary word")
            score -= 1
        
        # Final score calculation
        if score <= 1:
            strength = "WEAK"
        elif score <= 3:
            strength = "MEDIUM"
        else:
            strength = "STRONG"
        
        return {
            'strength': strength,
            'score': max(0, score),
            'feedback': feedback,
            'length': length,
            'has_lower': has_lower,
            'has_upper': has_upper,
            'has_digit': has_digit,
            'has_special': has_special
        }
    
    def display_analysis(self, password, analysis):
        """Display password analysis in a formatted way"""
        print("\n" + "="*60)
        print("PASSWORD STRENGTH ANALYSIS")
        print("="*60)
        print(f"Password: {'*' * len(password)}")
        print(f"Length: {analysis['length']} characters")
        print(f"\nStrength Level: {analysis['strength']}")
        print(f"Security Score: {analysis['score']}/6")
        print("\nCharacter Composition:")
        print(f"  Lowercase letters: {'Yes ✓' if analysis['has_lower'] else 'No ✗'}")
        print(f"  Uppercase letters: {'Yes ✓' if analysis['has_upper'] else 'No ✗'}")
        print(f"  Numbers: {'Yes ✓' if analysis['has_digit'] else 'No ✗'}")
        print(f"  Special characters: {'Yes ✓' if analysis['has_special'] else 'No ✗'}")
        print("\nDetailed Feedback:")
        for item in analysis['feedback']:
            print(f"  {item}")
        print("="*60 + "\n")


class WordlistGenerator:
    def __init__(self):
        self.wordlist = set()
    
    def generate_from_inputs(self, name="", birthdate="", keywords=None, 
                            include_common=True, max_combinations=1000):
        """Generate custom wordlist based on user inputs"""
        if keywords is None:
            keywords = []
        
        base_words = []
        
        # Add name variations
        if name:
            base_words.append(name.lower())
            base_words.append(name.capitalize())
            base_words.append(name.upper())
        
        # Add birthdate variations
        if birthdate:
            # Assuming format: YYYY-MM-DD or YYYY
            base_words.append(birthdate.replace("-", ""))
            if len(birthdate) >= 4:
                base_words.append(birthdate[:4])  # Year
        
        # Add custom keywords
        for keyword in keywords:
            base_words.append(keyword.lower())
            base_words.append(keyword.capitalize())
        
        # Common suffixes and prefixes
        common_additions = ['123', '!', '@', '2024', '2025', '1', '12', '123!']
        
        # Add common passwords if requested
        if include_common:
            common = ['password', 'admin', 'user', 'welcome', 'login']
            base_words.extend(common)
        
        # Generate combinations
        self.wordlist.update(base_words)
        
        # Add variations with numbers and special chars
        count = 0
        for word in base_words[:10]:  # Limit base words to prevent explosion
            for addition in common_additions:
                if count >= max_combinations:
                    break
                self.wordlist.add(word + addition)
                self.wordlist.add(addition + word)
                count += 1
        
        # Add leet speak variations
        for word in list(base_words)[:5]:
            leet = self.to_leet_speak(word)
            self.wordlist.add(leet)
        
        return sorted(list(self.wordlist))
    
    def to_leet_speak(self, word):
        """Convert word to leet speak"""
        leet_map = {
            'a': '4', 'e': '3', 'i': '1', 'o': '0', 
            's': '5', 't': '7', 'l': '1', 'g': '9'
        }
        return ''.join(leet_map.get(c.lower(), c) for c in word)
    
    def save_wordlist(self, filename="custom_wordlist.txt"):
        """Save wordlist to file"""
        try:
            with open(filename, 'w') as f:
                for word in sorted(self.wordlist):
                    f.write(word + '\n')
            print(f"✓ Wordlist saved to {filename}")
            print(f"✓ Total passwords generated: {len(self.wordlist)}")
            return True
        except Exception as e:
            print(f"✗ Error saving wordlist: {e}")
            return False
    
    def display_sample(self, count=20):
        """Display sample of generated wordlist"""
        print("\n" + "="*60)
        print("GENERATED WORDLIST SAMPLE")
        print("="*60)
        sample = list(self.wordlist)[:count]
        for idx, word in enumerate(sample, 1):
            print(f"{idx:3d}. {word}")
        if len(self.wordlist) > count:
            print(f"... and {len(self.wordlist) - count} more passwords")
        print("="*60 + "\n")


def print_banner():
    """Display project banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║   PASSWORD STRENGTH ANALYZER & WORDLIST GENERATOR        ║
    ║   Cybersecurity Awareness Tool                           ║
    ║   For Educational Purposes Only                          ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)


def main_menu():
    """Display main menu and handle user choices"""
    analyzer = PasswordAnalyzer()
    generator = WordlistGenerator()
    
    while True:
        print("\n" + "="*60)
        print("MAIN MENU")
        print("="*60)
        print("1. Analyze Password Strength")
        print("2. Generate Custom Wordlist")
        print("3. Security Tips")
        print("4. Exit")
        print("="*60)
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            password = input("\nEnter password to analyze: ").strip()
            if password:
                analysis = analyzer.analyze_password(password)
                analyzer.display_analysis(password, analysis)
                
                # Provide recommendations
                if analysis['strength'] != 'STRONG':
                    print("💡 RECOMMENDATIONS:")
                    print("  • Use at least 12 characters")
                    print("  • Mix uppercase, lowercase, numbers, and symbols")
                    print("  • Avoid common words and patterns")
                    print("  • Use a passphrase or password manager")
                    print()
            else:
                print("⚠️ Password cannot be empty!\n")
        
        elif choice == '2':
            print("\n" + "="*60)
            print("CUSTOM WORDLIST GENERATOR")
            print("="*60)
            print("This tool generates potential weak passwords for testing.")
            print("⚠️ Use only for authorized security testing!\n")
            
            name = input("Enter name (or press Enter to skip): ").strip()
            birthdate = input("Enter birthdate YYYY or YYYY-MM-DD (or press Enter to skip): ").strip()
            keywords_input = input("Enter keywords separated by comma (or press Enter to skip): ").strip()
            keywords = [k.strip() for k in keywords_input.split(',')] if keywords_input else []
            
            print("\n⏳ Generating wordlist...")
            wordlist = generator.generate_from_inputs(name, birthdate, keywords)
            
            generator.display_sample(25)
            
            save = input("Save complete wordlist to file? (y/n): ").strip().lower()
            if save == 'y':
                filename = input("Enter filename (default: custom_wordlist.txt): ").strip()
                if not filename:
                    filename = "custom_wordlist.txt"
                generator.save_wordlist(filename)
        
        elif choice == '3':
            print("\n" + "="*60)
            print("CYBERSECURITY PASSWORD TIPS")
            print("="*60)
            print("""
1. LENGTH MATTERS
   • Use at least 12-16 characters
   • Longer passwords are exponentially harder to crack

2. COMPLEXITY IS KEY
   • Mix uppercase and lowercase letters
   • Include numbers and special characters
   • Avoid predictable substitutions (e.g., P@ssw0rd)

3. AVOID COMMON MISTAKES
   • Don't use dictionary words
   • Avoid personal information (name, birthdate)
   • Don't reuse passwords across sites
   • Avoid sequential patterns (123, abc)

4. BEST PRACTICES
   • Use passphrases (e.g., "Coffee!Morning#Walk2024")
   • Enable two-factor authentication (2FA)
   • Use a password manager
   • Change passwords if breach suspected

5. PASSWORD STRENGTH EXAMPLES
   • WEAK: password123, john1990, qwerty
   • MEDIUM: John@1990, MyDog2024!
   • STRONG: Tr0p1c@l$unS3t#2024, C0ff33&M0rn!ng$W@lk
            """)
            print("="*60)
        
        elif choice == '4':
            print("\n✓ Thank you for using the Password Security Tool!")
            print("✓ Stay secure! 🔒\n")
            break
        
        else:
            print("\n⚠️ Invalid choice! Please enter 1-4.\n")


def main():
    """Main program entry point"""
    print_banner()
    print("\n⚠️  ETHICAL USE DISCLAIMER ⚠️")
    print("This tool is for educational and authorized security testing only.")
    print("Unauthorized access to systems is illegal.")
    input("\nPress Enter to continue...")
    
    main_menu()


if __name__ == "__main__":
    main()