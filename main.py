import re
import math
import string
from getpass import getpass
from pathlib import Path
import time

class PasswordStrengthChecker:
    def __init__(self, wordlist_path='data/rockyou.txt'): ## You can change the rockyou file here
        self.common_passwords = self.load_common_passwords(wordlist_path)
        self.min_password_length = 8
        self.recommended_password_length = 12
        self.special_chars = string.punctuation
    
    def load_common_passwords(self, file_path):
        """Load common passwords from wordlist file"""
        common_passwords = set()
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                for line in f:
                    password = line.strip()
                    if password:
                        common_passwords.add(password)
                        # Limit number of passwords loaded to conserve memory
                        if len(common_passwords) >= 1_000_000:
                            break
            print(f"Loaded {len(common_passwords)} common passwords from wordlist")
        except FileNotFoundError:
            print(f"Warning: Wordlist file not found at {file_path}. Using default common passwords.")
            common_passwords = self.get_default_common_passwords()
        return common_passwords
    
    def get_default_common_passwords(self):
        """Default common passwords if wordlist not found"""
        return {
            'password', '123456', '12345678', '1234', 'qwerty', '12345',
            'dragon', 'baseball', 'football', 'letmein', 'monkey', 'abc123',
            'mustang', 'michael', 'shadow', 'master', 'jennifer', '111111',
            '2000', 'jordan', 'superman', 'harley', '1234567', 'iloveyou'
        }
    
    def calculate_entropy(self, password):
        """Calculate password entropy in bits"""
        char_set = 0
        length = len(password)
        
        # Detect character types used
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_special = any(c in self.special_chars for c in password)
        
        # Calculate character set size
        if has_lower:
            char_set += 26
        if has_upper:
            char_set += 26
        if has_digit:
            char_set += 10
        if has_special:
            char_set += len(self.special_chars)
        
        # If no character types detected, use unique characters
        if char_set == 0:
            char_set = len(set(password))
            if char_set == 0:
                return 0
        
        # Calculate entropy
        entropy = length * math.log2(char_set)
        
        return entropy
    
    def check_common_patterns(self, password):
        """Detect common weakening patterns"""
        patterns = []
        lower_pass = password.lower()
        
        # Keyboard patterns
        keyboard_patterns = [
            'qwerty', 'asdfgh', 'zxcvbn', '123456', '1qaz2wsx',
            '1q2w3e4r', 'qazwsx', '!qaz@wsx', 'qwertyuiop'
        ]
        
        for pattern in keyboard_patterns:
            if pattern in lower_pass:
                patterns.append(f"Common keyboard pattern ('{pattern}')")
                break
        
        # Repeated characters
        if re.search(r'(.)\1{2,}', password):
            patterns.append("Repeated characters (e.g., 'aaa', '111')")
        
        # Number sequences
        if re.search(r'(0123|1234|2345|3456|4567|5678|6789)', password):
            patterns.append("Consecutive number sequence")
        
        # Common date patterns
        if re.search(r'(19|20)\d{2}', password):
            patterns.append("Possible birth year included")
        
        # Common words with simple substitutions
        common_words = ['admin', 'welcome', 'login', 'secret', 'letmein']
        for word in common_words:
            if word in lower_pass:
                patterns.append(f"Contains common word ('{word}')")
                break
        
        return patterns
    
    def generate_password_suggestions(self, password, analysis):
        """Generate password improvement suggestions"""
        suggestions = []
        length = len(password)
        
        # Length-based suggestions
        if length < self.min_password_length:
            suggestions.append(
                f"Add {self.min_password_length - length} more characters "
                f"(minimum {self.min_password_length} characters)"
            )
        elif length < self.recommended_password_length:
            suggestions.append(
                f"Add {self.recommended_password_length - length} characters "
                f"to reach recommended length ({self.recommended_password_length} characters)"
            )
        
        # Complexity suggestions
        if not analysis['has_upper']:
            suggestions.append("Add uppercase letters (A-Z)")
        if not analysis['has_lower']:
            suggestions.append("Add lowercase letters (a-z)")
        if not analysis['has_digit']:
            suggestions.append("Add numbers (0-9)")
        if not analysis['has_special']:
            suggestions.append(f"Add special characters ({self.special_chars[:10]}...)")
        
        # Pattern-based suggestions
        if analysis['common_patterns']:
            suggestions.append("Avoid detected patterns: " + ", ".join(analysis['common_patterns']))
        
        # Entropy-based suggestions
        if analysis['entropy'] < 50:
            suggestions.append(
                "Use more random character combinations instead of easily guessed words/patterns"
            )
        
        # Strong password examples
        if length < 8 or analysis['entropy'] < 60:
            suggestions.append(
                "Example strong pattern: " + self.generate_strong_password_pattern()
            )
        
        return suggestions
    
    def generate_strong_password_pattern(self):
        """Generate example strong password patterns"""
        examples = [
            "Word1#Word2#Symbol3",
            "LongPhrase-NoSpaces123!",
            "N0mb3r!$Ymbol#1nM1ddle",
            "U!pp3rC4s3@StartAndEnd"
        ]
        return examples[0]
    
    def check_password_strength(self, password):
        """Main password strength analysis"""
        # Basic analysis
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in self.special_chars for c in password)
        is_common = password.lower() in self.common_passwords
        common_patterns = self.check_common_patterns(password)
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        
        # Calculate strength score (0-100)
        score = 0
        
        # Length (max 30 points)
        score += min(30, length * 2.5)
        
        # Complexity (max 40 points)
        complexity = sum([has_upper, has_lower, has_digit, has_special]) * 10
        score += complexity
        
        # Entropy (max 30 points)
        score += min(30, entropy / 3)
        
        # Penalties
        if is_common:
            score *= 0.2  # Reduce by 80% if common password
        if common_patterns:
            score *= 0.7  # Reduce by 30% if common patterns
        
        # Ensure score between 0-100
        score = max(0, min(100, score))
        
        # Strength classification
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Moderate"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        # Analysis results
        result = {
            'length': length,
            'has_upper': has_upper,
            'has_lower': has_lower,
            'has_digit': has_digit,
            'has_special': has_special,
            'is_common': is_common,
            'common_patterns': common_patterns,
            'entropy': entropy,
            'score': score,
            'strength': strength,
            'suggestions': []
        }
        
        # Generate suggestions
        result['suggestions'] = self.generate_password_suggestions(password, result)
        
        return result
    
    def estimate_cracking_time(self, entropy):
        """Estimate time needed to crack password"""
        if entropy <= 0:
            return "instantly"
        
        # Assumptions:
        # - 1 trillion (10^12) guesses per second (supercomputer/GPU cluster)
        # - 1 million (10^6) guesses per second (high-end system)
        # - 1 thousand (10^3) guesses per second (regular system)
        
        guesses_per_second = 1e12  # Worst-case scenario
        
        total_guesses = 2 ** entropy
        seconds = total_guesses / guesses_per_second
        
        # Convert to human-readable units
        if seconds < 1:
            return "less than 1 second"
        
        intervals = (
            ('centuries', 60 * 60 * 24 * 365 * 100),
            ('decades', 60 * 60 * 24 * 365 * 10),
            ('years', 60 * 60 * 24 * 365),
            ('months', 60 * 60 * 24 * 30),
            ('weeks', 60 * 60 * 24 * 7),
            ('days', 60 * 60 * 24),
            ('hours', 60 * 60),
            ('minutes', 60),
            ('seconds', 1)
        )
        
        result = []
        for name, count in intervals:
            value = seconds // count
            if value:
                seconds -= value * count
                if value == 1:
                    name = name.rstrip('s')
                result.append(f"{int(value)} {name}")
        
        return ", ".join(result[:2]) if len(result) > 1 else result[0]
    
    def generate_report(self, analysis):
        """Generate analysis report"""
        report = []
        report.append("\n=== PASSWORD ANALYSIS RESULTS ===")
        report.append(f"Length: {analysis['length']} characters")
        report.append(f"Complexity: {'✅' if analysis['has_upper'] else '❌'} Uppercase")
        report.append(f"           {'✅' if analysis['has_lower'] else '❌'} Lowercase")
        report.append(f"           {'✅' if analysis['has_digit'] else '❌'} Numbers")
        report.append(f"           {'✅' if analysis['has_special'] else '❌'} Special chars")
        report.append(f"Common password: {'❌ (High Risk!)' if analysis['is_common'] else '✅'}")
        
        if analysis['common_patterns']:
            report.append(f"Detected patterns: ⚠️ {'; '.join(analysis['common_patterns'])}")
        
        report.append(f"\nEntropy: {analysis['entropy']:.2f} bits")
        report.append(f"Strength Score: {analysis['score']:.1f}/100 ({analysis['strength']})")
        
        # Cracking time estimate
        time_estimate = self.estimate_cracking_time(analysis['entropy'])
        report.append(f"\n⏱️ Estimated cracking time: {time_estimate}")
        
        # Suggestions
        if analysis['suggestions']:
            report.append("\n🔧 IMPROVEMENT SUGGESTIONS:")
            for i, suggestion in enumerate(analysis['suggestions'], 1):
                report.append(f" {i}. {suggestion}")
        else:
            report.append("\n✅ Your password is already very strong!")
        
        return "\n".join(report)

def main():
    print("=== PASSWORD STRENGTH CHECKER ===")
    print("This tool analyzes password security using entropy metrics")
    print("and provides suggestions to improve password strength.\n")
    
    # Initialize checker
    wordlist_path = 'data/rockyou.txt'
    checker = PasswordStrengthChecker(wordlist_path)
    
    while True:
        password = getpass("\nEnter password (blank to exit): ").strip()
        if not password:
            print("Exiting program...")
            break
        
        start_time = time.time()
        analysis = checker.check_password_strength(password)
        elapsed_time = time.time() - start_time
        
        report = checker.generate_report(analysis)
        print(report)
        
        # Display score visualization
        print("\n📊 Strength Score Visualization:")
        score = min(100, max(0, analysis['score']))
        filled = int(score / 10)
        empty = 10 - filled
        print(f"[{'#' * filled}{'-' * empty}] {score:.0f}/100")
        
        print(f"\nAnalysis completed in {elapsed_time:.3f} seconds")

if __name__ == "__main__":
    main()
