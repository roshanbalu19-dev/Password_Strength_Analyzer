import math
import re
import sqlite3
import string
from datetime import datetime

# Optional: Common password list to detect weak, predictable passwords
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "dragon", "letmein", "admin", "welcome", "password123"
}


class PasswordDatabase:
    """Handles optional SQLite integration to prevent password reuse."""
    
    def __init__(self, db_name="password_history.db"):
        self.conn = sqlite3.connect(db_name)
        self.create_table()

    def create_table(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    password_text TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def is_password_reused(self, user_id: str, password: str) -> bool:
        """Check if the password was previously used by the specific user."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT 1 FROM password_history 
            WHERE user_id = ? AND password_text = ?
        """, (user_id, password))
        return cursor.fetchone() is not None

    def save_password(self, user_id: str, password: str):
        """Save a new password into history."""
        with self.conn:
            self.conn.execute("""
                INSERT INTO password_history (user_id, password_text) 
                VALUES (?, ?)
            """, (user_id, password))


class PasswordAnalyzer:
    """Evaluates password strength based on length, complexity, and entropy."""

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """
        Calculates Shannon Entropy in bits.
        Formula: Entropy = L * log2(R)
        L = password length, R = size of the character pool
        """
        pool_size = 0
        if re.search(r'[a-z]', password): pool_size += 26
        if re.search(r'[A-Z]', password): pool_size += 26
        if re.search(r'\d', password): pool_size += 10
        if re.search(r'[^a-zA-Z0-9]', password): pool_size += 32

        if pool_size == 0 or len(password) == 0:
            return 0.0

        return len(password) * math.log2(pool_size)

    def analyze(self, password: str, user_id: str = None, db: PasswordDatabase = None) -> dict:
        score = 0
        feedback = []

        # 1. Database Check for Reuse
        if db and user_id:
            if db.is_password_reused(user_id, password):
                return {
                    "strength": "REJECTED",
                    "score": 0,
                    "entropy": 0,
                    "feedback": ["❌ You have used this password before. Reuse is prohibited."],
                    "suggestion": self.generate_suggestion(password)
                }

        # 2. Check against common dictionary passwords
        if password.lower() in COMMON_PASSWORDS:
            return {
                "strength": "Very Weak",
                "score": 0,
                "entropy": self.calculate_entropy(password),
                "feedback": ["❌ Extremely common password. Easily cracked via dictionary attacks."],
                "suggestion": self.generate_suggestion(password)
            }

        # 3. Check Length
        length = len(password)
        if length >= 16:
            score += 3
        elif length >= 12:
            score += 2
        elif length >= 8:
            score += 1
        else:
            feedback.append("⚠️ Password is too short. Aim for at least 12–16 characters.")

        # 4. Check Complexity (Character Diversity)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

        diversity_count = sum([has_lower, has_upper, has_digit, has_special])
        score += diversity_count

        if not has_lower: feedback.append("💡 Add lowercase letters.")
        if not has_upper: feedback.append("💡 Add uppercase letters.")
        if not has_digit: feedback.append("💡 Add numeric digits.")
        if not has_special: feedback.append("💡 Add special characters (e.g., !@#$%^&*).")

        # 5. Check Structural Patterns
        if re.search(r'(123|abc|qwerty|password)', password, re.IGNORECASE):
            score = max(0, score - 2)
            feedback.append("⚠️ Contains predictable sequential patterns or words.")

        if re.search(r'(.)\1{2,}', password):
            score = max(0, score - 1)
            feedback.append("⚠️ Contains repeating characters (e.g., 'aaa').")

        # 6. Entropy Calculation
        entropy = self.calculate_entropy(password)

        # 7. Rating Determination
        if score >= 6 and entropy > 60:
            rating = "Strong"
        elif score >= 4 and entropy > 40:
            rating = "Moderate"
        else:
            rating = "Weak"

        return {
            "strength": rating,
            "score": f"{score}/7",
            "entropy": round(entropy, 2),
            "feedback": feedback if feedback else ["✅ Password meets security criteria!"],
            "suggestion": self.generate_suggestion(password)
        }

    @staticmethod
    def generate_suggestion(password: str) -> str:
        """Generates a stronger alternative based on the user's input."""
        import random
        
        specials = "!@#$%^&*"
        digits = "0123456789"
        
        # Base enhancement
        enhanced = password.capitalize() if password else "Pass"
        
        # Inject diversity if missing
        if not re.search(r'\d', enhanced):
            enhanced += str(random.randint(10, 99))
        if not re.search(r'[^a-zA-Z0-9]', enhanced):
            enhanced += random.choice(specials)
            
        # Ensure sufficient length
        while len(enhanced) < 14:
            enhanced += random.choice(string.ascii_letters + digits + specials)

        return enhanced


# --- Demonstration ---
if __name__ == "__main__":
    db = PasswordDatabase()
    analyzer = PasswordAnalyzer()
    
    user = "user_101"
    
    print("=== Password Strength Analyzer ===\n")
    
    # Interactive Test Loop
    test_passwords = ["123456", "hello2024", "P@ssw0rd123!", "Correct-Horse-Battery-Staple#99"]

    for pwd in test_passwords:
        print(f"Testing Password: '{pwd}'")
        result = analyzer.analyze(pwd, user_id=user, db=db)
        
        print(f"  • Strength:   {result['strength']}")
        print(f"  • Score:      {result['score']}")
        print(f"  • Entropy:    {result['entropy']} bits")
        print(f"  • Feedback:   {', '.join(result['feedback'])}")
        print(f"  • Suggestion: {result['suggestion']}")
        print("-" * 50)

    # Save a password to DB and attempt reuse test
    secure_pwd = "Correct-Horse-Battery-Staple#99"
    db.save_password(user, secure_pwd)
    
    print(f"\n[DB Test] Re-testing previously saved password for '{user}':")
    reuse_result = analyzer.analyze(secure_pwd, user_id=user, db=db)
    print(f"  • Status: {reuse_result['strength']}")
    print(f"  • Feedback: {reuse_result['feedback'][0]}")