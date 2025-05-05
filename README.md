
# 🔐 Password Strength Checker

![Python](https://img.shields.io/badge/python-3.11-blue)

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A Python-based command-line tool that analyzes the strength of a password using entropy, complexity, and pattern detection. It helps users create more secure passwords by identifying weaknesses and providing actionable suggestions.

## 📋Features
- Checks password length, character diversity, and entropy.

- Detects common passwords from a wordlist (rockyou.txt or   fallback defaults).

- Identifies weak patterns (e.g., qwerty, 1234, repeated characters).

- Estimates time to crack the password using brute force.

- Gives practical suggestions to improve password security.

- Provides a visual score and categorized strength level (Very Weak → Very Strong).

## 🛠️ Requirements
- Python 3.8
- A wordlist file (optional) in data/rockyou.txt for improved common password detection.

## 🚀 How to Use
- Clone the repository
```bash
git clone https://github.com/xiddess/pw-Checker
```
- Change your directory
```bash
cd pw-Checker
```
- run your script
```python
python3 main.py
```

## 🧪 Example Output
```yaml
=== PASSWORD STRENGTH CHECKER ===
This tool analyzes password security using entropy metrics
and provides suggestions to improve password strength.

Enter password (blank to exit):

=== PASSWORD ANALYSIS RESULTS ===
Length: 8 characters
Complexity: ✅ Uppercase
            ✅ Lowercase
            ✅ Numbers
            ❌ Special chars
Common password: ❌ (High Risk!)
Detected patterns: ⚠️ Common keyboard pattern ('123456')

Entropy: 33.64 bits
Strength Score: 47.1/100 (Moderate)

⏱️ Estimated cracking time: less than 1 second

🔧 IMPROVEMENT SUGGESTIONS:
 1. Add special characters (!"#$%&'...)
 2. Avoid detected patterns: Common keyboard pattern ('123456')
 3. Use more random character combinations instead of easily guessed words/patterns
 4. Example strong pattern: Word1#Word2#Symbol3

📊 Strength Score Visualization:
[#####-----] 47/100
```

## 📁 File Structure
```bash
main.py
data/
└── rockyou.txt  # (Optional) Common password list
```

## 🧠 How It Works
- Entropy Calculation: Determines randomness using length * log2(character set size).
- Scoring System:
## 🔢 Scoring System

| Component                            | Maximum Score | Description                                           |
|-------------------------------------|----------------|-----------------------------------------------------|
| Length                              | 30             | Score based on password length.               |
| Complexity                          | 40             | Scores are based on a combination of letters, numbers, symbols.   |
| Entropy                             | 30             | Scores based on diversity and uncertainty.     |
| Deductions (Common/Weak Patterns)   | -              | Score reduction for common or weak passwords.   |

## 📜 License
This project is licensed under the [MIT License](https://opensource.org/licenses/MIT). Feel free to use and modify it for personal or educational purposes.

## 🙋‍♂️ Contributions
Contributions, issues, and suggestions are welcome! Feel free to fork this repo or open an issue to improve the tool.

## ☎️ Contact
For further questions, please contact us at [email](mailto:parker@cyberfear.com)



