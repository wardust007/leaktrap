# 🛡️ Security & responsible use

LeakTrap is a **defensive testing tool**. It helps you find out whether an AI model or app
can be tricked into leaking secrets *before* an attacker does.

## ✅ Do
- Test models and applications **you own**, or that you have **written permission** to test.
- Follow each AI provider's terms of service and usage policies.
- Share findings responsibly with the people who can fix them.

## ❌ Don't
- Point LeakTrap at someone else's chatbot, website or API without permission.
- Change the attacks to target real secrets or real people.

## 🔒 How LeakTrap protects you
- Every attack targets a **fake secret** generated fresh for each test. No real data is used.
- The secret is masked as `<SECRET>` in every report and results file.
- API keys are read from environment variables and are **never** written to disk.
- Attacker links use `attacker.example`, a domain reserved for examples (RFC 2606) that can't receive data.

## 🐛 Found a bug in LeakTrap itself?
Please open a GitHub issue. For anything sensitive, contact the author through GitHub first.
