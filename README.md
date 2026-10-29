# AI Phishing Detector

A Python command-line tool that reads an email, checks its headers, inspects its links, looks for red-flag wording and uses an AI model to review the result. It then reports whether the email is **likely malicious**, **suspicious** or **likely not malicious**.

Built as a personal cybersecurity project, drawing on my coursework at UTS (Networking and Cybersecurity).

## How it works
1. **Reads the email** from an `.eml` file (sender, subject, body and links).
2. **Checks the headers**
   - SPF, DKIM and DMARC results in `Authentication-Results`
   - Reply-To or Return-Path domains that differ from the From domain
   - Display names that imitate a brand or contain a different email address
3. **Inspects the links**
   - Links that don't use HTTPS, or that point to a raw IP address
   - Link text that shows one domain while the link goes to another
   - Look-alike domains (for example `paypa1`), punycode, `@` tricks, URL shorteners and long subdomain chains
4. **Checks the wording** for urgency and requests for login or payment details.
5. **Asks an AI model (optional)** to review the headers, links, findings and body, and return a verdict, red flags and a short explanation.
6. **Gives a final result.** If the rule-based score and the AI disagree, the tool reports the more cautious verdict.

The email text is treated as untrusted input. The AI is told to analyse it and never follow instructions inside it, which helps guard against prompt injection from a malicious email.

## Built with
- Python 3 (standard library for parsing and checks)
- Anthropic API for the AI review (optional)

## How to run
```bash
git clone https://github.com/<your-username>/ai-phishing-detector.git
cd ai-phishing-detector

# Rule-based checks only (no account or API key needed)
python phishing_detector.py samples/phishing_example.eml --no-ai

# With AI review
pip install -r requirements.txt
export ANTHROPIC_API_KEY="your-key-here"     # Windows PowerShell: $env:ANTHROPIC_API_KEY="your-key-here"
python phishing_detector.py samples/phishing_example.eml
```

Options: `--no-ai` for rule-based checks only, `--json` for machine-readable output. Set `PHISHING_MODEL` to change the AI model.

To test an email of your own, save it as an `.eml` file from your mail client. Do not upload real emails to a public repository.

## Tests
```bash
python -m unittest test_detector.py -v
```

## Example output (rule-based, sample email)
```
Rule-based score: 28 -> LIKELY MALICIOUS
FINAL RESULT: LIKELY MALICIOUS
```
![Phishing sample result](screenshots/phishing-result.png)

![Legitimate sample result](screenshots/legit-result.png)

![Tests passing](screenshots/tests-passing.png)
The sample emails in `samples/` are made up for testing and are not real messages.

## What I learned
- How phishing emails are put together and the warning signs in headers, links and wording
- How SPF, DKIM and DMARC results show whether a sender is genuine
- How to combine rule-based checks with an AI model, and why the AI's input must be treated as untrusted
- How to test, document and publish a project on GitHub

## Limitations and future improvements
- Scores and thresholds are hand-tuned on a few examples, so accuracy has not been measured on a large dataset
- Brand and TLD lists are small and would need regular updates
- Does not check attachments or look up domain age or reputation
- Possible next steps: attachment checks, a larger test set and a simple web interface

## Disclaimer
This is a project for learning purposes. It gives an estimate only and should not replace professional email security tools.
