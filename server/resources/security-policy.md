# Security Policy

This policy describes how to report security vulnerabilities responsibly. It is a template shipped with Nauthilus and is not legal advice. Operators should review and adapt it before publishing.

## Reporting a Vulnerability

Please report suspected vulnerabilities using the contact method listed in `/.well-known/security.txt`.

Include as much relevant information as possible:

- affected product, service, or endpoint
- steps to reproduce the issue
- expected and observed behavior
- potential impact
- relevant logs, screenshots, or proof-of-concept details

Do not include sensitive personal data, production secrets, or unrelated third-party data in the report.

## Responsible Testing

Only test systems that you are authorized to assess. Avoid actions that could degrade service availability, alter data, or access data that does not belong to you.

Do not perform:

- denial-of-service testing
- social engineering
- phishing
- physical attacks
- spam or mass account creation
- destructive testing
- persistence, lateral movement, or data exfiltration

If you encounter sensitive data while testing, stop immediately and report the issue without copying, changing, or deleting the data.

## Coordination

We aim to acknowledge reports promptly and coordinate remediation in good faith. Please allow reasonable time for investigation and remediation before public disclosure.

## Scope

Unless a separate policy says otherwise, this policy applies only to systems explicitly identified by the operator publishing this file. Third-party services, hosted customer content, and systems outside that scope are excluded.

## Recognition

Public recognition may be offered at the operator's discretion after a vulnerability has been remediated and disclosure has been coordinated.
