# Secure Authentication Prototype

A Python prototype I built for my Secure Software Engineering course to practice protecting account information. It demonstrates password hashing, encrypted address data, session tokens, and different permissions for administrators and customers.

## What It Demonstrates

- Password hashing with PBKDF2-HMAC-SHA256 and a separate random salt for each user.
- Address encryption with AES-GCM.
- Random session tokens after successful login.
- Administrator checks before creating users or listing accounts.
- Customers retrieving their own information through their session.

## How the Demo Works

The program creates sample accounts and runs through a sequence of examples:

1. An administrator logs in.
2. The administrator creates customer accounts.
3. A customer retrieves their own information.
4. The administrator lists accounts while addresses remain encrypted in the output.
5. A customer attempts an administrator action and is denied.

## How to Run

You need Python 3 and the `cryptography` package.

From the project folder, install the dependency:

```bash
python -m pip install cryptography
```

Run the demonstration:

```bash
python "Comprehensive Security Plan and Prototype (code).py"
```

The program generates an encryption key automatically when `AES_KEY_B64` is not set.

## Project Files

- `Comprehensive Security Plan and Prototype (code).py` — the Python demonstration.
- `docs/Comprehensive Security Plan and Prototype (paper).docx` — the supporting security plan and explanation.
- `docs/Module 2 STRIDE Threat Modeling Analysis Worksheet.docx` — related threat-modeling work.

## Project Scope

This is a classroom demonstration, not a production authentication service. Accounts and sessions are stored in memory and disappear when the program closes. It uses fixed sample passwords, displays a demonstration session token, and does not implement session expiration or login rate limiting.

**Course:** Secure Software Engineering  
**Date:** September 25, 2025
