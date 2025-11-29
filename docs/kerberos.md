# Kerberoasting and suspicious AS-REQ:

## What is Kerberos ?

Kerberos is a network authentication protocol designed to provide strong authentication for client/server applications using secret-key cryptography. 

The KDC (Key Distribution Centre) in the domain controller is responsible for this process of authentication and identity verification where it provides a centralized authentication server whose function is to authenticate users to servers and servers to users. 

The main components of Kerberos are:

- **Authentication Server (AS):** The Authentication Server performs the initial authentication and ticket for Ticket Granting Service.
- **Database:** The Authentication Server verifies the access rights of users in the database.
- **Ticket Granting Server (TGS):** The Ticket Granting Server issues the ticket for the Server.


1. User login and request services on the host. Thus user requests for ticket-granting service from the AS.(AS-REQ)
2. Authentication Server verifies user's access right using database and then gives ticket-granting-ticket and session key. Results are encrypted using the hash of the user.
3. The decryption of the message is done using the password then send the ticket to Ticket Granting Server. The Ticket contains authenticators like user names and network addresses.
4. Ticket Granting Server decrypts the ticket sent by User and authenticator verifies the request then creates the ticket for requesting services from the Server.
5. The user sends the Ticket and Authenticator to the Server.
6. The server verifies the Ticket and authenticators then generate access to the service. After this User can access the services.

## Kerberos common attacks that are to detect:

### 1. Suspicious AS-REQ: The request of the TGT

**Suspicious activity here often indicates:**

- Password spraying attacks
- Brute force attempts
- Kerberoasting preparation
- Credential stuffing
- Compromised accounts

To investigate this potential attack we can follow the below steps: 

1. **Analyse the source** 

**Check the requesting device/IP:**

- Is it a known corporate device or external IP?
- Verify geo-location (is it from an expected location?)

KQL Queries: 

```visual-basic
DeviceNetworkEvents
| where RemoteIP == "<suspicious_IP>"
| where Timestamp between (datetime(<start>) .. datetime(<end>))
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort
```

1. Examine Authentication Patterns

**Look for authentication anomalies:**

- High volume of AS-REQ attempts in short timeframe
- Many Failed authentication attempts followed by success
- Authentication from unusual locations or devices
- Off-hours authentication attempts

KQL Queries: 

```visual-basic
IdentityLogonEvents
| where Timestamp > ago(24h)
| where Protocol == "Kerberos"
| where AccountName == "<suspected_account>"
| summarize 
    TotalAttempts = count(),
    FailedAttempts = countif(ActionType == "LogonFailed"),
    SuccessfulAttempts = countif(ActionType == "LogonSuccess"),
    UniqueIPs = dcount(IPAddress),
    UniqueDevices = dcount(DeviceName)
    by AccountName, bin(Timestamp, 1h)
```

1. **User Account Analysis**

**Verify account legitimacy:**

- Is the account active and should it be authenticating?
- Check account privilege level (standard user vs. admin)
- Review account creation date (newly created accounts are suspicious)
- Check for recent password changes or account modifications

**Look for compromise indicators:**

- Concurrent logins from multiple locations
- Impossible travel scenarios
- Access to resources the user doesn't normally access
- Unusual service ticket requests (TGS-REQ) following the AS-REQ

1. **Determining if Activity is Expected**

**Suspicious/Unexpected Indicators:**

- Multiple failed attempts across many accounts
- Off-hours activity inconsistent with user behaviour
- High volume of requests in short time
- Authentication from known malicious IPs
- Service accounts authenticating from user workstations

**Investigation Actions:**

1. Check correlated alerts in the same incident
2. Review sign-in logs in Entra ID 
3. Examine domain controller security logs (Event IDs 4768, 4771)

```visual-basic
KQL
let SuspiciousAccount = "<account_name>";
let TimeWindow = 24h;
union
    (DeviceLogonEvents
    | where Timestamp > ago(TimeWindow)
    | where AccountName == SuspiciousAccount),
    (DeviceFileEvents
    | where Timestamp > ago(TimeWindow)
    | where InitiatingProcessAccountName == SuspiciousAccount),
    (DeviceProcessEvents
    | where Timestamp > ago(TimeWindow)
    | where AccountName == SuspiciousAccount)
| summarize Events = count() by ActionType, DeviceName, bin(Timestamp, 1h) 
```

### 2. Kerberoasting attack

Kerberoasting attack is a post exploitation technique targeting the Kerberos authentication protocol.

adversary uses a valid (even low-privilege) domain user account to request service tickets for service accounts (accounts that have a Service Principal Name (SPN) registered). These service tickets (TGS tickets) are encrypted with the service account’s password hash, and the attacker can retrieve them and crack the hash offline to obtain the plaintext password.

Here’s a step-by-step overview of how a Kerberoasting attack typically unfolds:

1. **Target Identification:** The attacker enumerates Active Directory to find **user accounts with SPNs**. Any authenticated domain user can query directory data to identify these accounts since having an SPN means the account is running a Kerberos-service.
2. **Ticket Request (TGS):** Using any domain user credentials, the attacker requests a **Kerberos service ticket** (TGS) for one or more of the identified SPNs. This request is made to the Key Distribution Center (KDC) on the domain controller. Notably, the KDC does **not** check whether the requesting user has permission to actually use the service – it only verifies that the user is authenticated and the SPN exists This design flaw is what makes Kerberoasting possible: **any authenticated user can request a service ticket for any SPN**.
3. **Ticket Retrieval:** The domain controller responds by issuing the requested TGS. The **service ticket is encrypted with the service account’s secret key** – effectively using a hash of the service account’s password as the encryption key. The attacker now receives this **encrypted ticket**. 
4. **Offline Cracking:**  The speed of cracking depends on the password strength and the encryption algorithm used. (Notably, attackers often request the ticket using the older RC4-HMAC encryption if possible, since it’s weaker and faster to crack than modern AES encryption.)
5. **Service Account Compromise:** If the password hash is cracked, the attacker now knows the **service account’s actual password**.  In real attacks, this foothold often leads to **full domain compromise** if the service account has extensive rights.

**Kerberoasting IOCs:** 

**Multiple SPN Ticket Requests**: Unusual volume of Kerberos service ticket requests (Event ID 4769) from a single user, especially targeting many different services in a short period.

**RC4 Encryption Usage:** Service tickets using **RC4-HMAC (encryption type 0x17)** are a red flag. Modern Kerberos defaults to AES encryption, so an RC4 ticket request may indicate the attacker intentionally requested a crackable encryption type.
**Non-Standard User Agents**: In Event 4769 logs, the **requesting account is a normal user** (no “$” at end) requesting tickets for services – normal users don’t typically request service tickets for arbitrary applications.

**No Corresponding Access**: Service tickets requested but never actually used to log into the service.

**KQL query to detect Kerberoasting :** 

### **Sentinel Query for Ticket Encryption Types**

```
SecurityEvent
| where EventID == 4769
| extend EncryptionType = case(
    TicketEncryptionType == "0x17", "RC4-HMAC (Weak)",
    TicketEncryptionType == "0x12", "AES256 (Secure)",
    "Unknown"
)
| where EncryptionType == "RC4-HMAC (Weak)"
| project TimeGenerated, Account, EncryptionType
```

### **Sentinel Query for High Volume TGS Requests**

```
SecurityEvent
| where EventID == 4769
| summarize RequestsPerHour = count() by bin(TimeGenerated, 1h), Account
| where RequestsPerHour > 50
| project TimeGenerated, Account, RequestsPerHour
```

### Defender XDR Identity Logon events table

```visual-basic
IdentityLogonEvents
| where Protocol == "Kerberos"
| extend ParsedFields = parse_json(AdditionalFields)
| extend EncryptionType = tostring(ParsedFields.EncryptionType)
| where EncryptionType == "Rc4Hmac"
| where LogonType == "Resource access"
| summarize
RequestCount = count(),
UniqueServices = dcount(DestinationDeviceName),
Services = make_set(DestinationDeviceName)
by AccountName, AccountDomain, DeviceName, IPAddress, bin(Timestamp, 1h)
```

# Security principal reconnaissance (LDAP) attack

Security principal reconnaissance (LDAP) is a type of reconnaissance typically used by attackers to gain critical information about the domain environment.

Attackers use LDAP queries to enumerate and collect:

- **User accounts with Service Principal Names (SPNs)** - targets for Kerberoasting
- **Members of sensitive security groups** - Domain Admins, Enterprise Admins, Schema Admins
- **Domain configurations** - Exchange servers, domain controllers
- **Account permissions** - delegation rights, privileges
- **Access Control Lists (ACLs)** - permission relationships between accounts

The below KQL query can help us to detect if there are any malicious LDAP activities in our network. 

```visual-basic
// First KQL to Search for LDAP Actions - LDAP Hunting Query with Target
let LDAP_Filter = dynamic([
"objectGUID=*",
"(objectClass=*)",
"(schemaIDGUID=*)",
"(samAccountType=805306368)",
"(&(objectclass=computer)(userAccountControl&8192))",
"( | (objectClass=user) (objectClass=group) ) (objectSid=S-1-5-21-1960408961-838170752-1801674531-512) )",
"objectCategory=CN=Organizational-Unit,CN=Schema,CN=Configuration",
"(|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))",
"(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))",
"(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)"
]);
let LDAP_Target = dynamic([
"Domain Admins",
"Schema Admins",
"Enterprise Admins",
"AllDomains",
"AllTrustDomains",
"AllSites",
"AllGroupPolicies"
]);
IdentityQueryEvents
| where Timestamp >= ago(1d)
| where ActionType == "LDAP query"
| where QueryTarget has_any (LDAP_Target)
| where Query has_any (LDAP_Filter)

// Second KQL to Search for LDAP Actions - LDAP Hunting Query without Target

let LDAP_Filter = dynamic([
"objectGUID=*",
"(objectClass=*)",
"(schemaIDGUID=*)",
"(samAccountType=805306368)",
"(&(objectclass=computer)(userAccountControl&8192))",
"( | (objectClass=user) (objectClass=group) ) (objectSid=S-1-5-21-1960408961-838170752-1801674531-512) )",
"objectCategory=CN=Organizational-Unit,CN=Schema,CN=Configuration",
"(|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))",
"(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))",
"(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)"
]);
IdentityQueryEvents
| where Timestamp >= ago(1d)
| where ActionType == "LDAP query"
| where Query has_any (LDAP_Filter)
```

# Suspected DCSync attack (replication of directory services)

DCSync is a cyberattack technique where threat actors impersonate legitimate Domain controllers to request password hashes and sensitive information from other DCs. The attack leverages the Directory Replication Service Remote Protocol (MS-DRSR) to extract credentials without running code on target DC memory or directly compromising the NTDS.dit file.

This technique fundamentally abuses the trust relationship between domain controllers. Attackers exploit legitimate replication protocols to harvest credentials across the entire domain infrastructure.

DCSync attacks require specific replication permissions within Active Directory. Attackers must possess “Replicating Directory Changes” and “Replicating Directory Changes All” extended rights on the domain object.

This technique falls under MITRE ATT&CK T1003.006 as a credential dumping method. It represents a post-exploitation technique that requires initial elevated privileges on the network.

Common tools for executing DCSync include Mimikatz, Impacket, and DSInternals. These open-source utilities provide the technical capability to invoke the DsGetNCChanges function and process returned credential data.

DCSync execution follows a predictable sequence that exploits legitimate AD replication mechanisms. Understanding this attack flow is essential for implementing effective detection and prevention strategies.

## **1. Initial Foothold and Privilege Escalation**

Attackers must first gain elevated privileges within the target domain. This typically involves compromising accounts with Domain Administrator, Enterprise Administrator, or Administrators group membership. Alternatively, attackers may compromise service accounts that have been delegated specific replication rights.

## **2. Target Domain Controller Identification**

Once privileged access is established, attackers identify accessible Domain Controllers within the target environment. Any functional DC can serve as a replication source for the attack.

## **3. Domain Controller Impersonation**

Using tools like Mimikatz with the command lsadump::dcsync /user:<target_user> /domain:<domain.com> or Impacket’s secretsdump.py, attackers simulate legitimate DC behavior. The compromised machine directly calls the DsGetNCChanges function of the Directory Replication Service Remote Protocol (DRSUAPI).

## **4. Replication Data Request and Credential Extraction**

The attacker’s spoofed DC sends replication requests to legitimate DCs, requesting synchronization of specific directory objects. These requests can target individual user accounts or entire domain naming contexts.

Legitimate DCs respond to replication requests by sending the requested data, including current and historical password hashes. Extracted data includes NTLM hashes, Kerberos keys, and potentially clear-text passwords if reversible encryption is enabled.

LSA secrets and SAM secrets may also be extracted during comprehensive DCSync operations.

## IOCs and elements to monitor:

### **Processes**

- **Mimikatz.exe**
- **Python3** (Impacket scripts)

### **Ports and Protocols**

- **RPC:** 135, dynamic range **49152–65535**
- **LDAP / LDAPS:** 389 / 636
- **Global Catalog:** 3268 / 3269

### **Relevant Event IDs**

- **4662** – Object operations
- **4624** – Network logons
- **5136** – Directory object modifications
- **Sysmon events** – Process/memory-related events

### **SubjectUserName Field**

If legitimate, this field should contain the **machine account name of a Domain Controller**, which ends with **“$”**.

### **AccessMask**

- Should contain **0x100**, which represents **control access**, typically associated with high-level and explicitly granted permissions.

### **Replication-Related Property GUIDs**

- **1131f6aa-9c07-11d1-f79f-00c04fc2dcd2** — *DS-Replication-Get-Changes*
- **1131f6ad-9c07-11d1-f79f-00c04fc2dcd2** — *DS-Replication-Get-Changes-All*
- **89e95b76-444d-4c62-991a-0facbeda640c** — *DS-Replication-Get-Changes-In-Filtered-Set*

Below are some KQL queries that can help us to detect the DCSync replication: 

```visual-basic
SecurityEvent
| where EventID == 4662 
| where Account !endswith "$" 
| where Account !startswith "MSOL_" //exclude AZ account 
| where ObjectServer == "DS" 
| where Properties contains "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" 
| project TimeGenerated, EventID, Account, Properties, Computer
```

```visual-basic
SecurityEvent
| where EventID == 4662
| where OperationType == "Object Access"
| where AccessMask == "0x100" 
| where Properties contains "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" 
    or Properties contains "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" 
    or Properties contains "89e95b76-444d-4c62-991a-0facbeda640c" 
| where SubjectUserName !endswith "$" 
| where SubjectUserName !startswith "MSOL_" 
```

```visual-basic
IdentityDirectoryEvents
| where ActionType == "Directory Service Replication"
| where Protocol == "Drsr" 
| where AccountName !endswith "$" 
| where AccountName !startswith "MSOL_" // Exclude Azure AD Connect accounts
| project Timestamp, DeviceName, AccountName, AccountDomain, 
          DestinationDeviceName, Protocol, ActionType, AdditionalFields
| sort by Timestamp desc
```

```visual-basic
IdentityDirectoryEvents
| where ActionType == "Directory Service Replication"
| extend ReplicationGUIDs = tostring(parse_json(AdditionalFields).Properties)
| where ReplicationGUIDs has_any (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  
    "89e95b76-444d-4c62-991a-0facbeda640c"  
)
| where AccountName !endswith "$"
| project Timestamp, AccountName, AccountDomain, DeviceName,
          DestinationDeviceName, ReplicationGUIDs, ActionType
```

# Bibliography

https://infrasos.com/kerberoasting-attack-detection-prevention-mitigation/

https://app.hackthebox.com/sherlocks/Campfire-1

https://github.com/eshlomo1/MS-Defender-4-xOPS/blob/main/MDI/MDI-Hunting/Hunting%20for%20LDAP.kusto

https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Identity/AnomalousLDAPTraffic.md

https://blog.blacklanternsecurity.com/p/detecting-dcsync

https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks
