---
title: "LDAP Protocol — Directory Access Backbone & Relay Attack Surface"
doc_type: "foundation"
phase: 0
phase_name: "00-Foundations"
topic: "Directory-Internals"
core_primitives: ["LDAP Bind", "LDAP Search", "LDAP Modify", "SASL", "LDAP Signing", "Channel Binding", "Anonymous Bind", "DN", "Filter Syntax", "ASN.1"]
applies_to: ["Active Directory", "LDAP", "LDAPS", "Global Catalog"]
status: "verified"
tags: [foundation, internals, ldap, ldaps, bind, sasl, search-filters, ldap-controls, enumeration, relay]
---

# LDAP Protocol — Directory Access Backbone & Relay Attack Surface

> **Architectural Mission:** Master the internal mechanics of the Lightweight Directory Access Protocol (LDAP) and its role as the primary query and modification engine for Active Directory Domain Services (AD DS). Understand how directory trees are structured, how ASN.1 BER encoding governs the wire protocol, how the four bind models establish session trust, how complex prefix search filters evaluate directory entries, and why cryptographic signing and Channel Binding Tokens (CBT) represent the definitive line of defense against directory relay attacks.

---

## 1. Architectural Foundations & Purpose

### 1.1 The Database Highway of Active Directory
Every resource, relationship, and credential state in an Active Directory forest resides within a centralized database file named `ntds.dit` (NT Directory Services - Directory Information Tree) managed by the Extensible Storage Engine (ESE, commonly known as the JET database engine).

While protocols like Kerberos handle ticket granting and SMB handles file transmission, **LDAP (Lightweight Directory Access Protocol)** is the universal, standardized wire protocol used by clients, servers, and administrative tools to interrogate and mutate the directory database. 

Whenever a system:
- Looks up a user's group memberships during logon,
- Resolves an email address to a recipient object,
- Enumerates domain computers for administrative patching,
- Edits a Group Policy Object (GPO), or
- Updates an Access Control List (ACL) on an Organizational Unit (OU),

that operation executes as an **LDAP Request** transmitted over the network to a Domain Controller (DC).

### 1.2 The Active Directory Directory Information Tree (DIT)
Active Directory organizes information hierarchically according to the X.500 directory model. Every entry in the directory is an **Object** governed by the Active Directory Schema:
- **DN (Distinguished Name):** The unambiguous, unique path identifying an object within the directory hierarchy (e.g., `CN=Ahmed,OU=Engineering,DC=corp,DC=local`).
- **RDN (Relative Distinguished Name):** The leftmost component of a DN that distinguishes an object from its siblings within the same parent container (e.g., `CN=Ahmed`).
- **Object Classes:** Structural templates defining what type of entity the object represents (e.g., `top`, `person`, `organizationalPerson`, `user`, `computer`).
- **Attributes:** Key-value pairs containing specific properties (e.g., `sAMAccountName`, `mail`, `memberOf`, `userAccountControl`, `nTSecurityDescriptor`).

```text
+----------------------------------------------------------------------------------------------------+
|                         ACTIVE DIRECTORY DIRECTORY INFORMATION TREE (DIT)                          |
+----------------------------------------------------------------------------------------------------+

  DC=corp,DC=local  (Domain Root Partition)
  |
  +-- CN=Users  (Default User Container)
  |   +-- CN=Administrator
  |   +-- CN=krbtgt
  |
  +-- CN=Computers  (Default Computer Container)
  |   +-- CN=DC01
  |
  +-- OU=Workstations  (Organizational Unit)
  |   +-- CN=WKSTN01
  |
  +-- OU=Engineering  (Organizational Unit)
      +-- CN=Ahmed  (Leaf User Object: CN=Ahmed,OU=Engineering,DC=corp,DC=local)
      |   |-- sAMAccountName: ahmed
      |   |-- objectSid: S-1-5-21-394...-1105
      |   |-- memberOf: CN=Engineering-Global,OU=Groups,DC=corp,DC=local
      |   \-- userAccountControl: 512 (NORMAL_ACCOUNT)
      |
      \-- CN=Engineering-Global  (Security Group Object)
```

### 1.3 Terminology & Core Primitives (Zero-Acronym Onboarding)
- **LDAP (Lightweight Directory Access Protocol):** An open, vendor-neutral application protocol (RFC 4511) operating over TCP/UDP port 389 used to query and modify directory services.
- **LDAPS (LDAP over TLS/SSL):** LDAP encapsulated within an encrypted Transport Layer Security (TLS) tunnel, operating over TCP port 636.
- **Global Catalog (GC):** A distributed directory repository running on designated Domain Controllers (listening on TCP port 3268 for cleartext and 3269 for SSL) containing a partial attribute set for every object across all domains in the entire forest.
- **ASN.1 (Abstract Syntax Notation One):** The formal interface definition language used by telecommunication and networking standards to define structured data types independently of computer architecture.
- **BER (Basic Encoding Rules):** The binary encoding standard used by LDAP to serialize ASN.1 messages into Tag-Length-Value (TLV) byte streams over TCP.
- **SASL (Simple Authentication and Security Layer):** A generalized framework (RFC 4422) enabling connection-based protocols to authenticate using pluggable cryptographic mechanisms such as Kerberos (GSS-API) or NTLM.
- **GSS-API (Generic Security Services Application Program Interface):** A standardized security API (RFC 2743) allowing applications to establish an authenticated security context with a remote peer without hardcoding specific authentication algorithms.
- **CBT (Channel Binding Token):** A cryptographic hash of the outer TLS server certificate (defined in RFC 5929) embedded within an inner authentication handshake to prevent relay attacks across different protocol boundaries.
- **OID (Object Identifier):** A globally unique, dot-separated numerical string (e.g., `1.2.840.113556.1.4.803`) assigned by international standards bodies and vendors to uniquely identify directory attribute types, syntaxes, matching rules, and extended controls.

---

## 2. Protocol Internals & The Wire Exchange

### 2.1 The Wire Protocol: ASN.1 BER Structure
Every LDAP communication exchange consists of discrete **LDAPMessage** envelopes serialized using ASN.1 BER encoding. An `LDAPMessage` packet possesses three structural components:

```text
LDAPMessage ::= SEQUENCE {
    messageID       MessageID (INTEGER),
    protocolOp      CHOICE {
        bindRequest         BindRequest,
        bindResponse        BindResponse,
        searchRequest       SearchRequest,
        searchResEntry      SearchResultEntry,
        searchResDone       SearchResultDone,
        modifyRequest       ModifyRequest,
        modifyResponse      ModifyResponse,
        ...
    },
    controls        [0] Controls OPTIONAL
}
```

1. **`messageID`:** A 32-bit integer generated by the client to track asynchronous operations. When the server replies, it includes the identical `messageID`, allowing multiple simultaneous queries across a single multiplexed TCP socket.
2. **`protocolOp`:** The specific operation being executed (Bind, Search, Modify, Add, Delete, Extended Operation).
3. **`controls`:** An optional sequence of standardized or vendor-specific flags (represented by OIDs) that alter how the server evaluates the request (such as server-side sorting or paged results).

---

### 2.2 Walkthrough: Tracing an LDAP Search on the Wire

Consider our enterprise scenario:
Ahmed is logged into `WKSTN01.corp.local`. Ahmed opens a directory administration console or executes a directory query to locate all active domain accounts within the `Engineering` department:
`Base DN: OU=Engineering,DC=corp,DC=local`
`Filter: (&(objectClass=user)(sAMAccountName=*))`

The following network interaction occurs between `WKSTN01` (Client) and `DC01` (Domain Controller):

```text
  +----------------------------------------------------------------------------------------------------+
  |                                 THE LDAP WIRE INTERACTION LIFECYCLE                                |
  +----------------------------------------------------------------------------------------------------+

     CLIENT WORKSTATION                                                      DOMAIN CONTROLLER
    [ ahmed @ WKSTN01 ]                                                     [ DC01 on TCP 389 ]
             |                                                                       |
             | ====== STEP 1: TRANSPORT CONNECTION ================================= |
             |                                                                       |
             |  1. TCP Three-Way Handshake (SYN -> SYN/ACK -> ACK)                   |
             |  -------------------------------------------------------------------> |
             |                                                                       |
             | ====== STEP 2: SESSION BIND (SASL GSS-API / Kerberos) =============== |
             |                                                                       |
             |  2. bindRequest (MessageID: 1, Version: 3, SASL: GSS-SPNEGO)          |
             |     - Negotiates Kerberos mechanism                                   |
             |     - Attaches Kerberos AP-REQ (Service Ticket for ldap/dc01)         |
             |  -------------------------------------------------------------------> |
             |                                                                       |
             |                                  [DC01 decrypts Kerberos Service Ticket]
             |                                  [DC01 verifies PAC and Ahmed's identity]
             |                                  [DC01 derives LDAP Session Signing Key]
             |                                                                       |
             |  3. bindResponse (MessageID: 1, ResultCode: 0 [success])              |
             |  <------------------------------------------------------------------- |
             |                                                                       |
             | ====== STEP 3: DIRECTORY SEARCH REQUEST ============================= |
             |                                                                       |
             |  4. searchRequest (MessageID: 2)                                      |
             |     - baseObject: "OU=Engineering,DC=corp,DC=local"                   |
             |     - scope: wholeSubtree (2)                                         |
             |     - derefAliases: neverDerefAliases (0)                             |
             |     - sizeLimit: 1000                                                 |
             |     - timeLimit: 120 seconds                                          |
             |     - typesOnly: FALSE                                                |
             |     - filter: (&(objectClass=user)(sAMAccountName=*))                 |
             |     - attributes: ["sAMAccountName", "mail", "userAccountControl"]    |
             |     - Controls: Simple Paged Results (OID 1.2.840.113556.1.4.319)     |
             |  -------------------------------------------------------------------> |
             |                                                                       |
             |                                  [DC01 translates filter to ESE index]
             |                                  [DC01 evaluates DACLs on matched rows]
             |                                  [DC01 extracts requested attributes]
             |                                                                       |
             | ====== STEP 4: RESULT RETURN ======================================== |
             |                                                                       |
             |  5. searchResEntry (MessageID: 2)                                     |
             |     - objectName: "CN=Ahmed,OU=Engineering,DC=corp,DC=local"          |
             |     - attributes: sAMAccountName="ahmed", mail="ahmed@corp.local"     |
             |  <------------------------------------------------------------------- |
             |                                                                       |
             |  6. searchResEntry (MessageID: 2)                                     |
             |     - objectName: "CN=Sarah,OU=Engineering,DC=corp,DC=local"          |
             |     - attributes: sAMAccountName="sarah", mail="sarah@corp.local"     |
             |  <------------------------------------------------------------------- |
             |                                                                       |
             |  7. searchResDone (MessageID: 2, ResultCode: 0 [success])             |
             |     - Response Control: Paging Cookie (Returned if more pages exist)  |
             |  <------------------------------------------------------------------- |
             +-----------------------------------------------------------------------+
```

---

## 3. The Four LDAP Bind Models Dissected

Before a client can execute a search or modification in Active Directory, it must execute an **LDAP Bind** to establish its identity and security context. Active Directory supports four distinct bind models:

### 3.1 Anonymous Bind (Unauthenticated Access)
- **The Concept:** The client sends a `bindRequest` with a zero-length DN and a zero-length password, requesting access as `NT AUTHORITY\ANONYMOUS LOGON`.
- **The Active Directory Architectural Reality:**
  - In Windows 2000, Anonymous Bind was enabled by default, allowing anyone on the network to enumerate domain users and password policies without credentials.
  - Beginning with Windows Server 2003, Microsoft disabled anonymous directory queries by default. This control is governed in the Active Directory Configuration partition under:
    `CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=local`
    via the **`SeventhDsHeuristic`** string attribute. When this character is `0` or unset, anonymous queries are rejected with error `LDAP_INAPPROPRIATE_AUTH` (`0x30`).
  - *Residual Exposure:* Even when anonymous LDAP operations are restricted, unauthenticated clients can still query the root Directory Specific Entry (**RootDSE**) over port 389 to read basic directory metadata, including the forest functional level, naming contexts, supported SASL mechanisms, and the DC's FQDN.

---

### 3.2 Simple Bind (Cleartext Credentials)
- **The Concept:** The client sends a `bindRequest` containing the user's plaintext Distinguished Name (`CN=Ahmed,OU=Users,DC=corp,DC=local`) paired with the user's **plaintext password** in cleartext.
- **The Architectural Hazard:**
  When executed over unencrypted port 389, the user's password travels in raw, unencrypted bytes across the local network segment. Any network tap, span port, or compromised switch can harvest domain credentials in plaintext. Simple Bind should **never** be permitted over port 389; it is acceptable only when encapsulated inside an encrypted LDAPS (TCP 636) TLS tunnel.

---

### 3.3 SASL / GSS-API Negotiate Bind (The Enterprise Standard)
- **The Concept:** Standard Windows domain members authenticate to LDAP using **Simple Authentication and Security Layer (SASL)** via the **GSS-API Negotiate** mechanism (SPNEGO).
- **The Protocol Flow:**
  1. The client requests a SASL Bind specifying mechanism `GSS-SPNEGO`.
  2. The client reaches out to the KDC on port 88, requests a Kerberos Service Ticket for the SPN `ldap/DC01.corp.local`, and attaches this ticket to the LDAP bind request.
  3. The Domain Controller decrypts the Service Ticket, validates the client's identity and PAC, and accepts the bind.
  4. **Session Protection:** Both client and DC derive an ephemeral session key from the Kerberos ticket. This key is subsequently used to digitally sign (**LDAP Signing**) or encrypt (**LDAP Sealing**) all subsequent LDAP queries and results, completely protecting the session against tampering and eavesdropping without requiring TLS certificates.

---

### 3.4 LDAPS (LDAP over TLS/SSL)
- **The Concept:** An encrypted TLS session negotiated over dedicated TCP port 636 before any LDAP protocol bytes are exchanged.
- **Prerequisites:** To enable LDAPS on a Domain Controller, the DC must possess a valid X.509 machine certificate issued by a trusted enterprise Certificate Authority (Active Directory Certificate Services - AD CS) containing the `Server Authentication` Extended Key Usage (EKU `1.3.6.1.5.5.7.3.1`).
- **Operational Value:** Provides transport encryption for third-party systems (such as Linux servers, printers, or web applications) that do not support SASL Kerberos binding.

---

## 4. Search Filter Syntax, Operators & Matching Rules

### 4.1 Polish Prefix Notation (RFC 4515)
LDAP search filters do not use standard infix notation (e.g., `A AND B`). Instead, they are constructed using **Polish Prefix Notation**, where the logical operator precedes the operands:
$$\text{Filter} = (\langle \text{operator} \rangle \, (\langle \text{filter}_1 \rangle) \, (\langle \text{filter}_2 \rangle))$$

#### Logical Operators:
- **AND (`&`):** All enclosed conditions must evaluate to true.
  - Example: `(&(objectClass=user)(department=Engineering))`
- **OR (`|`):** At least one enclosed condition must evaluate to true.
  - Example: `(|(department=Engineering)(department=Finance))`
- **NOT (`!`):** Inverts the result of the single enclosed condition.
  - Example: `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` (Exclude disabled accounts)

---

### 4.2 Matching Rule OIDs (Bitwise Logic & Transitive Search)
Standard LDAP equality checks (`attribute=value`) cannot evaluate bitmask fields or traverse complex recursive directory structures. To solve this, Active Directory implements **Extensible Matching Rules** referenced by specific Object Identifiers (OIDs):

$$\langle \text{attribute} \rangle : \langle \text{matchingRuleOID} \rangle : = \langle \text{value} \rangle$$

#### 1. Bitwise AND (`1.2.840.113556.1.4.803` — `LDAP_MATCHING_RULE_BIT_AND`):
Evaluates whether a specific bit is set within an integer bitmask.
- *Primary Use:* Filtering the `userAccountControl` (UAC) attribute.
- *Example (Find accounts with Pre-Authentication disabled):*
  `(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))`
  *(Because `DONT_REQ_PREAUTH` is bit flag `0x00400000` = `4,194,304` in decimal)*.
- *Example (Find accounts configured with Unconstrained Delegation):*
  `(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))`
  *(Because `TRUSTED_FOR_DELEGATION` is bit flag `0x00080000` = `524,288`)*.

#### 2. Bitwise OR (`1.2.840.113556.1.4.804` — `LDAP_MATCHING_RULE_BIT_OR`):
Evaluates whether *any* of the specified bits are set within an integer bitmask.

#### 3. In-Chain Transitive Matching (`1.2.840.113556.1.4.1941` — `LDAP_MATCHING_RULE_IN_CHAIN`):
Active Directory supports deeply nested group hierarchies: User A is in Group B, Group B is in Group C, and Group C is granted access. A standard equality query for Group C will not return User A.
- *The Solution:* The `LDAP_MATCHING_RULE_IN_CHAIN` rule traverses the entire ancestral tree recursively on the Domain Controller.
- *Example (Find all members of Domain Admins, including nested groups):*
  `(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=corp,DC=local))`

---

## 5. Directory Limits, Pagination & Extended Controls

### 5.1 The `MaxPageSize` Bottleneck
Domain Controllers must serve thousands of concurrent clients without exhausting physical memory or bandwidth. To maintain stability, Microsoft enforces hard administrative limits within Active Directory via LDAP query policies (managed under `CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=local`).

- **`MaxPageSize` Constraint:** By default, a Domain Controller will return a maximum of **1,000 objects** for any single `searchRequest`.
- **The Problem:** If an administrator or service queries a domain containing 20,000 users with a simple filter like `(objectClass=user)`, the DC returns the first 1,000 records followed by a `searchResDone` packet containing warning code `LDAP_SIZE_LIMIT_EXCEEDED` (`0x04`). The remaining 19,000 objects are discarded!

### 5.2 Simple Paged Results Control (RFC 2696)
To retrieve large datasets reliably, clients must utilize the **Simple Paged Results Control** (OID `1.2.840.113556.1.4.319`).
- **The Mechanism:**
  1. The client attaches the paging control to its `searchRequest`, specifying a requested page size (e.g., `size: 500`) and an empty cookie.
  2. The DC returns the first 500 objects, followed by a `searchResDone` message containing an opaque binary **Paging Cookie** generated by the server.
  3. The client issues a new `searchRequest` containing the exact same query, attaching the Paging Cookie received from the previous page.
  4. The DC uses the cookie to resume directory retrieval at the exact row index where the previous page terminated.
  5. The cycle repeats until the DC returns a final page with an empty cookie, signaling completion.

---

## 6. Demystifying LDAP Signing & Channel Binding Tokens (CBT)

Security vulnerabilities in directory services frequently stem from how network endpoints protect—or fail to protect—the integrity of their LDAP communication channels.

### 6.1 The Threat: Unsigned LDAP & Cross-Protocol Relay
Consider an enterprise network where Domain Controllers accept unsigned cleartext LDAP connections over TCP port 389:

```text
+----------------------------------------------------------------------------------------------------+
|                               THE MECHANISM OF NTLM RELAY INTO LDAP                                |
+----------------------------------------------------------------------------------------------------+

  VICTIM CLIENT (Admin)             ATTACKER PROXY (MitM)                    DOMAIN CONTROLLER
          |                                  |                                       |
          |  Authenticates via NTLM (SMB)    |                                       |
          | -------------------------------> |                                       |
          |                                  |  1. TCP Connect to port 389 (LDAP)    |
          |                                  | ------------------------------------> |
          |                                  |                                       |
          |                                  |  2. SASL NTLM Type 1 (Negotiate)      |
          |                                  | ------------------------------------> |
          |                                  | <------------------------------------ |
          |                                  |     Type 2 Challenge from DC          |
          |                                  |                                       |
          |  Type 2 Challenge forwarded      |                                       |
          | <------------------------------- |                                       |
          |                                  |                                       |
          |  Type 3 Authenticate Response    |                                       |
          | -------------------------------> |                                       |
          |                                  |  3. SASL NTLM Type 3 forwarded to DC  |
          |                                  | ------------------------------------> |
          |                                  |                                       |
          |                                  |     [DC accepts NTLM, authenticates   |
          |                                  |      attacker as Admin!]              |
          |                                  | <------------------------------------ |
          |                                  |     bindResponse: SUCCESS             |
          |                                  |                                       |
          |                                  |  4. modifyRequest (Add Admin to Group)|
          |                                  | ------------------------------------> |
          |                                  |     [DC executes write as Admin!]     |
```

1. **The Relay Vector:** An adversary intercepts an incoming NTLM authentication from a privileged workstation (or triggers it via authentication coercion).
2. **The LDAP Injection:** The attacker forwards this authentication to the Domain Controller on TCP port 389 as a SASL NTLM Bind.
3. **The Unsigned Write:** Because LDAP on port 389 does not enforce digital signatures by default, the attacker is granted an authenticated directory session. The attacker immediately transmits an LDAP `modifyRequest` to elevate permissions—such as modifying `nTSecurityDescriptor` or adding an account to `Domain Admins`.

---

### 6.2 The Defenses: LDAP Signing vs Channel Binding Tokens

#### 1. LDAP Signing (Integrity on Port 389):
- **Mechanism:** During SASL negotiation (Kerberos or NTLM), the client and server negotiate session security. Every subsequent LDAP request and response is signed with a cryptographic HMAC using the session key.
- **Why It Stops Relays:** When an attacker relays an NTLM authentication, the attacker does not possess the `ExportedSessionKey` held in the victim's memory. If LDAP Signing is enforced on the Domain Controller, any subsequent `modifyRequest` sent by the attacker without a valid cryptographic signature is immediately rejected with `LDAP_STRONG_AUTH_REQUIRED` (`0x08`).

#### 2. Channel Binding Tokens (CBT on Port 636 / LDAPS):
- **The Problem with LDAPS Relaying:** If an attacker attempts to relay NTLM into secure LDAPS (port 636), the attacker must establish their own TLS session with the DC.
- **The CBT Defense:** With Channel Binding enforced, the client computes a SHA-256 hash of the server's TLS certificate (`tls-server-end-point`) and embeds it within the NTLM Type 3 message. If the authentication was relayed from a different connection, the DC detects that the certificate hash inside the authentication payload does not match its own TLS certificate, and aborts the connection.

---

## 7. Architectural Vulnerability Primitives (Zero Tool Dumping)

Security vulnerabilities in Active Directory LDAP arise directly from deliberate architectural conveniences embedded in the directory service design:

### 7.1 Broad Default Read Permissions (`Authenticated Users`)
- **Design Philosophy:** Active Directory was engineered to allow employees to look up colleagues, resolve email addresses, find file shares, and read Group Policy Objects effortlessly.
- **The Friction Point:** By default, the special identity `NT AUTHORITY\Authenticated Users` possesses `READ_PROP` permissions over almost all attributes of all objects within the Domain Naming Context.
- **The Consequence:** Any compromised user account—even an unprivileged contractor or compromised workstation machine account—can query LDAP to dump the entire directory structure: all users, computers, service accounts, SPNs, group memberships, and security descriptors.

---

### 7.2 Directory Modification as the Universal Escalation Highway
- **The Friction Point:** All permissions and structural attributes in Active Directory are updated through LDAP `modifyRequest` packets.
- **Critical Target Attributes:**
  - `nTSecurityDescriptor`: Controls the Access Control List of an object. Gaining write access allows an adversary to grant themselves `GenericAll`.
  - `msDS-AllowedToActOnBehalfOfOtherIdentity`: The binary attribute governing Resource-Based Constrained Delegation (RBCD). Modifying this attribute on a computer object allows an adversary to impersonate any user to that computer.
  - `msDS-KeyCredentialLink`: Stores public key certificates for PKINIT / Shadow Credentials. Writing to this attribute allows passwordless authentication as the target.
  - `servicePrincipalName`: Controls Kerberos ticket routing. Adding an SPN to a user account exposes it to offline ticket extraction.

---

## 8. Defensive Telemetry, Detection Engineering & Hardening

### 8.1 Directory Service Event Telemetry
Domain Controllers record LDAP operations and security events within the **Directory Service** and **Security** event logs:

| Event ID | Log Name | Operational Meaning | Strategic Significance |
|:---:|:---:|:---|:---|
| **2886** | Directory Service | LDAP signing warnings. | Logged every 24 hours when the DC is configured to allow unsigned LDAP binds. |
| **2887** | Directory Service | Summary of unsigned/cleartext LDAP binds. | Aggregates the total count of insecure binds over a 24-hour window. |
| **2889** | Directory Service | Unsigned LDAP client connection details. | **High-Value Auditing:** Identifies the exact client IP address, username, and bind type of every unsigned LDAP connection. Vital for identifying systems requiring remediation before enforcement. |
| **3074 / 3075** | Directory Service | LDAP Channel Binding audit events. | Identifies clients connecting without proper Channel Binding Tokens. |
| **5136** | Security | A directory service object was modified. | **Primary Attack Telemetry:** Records exact attribute modifications in Active Directory, displaying the object DN, modified attribute name, and the old/new values. |

---

### 8.2 Detection Heuristics & Hunting Logic

#### 1. Dangerous Attribute Modifications (KQL):
Detects modifications to high-risk Active Directory attributes typically targeted during privilege escalation:

```kusto
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName in (
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-KeyCredentialLink",
    "nTSecurityDescriptor",
    "servicePrincipalName",
    "adminCount"
)
| project TimeGenerated, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue, OperationType
```

#### 2. Auditing Insecure LDAP Clients:
Monitor Directory Service Event `2889` to generate an inventory of all applications transmitting unsigned LDAP requests across the enterprise:

```text
Log: Directory Service
Event ID: 2889
Filter: EventData contains "Client IP" and "Binding Type: 0" (Cleartext) or "Binding Type: 1" (Unsigned SASL)
```

---

### 8.3 Enterprise Hardening Blueprint
Eradicating LDAP attack surface requires enforcing cryptographic signing and channel binding across all Domain Controllers:

1. **Enforce LDAP Server Signing:**
   - Configure GPO: `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options`:
     - `Domain controller: LDAP server signing requirements` $\rightarrow$ **Require signing**
   - *Impact:* Neutralizes SASL NTLM relay into LDAP port 389 across the entire domain.
2. **Enforce LDAPS Channel Binding (CBT):**
   - On all Domain Controllers, enforce Channel Binding Tokens by deploying the registry value:
     - Path: `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`
     - Value Name: `LdapEnforceChannelBinding`
     - Value Type: `DWORD`
     - Value Data: `2` (Enforce Channel Binding)
   - *Impact:* Completely prevents cross-protocol NTLM relaying into LDAPS port 636.
3. **Restrict Anonymous LDAP Access:**
   - Verify that the `SeventhDsHeuristic` attribute on `CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=local` is not set to `2` (which forces anonymous access support).
4. **Deploy Enterprise PKI for Universal LDAPS:**
   - Ensure every Domain Controller automatically enrolls a valid Server Authentication certificate from an enterprise Certificate Authority to provide secure, encrypted TLS connectivity for non-Windows clients.

---

## 9. Authoritative Specifications, RFCs & Cross-Vault Links

### 9.1 Authoritative Specifications
- **RFC 4511:** *Lightweight Directory Access Protocol (LDAP): The Protocol* — The foundational specification defining message envelopes, operations, and ASN.1 encoding.
- **RFC 4515:** *Lightweight Directory Access Protocol (LDAP): String Representation of Search Filters* — Formal specification for filter syntax and prefix notation.
- **RFC 2696:** *LDAP Control Extension for Simple Paged Results* — Specification for pagination and server-side cookie management.
- **RFC 4422:** *Simple Authentication and Security Layer (SASL)* — The general framework for pluggable connection-based authentication.
- **[MS-ADTS]:** *Active Directory Technical Specification* — Microsoft specification detailing Active Directory directory partitions, schema rules, and matching rule OIDs.

