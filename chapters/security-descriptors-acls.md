---
title: "Security Descriptors & ACLs — Access Control Architecture in Active Directory"
doc_type: "foundation"
phase: 0
phase_name: "00-Foundations"
topic: "Authorization"
core_primitives: ["DACL", "SACL", "ACE", "Security Descriptor", "nTSecurityDescriptor", "SDDL", "AdminSDHolder", "SDProp", "GenericAll", "WriteDacl", "DCSync Rights"]
applies_to: ["Active Directory", "NTFS", "Windows Kernel"]
status: "verified"
tags: [foundation, internals, acl, dacl, sacl, sddl, security-descriptor, ace, adminsdholder, genericall, writedacl, dcsync]
---

# Security Descriptors & ACLs — Access Control Architecture in Active Directory

> **Architectural Mission:** Master the internal mechanics of the Windows Access Control Model as implemented within Active Directory Domain Services (AD DS). Understand how the Security Reference Monitor (SRM) processes access tokens against security descriptors, deconstruct the binary `nTSecurityDescriptor` and its component Access Control Entries (ACEs), master the string syntax of the Security Descriptor Definition Language (SDDL), and demystify why enterprise privilege in Active Directory is not a binary status flag, but a directed mathematical graph of discretionary permissions.

---

## 1. Architectural Foundations & Purpose

### 1.1 Authentication vs Authorization: The Core Separation
In modern operating systems and directory services, security is divided into two distinct cryptographic and kernel operations:
1. **Authentication:** Establishes and verifies identity ("Who are you?"). In Active Directory, this is accomplished via Kerberos tickets or NTLM challenge-response handshakes. When Ahmed logs in, authentication produces an authenticated identity represented by a unique **Security Identifier (SID)**.
2. **Authorization:** Governs what that authenticated identity is permitted to execute ("What are you allowed to do?"). 

In Windows and Active Directory, **there is no such architectural concept as an "administrative user" in the abstract**. An account is not inherently privileged because of its name or account type. Instead, privilege is purely the outcome of a continuous, mathematical evaluation performed by the operating system kernel: **evaluating a caller's Access Token against the Security Descriptor attached to a requested resource**.

### 1.2 The Active Directory Access Control Model
The access control model across all Windows NT derivatives rests upon four interconnected components:

1. **The Securable Object:** Any resource that can have security enforced upon it (such as a user account in `ntds.dit`, an Organizational Unit, an NTFS file, a registry key, or a service process). Every Active Directory object stores its authorization policy within a binary attribute named **`nTSecurityDescriptor`**.
2. **The Access Token (The Subject):** Generated during logon by the Local Security Authority Subsystem Service (LSASS). The Access Token accompanies every process and thread executed by the user. It contains the user's primary SID, the SIDs of all security groups the user belongs to (direct and nested), and user-held system privileges (e.g., `SeDebugPrivilege`).
3. **The Security Descriptor (The Object):** A structured binary data container attached to the securable object defining who owns it, who can access it, and what actions generate security audit logs.
4. **The SRM (Security Reference Monitor):** The core security engine within the Windows NT executive kernel (`ntoskrnl.exe`), mirrored in user-mode by Active Directory Domain Services, responsible for executing the formal **Access Check Algorithm**.

---

### 1.3 Terminology & Core Primitives (Zero-Acronym Onboarding)
- **SID (Security Identifier):** A variable-length cryptographic byte string (e.g., `S-1-5-21-394...-1105`) that uniquely identifies a security principal (user, group, computer, or domain) across the forest.
- **RID (Relative Identifier):** The final numeric sub-authority component of a SID (e.g., `1105` for Ahmed, `500` for the built-in Administrator, `512` for Domain Admins) uniquely distinguishing an object within a specific domain.
- **SRM (Security Reference Monitor):** The Windows kernel component that evaluates access requests by comparing caller access tokens against object security descriptors.
- **ACL (Access Control List):** A container list composed of zero or more individual Access Control Entries.
- **DACL (Discretionary Access Control List):** The specific ACL that grants or denies access rights to users and groups. It is "discretionary" because the owner of the object has the discretion to assign whatever permissions they choose.
- **SACL (System Access Control List):** The specific ACL that instructs the operating system on which access attempts (successful or failed) should generate security audit events in the Windows Event Log.
- **ACE (Access Control Entry):** A single discrete rule inside an ACL specifying: *"Principal X is Granted/Denied Permission Y on Object Z."*
- **SDDL (Security Descriptor Definition Language):** A standardized, human-readable text string format used by Windows to serialize and represent binary security descriptors.
- **AdminSDHolder:** A special template object located in the Active Directory System container (`CN=AdminSDHolder,CN=System,DC=corp,DC=local`) that protects the DACLs of all high-value administrative accounts and groups.
- **SDProp (Security Descriptor Propagator):** A background maintenance thread executing on the Primary Domain Controller (PDC) Emulator that periodically overwrites the DACLs of protected administrative accounts with the clean template from `AdminSDHolder`.
- **GUID (Globally Unique Identifier):** A 128-bit integer used in Active Directory schema to uniquely identify object classes, specific attributes (Property Sets), and extended access rights.

---

## 2. Walkthrough: The SRM Access Check Algorithm

### 2.1 The Scenario Setup
To observe how the Windows Security Reference Monitor (SRM) enforces authorization, consider this concrete enterprise scenario:
- **Requesting User:** `ahmed` (SID: `S-1-5-21-394...-1105`, member of `Engineering-Users` group SID `S-1-5-21-394...-1602`).
- **Target Object:** A user object representing a marketing department head:
  `CN=Sarah,OU=Marketing,DC=corp,DC=local` (SID: `S-1-5-21-394...-1250`).
- **The Desired Operation:** Ahmed executes an administrative tool or script that attempts to modify Sarah's account properties by updating her `scriptPath` attribute (or forcing a password reset).

The tool transmits an LDAP `modifyRequest` targeting `Sarah`'s Distinguished Name to `DC01`. Before the Domain Controller writes a single byte to `ntds.dit`, the security subsystem initiates the **SRM Access Check Algorithm**.

---

### 2.2 Diagram: The Access Check Decision Pipeline

```text
  +----------------------------------------------------------------------------------------------------+
  |                           THE WINDOWS SRM ACCESS CHECK EVALUATION PIPELINE                         |
  +----------------------------------------------------------------------------------------------------+

     AHMED'S ACCESS TOKEN                                                    SARAH'S SECURITY DESCRIPTOR
     +-----------------------------------------+                            +--------------------------+
     | User SID   : S-1-5-21-...-1105 (ahmed)  |                            | Owner SID: Domain Admins |
     | Group SIDs : S-1-5-21-...-513 (Users)   |                            | DACL     : Sequence of   |
     |              S-1-5-21-...-1602 (Eng)    |                            |            ordered ACEs  |
     | Requested  : ADS_RIGHT_DS_WRITE_PROP    |                            +--------------------------+
     |              for attribute: scriptPath  |                                         |
     +-----------------------------------------+                                         |
                          |                                                              |
                          +-------------------------------+------------------------------+
                                                          |
                                                          v
                                     [ STEP 1: IS CALLER THE OWNER? ]
                                     If caller requests WRITE_DAC or READ_CONTROL,
                                     Owner is automatically granted access.
                                                          |
                                                          v
                                     [ STEP 2: EVALUATE DACL PRESENCE ]
                                     - If DACL is NULL (missing entirely) ----> [ ACCESS GRANTED (Unrestricted) ]
                                     - If DACL is EMPTY (zero ACEs) ----------> [ ACCESS DENIED (Locked down) ]
                                                          |
                                                          v
                                     [ STEP 3: TRAVERSE ORDERED ACES ]
                                     SRM scans ACEs sequentially from index 0:
                                                          |
                                  +-----------------------+-----------------------+
                                  |                                               |
                                  v                                               v
                     [ ACE TYPE: ACCESS_DENIED ]                     [ ACE TYPE: ACCESS_ALLOWED ]
                                  |                                               |
                    Does Trustee SID match Ahmed                   Does Trustee SID match Ahmed
                    or any Group in Ahmed's Token?                 or any Group in Ahmed's Token?
                                  |                                               |
                          +-------+-------+                               +-------+-------+
                          |               |                               |               |
                         YES              NO                             YES              NO
                          |               |                               |               |
                          v               v                               v               v
             Does Deny mask cover any   Ignore ACE,             Accumulate matching     Ignore ACE,
             of Ahmed's requested       proceed to next         permissions into        proceed to next
             permissions?               ACE.                    Granted Access Mask.    ACE.
                          |                                               |
                         YES                                              v
                          |                                     Have ALL requested
                          v                                     permissions been accumulated?
                [ ACCESS DENIED IMMEDIATELY ]                             |
                (Evaluation halts instantly;                      +-------+-------+
                 Deny takes absolute priority)                    |               |
                                                                 YES              NO
                                                                  |               |
                                                                  v               v
                                                        [ ACCESS GRANTED ]      Proceed to next ACE
                                                        (Evaluation terminates; in DACL.
                                                         Access is approved)      |
                                                                                  v
                                                                        [ REACHED END OF DACL? ]
                                                                        If end of DACL is reached
                                                                        and requested permissions
                                                                        remain unsatisfied:
                                                                                  |
                                                                                  v
                                                                        [ ACCESS DENIED ]
  +----------------------------------------------------------------------------------------------------+
```

---

### 2.3 Step-by-Step Traversal Rules
The SRM access check algorithm is strictly deterministic and follows canonical processing rules:

1. **Owner Rights Processing:**
   If Ahmed requests `WRITE_DAC` (the permission to modify the object's DACL) or `READ_CONTROL` (the permission to read the security descriptor), the SRM compares Ahmed's SID against the **Owner SID** field of Sarah's security descriptor. The object Owner has an immutable, mathematical guarantee: **an owner can always read and modify their own object's DACL**, even if a DACL explicitly denies them access!
2. **Canonical DACL Ordering:**
   To ensure predictable security semantics, Windows enforces a specific order when writing ACEs to a DACL:
   - **Explicit Deny ACEs** appear first.
   - **Explicit Allow ACEs** appear second.
   - **Inherited Deny ACEs** (passed down from parent OUs) appear third.
   - **Inherited Allow ACEs** appear fourth.
3. **Sequential Traversal:**
   The SRM steps through the DACL from top to bottom:
   - When an **Access-Denied ACE** matches Ahmed or any of his group memberships, the SRM checks if the denied permissions intersect with the requested permissions. If they intersect, the algorithm **aborts immediately and returns `STATUS_ACCESS_DENIED`**.
   - When an **Access-Allowed ACE** matches Ahmed or his groups, the granted rights are merged into the caller's running `GrantedAccess` bitmask.
   - If the `GrantedAccess` bitmask completely covers all rights Ahmed requested, the evaluation halts immediately, returning **`STATUS_SUCCESS`**.
4. **Default Deny Termination:**
   If the SRM reaches the final ACE in the DACL and Ahmed's requested rights have not been completely satisfied, access is denied. **Absence of an explicit Allow ACE equals a Deny.**

---

## 3. Dissecting the Binary `nTSecurityDescriptor`

When stored in `ntds.dit` or transmitted over LDAP, security descriptors are serialized in **Self-Relative Format** (specified in **[MS-DTYP] §2.4.6**). In a self-relative descriptor, all data structures (SIDs and ACLs) reside within a single contiguous memory buffer, referenced by relative byte offsets from the start of the structure.

```text
+----------------------------------------------------------------------------------------------------+
|                         SELF-RELATIVE SECURITY_DESCRIPTOR BINARY STRUCTURE                         |
+----------------------------------------------------------------------------------------------------+

  0x00: [ Revision (1 byte) ]     [ Sbz1 (1 byte) ]     [ Control Flags (2 bytes) ]
  0x04: [ OffsetOwner (4 bytes) - Relative offset to Owner SID ]
  0x08: [ OffsetGroup (4 bytes) - Relative offset to Primary Group SID ]
  0x0C: [ OffsetSacl  (4 bytes) - Relative offset to System Access Control List ]
  0x10: [ OffsetDacl  (4 bytes) - Relative offset to Discretionary Access Control List ]
  ----------------------------------------------------------------------------------------------------
  Variable Byte Offsets:
  [ Owner SID Buffer       : Revision + SubAuthorityCount + IdentifierAuthority + SubAuthorities... ]
  [ Group SID Buffer       : Primary Group SID ]
  [ SACL Buffer            : AclRevision + Sbz1 + AclSize + AceCount + Sbz2 + [SACL ACE Array] ]
  [ DACL Buffer            : AclRevision + Sbz1 + AclSize + AceCount + Sbz2 + [DACL ACE Array] ]
+----------------------------------------------------------------------------------------------------+
```

### 3.1 Field-by-Field Breakdown
- **`Revision` (1 byte):** The version of the security descriptor structure. For all modern Windows systems, this is `0x01`.
- **`Sbz1` (1 byte):** "Should be zero" padding byte for memory alignment.
- **`Control` (2 bytes — `SECURITY_DESCRIPTOR_CONTROL`):** A bitmask defining the behavioral characteristics of the descriptor. Crucial flags include:
  - `SE_DACL_PRESENT` (`0x0004`): The security descriptor contains a valid DACL. (If unset, the object has a NULL DACL, granting unrestricted access to everyone).
  - `SE_DACL_PROTECTED` (`0x1000`): **Blocks ACL Inheritance.** Prevents permissions defined on parent containers (like OUs) from flowing down into this object.
  - `SE_DACL_AUTO_INHERITED` (`0x0400`): Indicates that the DACL was built by automatically propagating inherited ACEs from parent containers.
  - `SE_SELF_RELATIVE` (`0x8000`): Confirms that the descriptor is stored in self-relative format rather than using absolute memory pointers.
- **`OffsetOwner` (4 bytes):** Byte offset from the start of the buffer to the Owner SID.
- **`OffsetGroup` (4 bytes):** Byte offset to the primary group SID (retained for POSIX compliance).
- **`OffsetSacl` (4 bytes):** Byte offset to the SACL. If zero, no SACL exists.
- **`OffsetDacl` (4 bytes):** Byte offset to the DACL.

---

### 3.2 Anatomy of an Access Control Entry (ACE)
An ACL is simply an array of individual ACE structures preceded by an 8-byte header (`ACL_HEADER`).
Every ACE begins with a standardized 4-byte header:

```text
ACE Header:
├── AceType  (1 byte)  : Determines whether this ACE Allows, Denies, Audits, or targets an Object.
├── AceFlags (1 byte)  : Controls inheritance and audit behavior.
└── AceSize  (2 bytes) : Total byte length of this ACE structure.
```

#### ACE Types (`AceType`):
1. **`ACCESS_ALLOWED_ACE_TYPE` (`0x00`):** Standard allow rule granting specific permissions to a trustee SID.
2. **`ACCESS_DENIED_ACE_TYPE` (`0x01`):** Standard deny rule blocking specific permissions for a trustee SID.
3. **`ACCESS_ALLOWED_OBJECT_ACE_TYPE` (`0x05`):** **The foundation of Active Directory granular control.** Unlike file systems where permissions apply to an entire file, Active Directory objects possess individual attributes and extended rights. An Object ACE contains two optional 128-bit GUIDs:
   - `ObjectType GUID`: Specifies the exact schema attribute (e.g., `userPassword`), attribute set, or extended right (e.g., `User-Force-Change-Password`) governed by this ACE.
   - `InheritedObjectType GUID`: Specifies the class of child objects (e.g., only child `user` objects) that inherit this ACE when attached to an OU container.
4. **`ACCESS_DENIED_OBJECT_ACE_TYPE` (`0x06`):** Object-specific deny rule.

#### Inheritance Flags (`AceFlags`):
- `CONTAINER_INHERIT_ACE` (`0x02`): Containers (such as OUs) propagate this ACE to child containers.
- `OBJECT_INHERIT_ACE` (`0x01`): Containers propagate this ACE to child leaf objects (such as users or computers).
- `INHERIT_ONLY_ACE` (`0x08`): The ACE does not apply to the current object; it applies exclusively to child objects that inherit it.
- `INHERITED_ACE` (`0x10`): Indicates that this ACE was inherited from a parent container rather than being explicitly defined on this object.

---

## 4. Deconstructing SDDL (Security Descriptor Definition Language)

Because binary security descriptors are unwieldy to view or edit, Microsoft created **SDDL (Security Descriptor Definition Language)**—a compact, formal string representation formalized in **[MS-DTYP] §2.5.1**.

### 4.1 Master SDDL Syntax Layout
An SDDL string encodes the four components of a security descriptor in a standardized prefix format:

$$\text{SDDL} = \mathbf{O:}\langle \text{OwnerSID} \rangle \; \mathbf{G:}\langle \text{GroupSID} \rangle \; \mathbf{D:}\langle \text{DACL\_Flags} \rangle \langle \text{ACE\_List} \rangle \; \mathbf{S:}\langle \text{SACL\_Flags} \rangle \langle \text{ACE\_List} \rangle$$

#### Individual ACE String Format:
Every ACE inside the DACL (`D:`) or SACL (`S:`) is enclosed in parentheses and contains exactly **six semicolon-delimited fields**:

$$\mathbf{(}\text{AceType} \,;\, \text{AceFlags} \,;\, \text{Rights} \,;\, \text{ObjectType} \,;\, \text{InheritedObjectType} \,;\, \text{TrusteeSID}\mathbf{)}$$

```text
  Field 1: AceType             -> 'A' (Allow), 'D' (Deny), 'OA' (Object Allow), 'OD' (Object Deny)
  Field 2: AceFlags            -> 'CI' (Container Inherit), 'OI' (Object Inherit), 'ID' (Inherited)
  Field 3: Rights (AccessMask) -> Two-character abbreviations or hex mask ('GA', 'RP', 'WP', etc.)
  Field 4: ObjectType          -> Schema GUID of specific attribute or extended right (or empty)
  Field 5: InheritedObjectType -> Schema GUID of child object class allowed to inherit (or empty)
  Field 6: TrusteeSID          -> SID string or well-known trustee alias ('DA', 'WD', 'AU', etc.)
```

---

### 4.2 Dissecting Enterprise SDDL Examples

#### Example 1: Standard Property Read/Write
`D:(A;;RPWP;;;WD)`

- `D:` $\rightarrow$ Discretionary Access Control List (DACL).
- `A` $\rightarrow$ `AceType`: Access Allowed.
- `;;` $\rightarrow$ `AceFlags`: None (explicitly applied to this object, not inherited).
- `RPWP` $\rightarrow$ `Rights`: Read Property (`RP`, `0x00000010`) and Write Property (`WP`, `0x00000020`).
- `;;` $\rightarrow$ `ObjectType` and `InheritedObjectType`: Empty (applies broadly to all properties on the object).
- `WD` $\rightarrow$ `TrusteeSID`: Well-known alias for **Everyone** (`World` — `S-1-1-0`).
- *Plain English:* **"Allow Everyone to read and write all properties on this object."**

---

#### Example 2: Administrative Full Control
`D:P(A;;GA;;;DA)`

- `D:P` $\rightarrow$ DACL with `P` flag (`SE_DACL_PROTECTED` — **Inheritance is blocked**; parent container ACEs will not flow down).
- `A` $\rightarrow$ Access Allowed.
- `GA` $\rightarrow$ `Rights`: **Generic All** (`0x10000000` — Full Unconstrained Control).
- `DA` $\rightarrow$ `TrusteeSID`: Well-known alias for **Domain Admins** (`S-1-5-21-...-512`).
- *Plain English:* **"Block inheritance, and grant Domain Admins complete unconstrained control."**

---

#### Example 3: Granular Password Reset (Object ACE)
`D:(OA;;CR;00299570-246d-11d0-a7ec-00c04fb677f1;;PS)`

- `OA` $\rightarrow$ `AceType`: **Object Access Allowed** (`ACCESS_ALLOWED_OBJECT_ACE_TYPE`).
- `CR` $\rightarrow$ `Rights`: Control Access Right (`0x00000100` — Extended Right).
- `00299570-246d-11d0-a7ec-00c04fb677f1` $\rightarrow$ `ObjectType`: The Active Directory schema GUID for **`User-Force-Change-Password`**.
- `PS` $\rightarrow$ `TrusteeSID`: Well-known alias for **Principal Self** (`S-1-5-10`).
- *Plain English:* **"Grant the user itself the extended right to change its own password."**

---

### 4.3 Reference Table: Common SDDL Aliases & Rights

| SDDL Code | Meaning / Constant | Numerical Value | Category |
|:---:|:---|:---:|:---|
| **`GA`** | `GENERIC_ALL` | `0x10000000` | Full Unconstrained Administrative Control |
| **`GR`** | `GENERIC_READ` | `0x20000000` | Read all properties and permissions |
| **`GW`** | `GENERIC_WRITE` | `0x40000000` | Write all properties and attributes |
| **`RC`** | `READ_CONTROL` | `0x00020000` | Read the Security Descriptor (DACL/Owner) |
| **`WD`** | `WRITE_DAC` | `0x00040000` | **Modify the DACL** (Can grant oneself GenericAll) |
| **`WO`** | `WRITE_OWNER` | `0x00080000` | **Seize Ownership** of the object |
| **`RP`** | `ADS_RIGHT_DS_READ_PROP` | `0x00000010` | Read a specific directory property |
| **`WP`** | `ADS_RIGHT_DS_WRITE_PROP` | `0x00000020` | Write a specific directory property |
| **`CR`** | `ADS_RIGHT_DS_CONTROL_ACCESS` | `0x00000100` | Execute an Extended Right (e.g., DCSync, Reset Password) |
| **`CC`** | `ADS_RIGHT_DS_CREATE_CHILD` | `0x00000001` | Create child objects within a container |
| **`DC`** | `ADS_RIGHT_DS_DELETE_CHILD` | `0x00000002` | Delete child objects within a container |

#### Well-Known Trustee Aliases:
- **`DA`:** Domain Administrators (`S-1-5-21-...-512`)
- **`EA`:** Enterprise Administrators (`S-1-5-21-...-519`)
- **`BA`:** Built-in Administrators (`S-1-5-32-544`)
- **`AU`:** Authenticated Users (`S-1-5-11`)
- **`WD`:** Everyone (`World` — `S-1-1-0`)
- **`PS`:** Principal Self (`S-1-5-10`)
- **`SY`:** Local System (`NT AUTHORITY\SYSTEM` — `S-1-5-18`)

---

## 5. Demystifying Privilege: Active Directory as a Directed Graph

Why do modern Active Directory security evaluations focus on graph theory rather than looking for accounts marked as "Administrators"?

### 5.1 The Mathematical Model: Privilege is a Graph
In Active Directory, identity and access form a **Directed Graph** $G = (V, E)$:
- **Vertices ($V$):** Principals and objects (Users, Groups, Computers, OUs, GPOs, Domains).
- **Edges ($E$):** Access Control Entries (ACEs), group memberships, and architectural relationships directed from a Subject to an Object:
  $$\text{Subject} \xrightarrow{\text{Edge Type}} \text{Object}$$

Privilege escalation in Active Directory is simply the mathematical discovery of a **Transitive Path** from a low-privileged vertex to a Tier-0 administrative vertex:

```text
[ ahmed ] 
   |
   |-- (MemberOf)
   v
[ Engineering-Lead-Group ]
   |
   |-- (WriteDacl)
   v
[ IT-Service-Account ]
   |
   |-- (GenericAll)
   v
[ Domain Admins Group ]
   |
   |-- (MemberOf)
   v
[ Full Forest Compromise ]
```

Ahmed is not in Domain Admins. Ahmed’s group is not in Domain Admins. Yet Ahmed mathematically controls Domain Admins because **he can traverse a chain of discretionary ACE permissions**.

---

### 5.2 The High-Impact ACE Primitives Explained

#### 1. `GenericAll` (Full Control):
- **Mechanism:** Bestows all standard, generic, and object rights simultaneously.
- **Impact:** The trustee can change the target’s password, modify its group memberships, rewrite its SPNs, edit its attributes, or seize ownership.

#### 2. `WriteDacl` (`WRITE_DAC`):
- **Mechanism:** The right to modify the Discretionary Access Control List of the object.
- **The Escalation Path:** An attacker with `WriteDacl` on an object does not need any other rights. They simply craft a new ACE granting themselves `GenericAll`, append it to the DACL, and write it back via LDAP. **`WriteDacl` is mathematically equivalent to `GenericAll`.**

#### 3. `WriteOwner` (`WRITE_OWNER`):
- **Mechanism:** The right to seize ownership of the object.
- **The Escalation Path:** As established in Section 2.3, the Windows SRM guarantees that an object Owner always retains the right to read and modify the DACL (`WRITE_DAC`). An attacker with `WriteOwner` changes the owner to their own account, uses owner rights to grant themselves `GenericAll`, and takes full control. **`WriteOwner` is mathematically equivalent to `GenericAll`.**

#### 4. `WriteProperty` over Sensitive Attributes:
- **`msDS-AllowedToActOnBehalfOfOtherIdentity`:** Writing this binary security descriptor on a computer object configures Resource-Based Constrained Delegation (RBCD), allowing the attacker to impersonate any user to that machine.
- **`msDS-KeyCredentialLink`:** Writing to this attribute injects a public key certificate, enabling passwordless authentication via PKINIT (Shadow Credentials).
- **`servicePrincipalName` (SPN):** Writing an SPN onto a user account exposes that account to offline Kerberoasting.

#### 5. Extended Rights (`CR` — `ControlAccess`):
- **`User-Force-Change-Password` (`00299570-246d-11d0-a7ec-00c04fb677f1`):** Allows an attacker to reset a user's password directly via LDAP or RPC without knowing the user's current password.
- **`DS-Replication-Get-Changes` & `DS-Replication-Get-Changes-All` (DCSync Rights):** When granted on the Domain Root object (`DC=corp,DC=local`), these two extended rights allow a principal to mimic a Domain Controller using the Directory Replication Service Remote Protocol (MS-DRSR), dumping all password hashes across the forest.

---

## 6. The Defense of Privileged Objects: AdminSDHolder & SDProp

Because Active Directory inheritance and delegation can accumulate complex, unintentional ACLs over time, Microsoft engineered an automated immune system to protect Tier-0 accounts: **AdminSDHolder** and the **SDProp (Security Descriptor Propagator)** process.

### 6.1 The Problem: ACL Drift on Administrative Accounts
Consider an enterprise where an administrator accidentally delegates permissions on an Organizational Unit (`OU=Admins,DC=corp,DC=local`) to a junior helpdesk group. Because ACEs inherit downward by default, the helpdesk group would suddenly inherit `GenericAll` or `ResetPassword` over the Domain Administrator accounts residing inside that OU!

---

### 6.2 The Protection Mechanism: AdminSDHolder & SDProp

```text
+----------------------------------------------------------------------------------------------------+
|                                    THE SDPROP REPAIR CYCLE                                         |
+----------------------------------------------------------------------------------------------------+

  PDC EMULATOR (Every 60 Minutes)
  +--------------------------------------------------------------------------------------------------+
  |  1. Locates template: CN=AdminSDHolder,CN=System,DC=corp,DC=local                                 |
  |  2. Reads clean DACL from AdminSDHolder template                                                 |
  |  3. Scans all domain objects where adminCount == 1:                                              |
  |     - Domain Admins, Enterprise Admins, Schema Admins, Built-in Administrators                    |
  |     - Account Operators, Backup Operators, Server Operators                                       |
  |     - Krbtgt account, Domain Controller machine accounts                                         |
  +--------------------------------------------------------------------------------------------------+
                |
                v
  FOR EVERY PROTECTED OBJECT DETECTED:
  +--------------------------------------------------------------------------------------------------+
  |  Step A: Sets SE_DACL_PROTECTED flag on object (Disables all inheritance from parent OUs!)       |
  |  Step B: Completely overwrites the object's DACL with a pristine copy of AdminSDHolder DACL      |
  +--------------------------------------------------------------------------------------------------+
```

1. **The Protected Objects (`adminCount = 1`):** Active Directory maintains an internal list of sensitive administrative groups and accounts (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, and the `krbtgt` account). When an account is added to any of these groups, the directory sets its **`adminCount`** attribute to `1`.
2. **The SDProp Background Thread:** Every 60 minutes, a background thread named **SDProp** wakes up on the Domain Controller holding the Primary Domain Controller (PDC) Emulator FSMO role.
3. **Inheritance Severing:** SDProp inspects every object with `adminCount = 1`. It forcibly applies the `SE_DACL_PROTECTED` flag to the object's security descriptor, instantly severing inheritance from its parent OU. Any accidental delegation granted at the OU layer is stripped away.
4. **Template Enforcement:** SDProp copies the pristine DACL from `CN=AdminSDHolder,CN=System,DC=corp,DC=local` and overwrites the object's DACL, restoring strict administrative access.

### 6.3 The Architectural Implications for Persistence
- **The Ineffective Temporary Backdoor:** If an adversary compromises a Domain Admin and adds a rogue ACE directly to the Domain Admin's DACL, the backdoor will function for at most 60 minutes. As soon as SDProp runs, the rogue ACE is eradicated.
- **The Ultimate Stealth Persistence (`AdminSDHolder` Poisoning):** Conversely, if an adversary with temporary domain administrative access adds an ACE granting their hidden account `GenericAll` directly to the **`CN=AdminSDHolder` template object**, SDProp works in the attacker's favor! Every 60 minutes, SDProp automatically pushes the attacker's backdoor ACE onto every Domain Admin, Enterprise Admin, and protected group across the entire Active Directory forest.

---

## 7. Defensive Telemetry, Detection Engineering & Hardening

### 7.1 Security Event Telemetry
Modifications to Active Directory security descriptors generate high-fidelity security audit events:

| Event ID | Log Name | Operational Meaning | Strategic Significance |
|:---:|:---:|:---|:---|
| **5136** | Security | A directory service object was modified. | **High-Value:** Generated when `nTSecurityDescriptor` is edited over LDAP. Shows the Object DN, the modified attribute (`nTSecurityDescriptor`), and the raw SDDL change. |
| **4670** | Security | Permissions on an object were changed. | Emitted when local or directory object DACLs are modified, displaying the old and new SDDL strings. |
| **4738** | Security | A user account was modified. | Look for changes to `adminCount` or password reset events initiated by non-administrative callers. |
| **4728 / 4732** | Security | A member was added to a security group. | Monitors additions to privileged administrative groups. |

---

### 7.2 Detection Heuristics & Hunting Logic

#### 1. Dangerous DACL Modifications on AdminSDHolder (KQL):
Detects any modification targeting the `AdminSDHolder` template container—a definitive marker of directory persistence staging:

```kusto
SecurityEvent
| where EventID == 5136
| where ObjectDN =~ "CN=AdminSDHolder,CN=System,DC=corp,DC=local"
| where AttributeLDAPDisplayName == "nTSecurityDescriptor"
| project TimeGenerated, SubjectUserName, SubjectDomainName, ObjectDN, AttributeValue, OperationType
```

#### 2. Detecting DCSync Rights Grants on the Domain Root (KQL):
Monitors when `DS-Replication-Get-Changes` (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) or `DS-Replication-Get-Changes-All` (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) extended rights are added to non-DC accounts:

```kusto
SecurityEvent
| where EventID == 5136
| where ObjectDN =~ "DC=corp,DC=local"
| where AttributeLDAPDisplayName == "nTSecurityDescriptor"
| where AttributeValue has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" or AttributeValue has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
| project TimeGenerated, SubjectUserName, ObjectDN, AttributeValue
```

---

### 7.3 Enterprise Hardening Blueprint
Securing Active Directory against ACL-based attacks requires continuous hygiene and strict separation of administrative boundaries:

1. **Audit and Eliminate Dangerous ACE Paths:**
   - Regularly run graph-based security assessments to identify transitive control paths leading to Tier-0 assets.
   - Remove historical delegations that grant `GenericAll`, `WriteDacl`, or `WriteOwner` to non-administrative accounts on OUs hosting sensitive users or servers.
2. **Monitor the `AdminSDHolder` Template Object:**
   - Place an explicit SACL on `CN=AdminSDHolder,CN=System,DC=corp,DC=local` to generate high-priority SIEM alerts on any write operation.
3. **Remediate "Orphaned" Protected Accounts:**
   - When an administrator is removed from Domain Admins, Active Directory **does not automatically reset `adminCount` to 0**, nor does it re-enable inheritance. These accounts remain disconnected from OU policies. Identify and re-enable inheritance on former administrative accounts.
4. **Enforce Tiered Administration (Tier Model / Enterprise Access Model):**
   - Separate administrative accounts strictly: Tier-0 (Domain Admins), Tier-1 (Server Admins), Tier-2 (Workstation Admins).
   - Ensure that lower-tier administrators never possess write permissions, ownership, or password-reset authority over higher-tier accounts or containers.

---

## 8. Authoritative Specifications, RFCs & Cross-Vault Links

### 8.1 Authoritative Specifications
- **[MS-DTYP]:** *Windows Data Types* — Section 2.4.6 (`SECURITY_DESCRIPTOR`) and Section 2.5.1 (`Security Descriptor Definition Language - SDDL`). The definitive mathematical specification for Windows access control.
- **[MS-ADTS]:** *Active Directory Technical Specification* — Details directory object security descriptors, object ACE inheritance mechanics, and the SDProp background task.
- **[MS-PAC]:** *Privilege Attribute Certificate Data Structure* — Documents how group SIDs and user tokens are serialized into Kerberos tickets to form access tokens.

