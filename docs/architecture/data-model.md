# SecureAssure Data Model

## 1. Purpose

The SecureAssure data model defines the core entities and relationships used by the security risk and assurance framework.

The model is designed to support:

- Asset management
- Service discovery
- Security scanning
- Security findings
- Risk assessment
- CIA impact analysis
- Security controls
- Evidence collection
- Remediation tracking
- Security verification

The data model is designed around the following security workflow:

```text
Asset Discovery
      ↓
Security Assessment
      ↓
Finding
      ↓
Risk Assessment
      ↓
Security Control
      ↓
Remediation
      ↓
Verification
2. Core Entities

SecureAssure will initially use the following core entities:

Asset
Service
Scan
Finding
Risk Assessment
Security Control
Evidence
Remediation
Entity Overview
Entity	Purpose
Asset	Represents a system, host, device, or other security-relevant asset
Service	Represents a network service discovered on an asset
Scan	Represents a security discovery or assessment operation
Finding	Represents a security issue identified during an assessment
Risk Assessment	Represents the calculated security risk associated with a finding
Security Control	Represents a security safeguard or control used to mitigate risk
Evidence	Stores technical evidence supporting a finding or assessment
Remediation	Tracks the process of fixing and verifying a finding
3. Entity Relationships

The primary relationships are:

                    ┌──────────────┐
                    │    ASSET     │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
          SERVICE        SCAN        FINDING
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                 │
                    ▼                 ▼                 ▼
             RISK ASSESSMENT      EVIDENCE        REMEDIATION
                    │
                    ▼
             SECURITY CONTROL
Cardinality
Asset 1 ─────── N Service

Asset 1 ─────── N Scan

Asset 1 ─────── N Finding

Finding 1 ───── 1 Risk Assessment

Finding 1 ───── N Evidence

Finding 1 ───── N Remediation

Finding N ───── N Security Control

The Finding-to-Security-Control relationship is many-to-many and will therefore use an association table.

4. Asset

An Asset represents a system, host, server, workstation, network device, application, or other security-relevant resource.

Example
IP Address:        192.168.56.101
Hostname:          security-lab
Operating System:  Kali Linux
Asset Type:        SERVER
Criticality:       HIGH
Status:            ACTIVE
Main Attributes
Asset ID
IP address
Hostname
Operating system
Asset type
Criticality
Owner
Status
Description
Created timestamp
Updated timestamp
Purpose

Assets are the central objects against which scans, services, findings, and risk assessments are associated.

5. Service

A Service represents a network service discovered on an asset.

Example
Asset:       192.168.56.101
Port:        22
Protocol:    TCP
Service:     SSH
Version:     OpenSSH
State:       OPEN
Main Attributes
Service ID
Asset ID
Port
Protocol
Service name
Service version
State
Discovery timestamp
Relationship
One Asset → Many Services
6. Scan

A Scan represents a discovery, assessment, or security scanning operation performed against authorized targets.

Example
Scan ID:        001
Scanner:        Nmap
Scan Type:      Service Discovery
Target:         192.168.56.0/24
Status:         COMPLETED
Main Attributes
Scan ID
Scanner
Scan type
Target
Status
Started timestamp
Completed timestamp
Configuration
Error information
Scan Lifecycle
PENDING
   ↓
RUNNING
   ↓
COMPLETED

or

PENDING
   ↓
RUNNING
   ↓
FAILED
7. Finding

A Finding represents a security issue identified during an assessment.

Example
Title:       Exposed Database Service
Severity:    HIGH
Status:      OPEN
Asset:       192.168.56.101
Service:     MySQL / 3306
Main Attributes
Finding ID
Asset ID
Service ID
Scan ID
Title
Description
Severity
Status
Detection source
Recommendation
Detected timestamp
Updated timestamp
Finding Lifecycle
OPEN
  ↓
ACKNOWLEDGED
  ↓
IN_PROGRESS
  ↓
REMEDIATED
  ↓
VERIFIED
  ↓
CLOSED
8. Risk Assessment

A Risk Assessment represents the security risk associated with a finding.

Risk assessment will incorporate:

Likelihood
Impact
Confidentiality
Integrity
Availability
Example
Likelihood:        4
Impact:            5

Confidentiality:   5
Integrity:         4
Availability:      3

Risk Score:        20
Risk Level:        CRITICAL
Main Attributes
Risk assessment ID
Finding ID
Likelihood
Impact
Confidentiality impact
Integrity impact
Availability impact
Risk score
Risk level
Assessment method
Assessed timestamp
Risk Calculation

The initial risk model will use:

Risk Score = Likelihood × Impact

The CIA values will be retained separately to provide a detailed impact assessment.

9. Security Control

A Security Control represents a security safeguard, policy, procedure, or technical control used to reduce or manage security risk.

Example
Control Code:    AC-01
Name:            Access Control
Category:        Preventive
Description:     Restrict unauthorized access to protected resources
Main Attributes
Control ID
Control code
Name
Category
Description
Framework
Implementation status
Created timestamp
Updated timestamp
Relationship

A finding may require multiple security controls, and a security control may address multiple findings.

Finding N ───── N Security Control

Therefore, an association table will be used.

10. Evidence

Evidence stores technical information supporting a finding or security assessment.

Example
Source:

Nmap

Command:

nmap -sV 192.168.56.101

Observed Value:

3306/tcp open mysql

Expected Value:

Database service should not be publicly exposed
Main Attributes
Evidence ID
Finding ID
Source
Command or check
Observed value
Expected value
Evidence type
Collected timestamp
Purpose

Evidence provides traceability between a security finding and the technical information that produced or supports it.

11. Remediation

Remediation tracks the process of addressing a security finding.

Main Attributes
Remediation ID
Finding ID
Recommendation
Assigned user
Priority
Status
Due date
Started timestamp
Completed timestamp
Verification timestamp
Remediation Lifecycle
OPEN
  ↓
ASSIGNED
  ↓
IN_PROGRESS
  ↓
REMEDIATED
  ↓
VERIFIED
  ↓
CLOSED

A finding may have multiple remediation records over its lifecycle.

12. Data Flow

The overall SecureAssure security assessment workflow is:

                    ┌──────────────┐
                    │    ASSET     │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   SERVICE    │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │     SCAN     │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   FINDING    │
                    └──────┬───────┘
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
      ┌────────────┐ ┌────────────┐ ┌────────────┐
      │    RISK    │ │  EVIDENCE  │ │ REMEDIATION│
      │ ASSESSMENT │ │            │ │            │
      └─────┬──────┘ └────────────┘ └─────┬──────┘
            │                             │
            ▼                             ▼
      ┌────────────┐               ┌────────────┐
      │    CIA     │               │VERIFICATION│
      │   IMPACT   │               └────────────┘
      └──────┬─────┘
             │
             ▼
      ┌──────────────────┐
      │ SECURITY CONTROL │
      └──────────────────┘
Security Assessment Flow
Authorized Target
       ↓
Asset Discovery
       ↓
Service Discovery
       ↓
Security Assessment
       ↓
Finding Creation
       ↓
CIA Impact Analysis
       ↓
Risk Calculation
       ↓
Security Control Mapping
       ↓
Remediation
       ↓
Verification
       ↓
Finding Closure
Data Model Design Principles

The SecureAssure data model follows these principles:

Keep security findings separate from risk assessments.
Preserve technical evidence for auditability.
Support CIA-based impact analysis.
Support many-to-many mapping between findings and controls.
Track remediation as a lifecycle.
Maintain timestamps for security events.
Avoid storing secrets or sensitive credentials in the database.
Keep scanner-specific implementation details outside the core data model where possible.
Design the schema so additional scanners can be integrated later.
Support future migration from SQLite to a production relational database.
Future Extensions

The initial data model may later be extended with:

Users
Roles
Organizations
Asset groups
Vulnerability identifiers
Security frameworks
Audit records
Compliance assessments
Scheduled scans
Notifications
Risk acceptance
Exception management

---

## 13. Database Schema

This section defines the initial relational database schema for SecureAssure.

The schema is designed for SQLite during development and remains compatible
with migration to PostgreSQL or another production relational database.

### 13.1 assets

Stores security-relevant systems, hosts, devices, applications, and other
assessable resources.

| Column | Type | Nullable | Constraints |
|---|---|---:|---|
| id | Integer | No | Primary Key |
| ip_address | String(45) | Yes | Indexed |
| hostname | String(255) | Yes | Indexed |
| operating_system | String(255) | Yes | |
| asset_type | String(50) | No | |
| criticality | String(20) | No | |
| owner | String(255) | Yes | |
| status | String(30) | No | |
| description | Text | Yes | |
| created_at | DateTime | No | |
| updated_at | DateTime | No | |

### 13.2 services

Stores network services discovered on assets.

| Column | Type | Nullable | Constraints |
|---|---|---:|---|
| id | Integer | No | Primary Key |
| asset_id | Integer | No | Foreign Key → assets.id |
| port | Integer | No | |
| protocol | String(10) | No | |
| service_name | String(100) | Yes | |
| service_version | String(255) | Yes | |
| state | String(30) | No | |
| discovered_at | DateTime | No | |

### 13.3 scans

Stores security discovery and assessment operations.

| Column | Type | Nullable | Constraints |
|---|---|---:|---|
| id | Integer | No | Primary Key |
| scanner | String(50) | No | |
| scan_type | String(50) | No | |
| target | String(255) | No | |
| status | String(30) | No | |
| configuration | Text | Yes | |
| error_message | Text | Yes | |
| started_at | DateTime | Yes | |
| completed_at | DateTime | Yes | |
| created_at | DateTime | No | |

### 13.4 findings

Stores security issues identified during assessments.

| Column | Type | Nullable | Constraints |
|---|---|---:|---|
| id | Integer | No | Primary Key |
| asset_id | Integer | No | Foreign Key → assets.id |
| service_id | Integer | Yes | Foreign Key → services.id |
| scan_id | Integer | Yes | Foreign Key → scans.id |
| title | String(255) | No | |
| description | Text | No | |
| severity | String(20) | No | Indexed |
| status | String(30) | No | Indexed |
| detection_source | String(100) | No | |
| recommendation | Text | Yes | |
| detected_at | DateTime | No | |
| updated_at | DateTime | No | |

### 13.5 risk_assessments

Stores risk calculations and CIA impact assessments for findings.

| Column | Type | Nullable | Constraints |
|---|---|---:|---|
| id | Integer | No | Primary Key |
| finding_id | Integer | No | Foreign Key → findings.id, Unique |
| likelihood | Integer | No | 1–5 |
| impact | Integer | No | 1–5 |
| confidentiality | Integer | No | 1–5 |
| integrity | Integer | No | 1–5 |
| availability | Integer | No | 1–5 |
| risk_score | Integer | No | |
| risk_level | String(20) | No | |
| assessment_method | String(100) | No | |
| assessed_at | DateTime | No | |

Initial risk calculation:

```text
Risk Score = Likelihood × Impact
13.6 security_controls

Stores security controls used to reduce or manage security risk.

Column	Type	Nullable	Constraints
id	Integer	No	Primary Key
control_code	String(50)	No	Unique
name	String(255)	No	
category	String(100)	No	
description	Text	No	
framework	String(100)	Yes	
implementation_status	String(30)	No	
created_at	DateTime	No	
updated_at	DateTime	No	
13.7 finding_controls

Association table for the many-to-many relationship between findings
and security controls.

Column	Type	Nullable	Constraints
finding_id	Integer	No	Foreign Key → findings.id
control_id	Integer	No	Foreign Key → security_controls.id

Primary key:

(finding_id, control_id)
13.8 evidence

Stores technical evidence supporting security findings.

Column	Type	Nullable	Constraints
id	Integer	No	Primary Key
finding_id	Integer	No	Foreign Key → findings.id
source	String(100)	No	
command	Text	Yes	
observed_value	Text	Yes	
expected_value	Text	Yes	
evidence_type	String(50)	No	
collected_at	DateTime	No	
13.9 remediations

Tracks remediation activities associated with findings.

Column	Type	Nullable	Constraints
id	Integer	No	Primary Key
finding_id	Integer	No	Foreign Key → findings.id
recommendation	Text	No	
assigned_to	String(255)	Yes	
priority	String(20)	No	
status	String(30)	No	
due_date	DateTime	Yes	
started_at	DateTime	Yes	
completed_at	DateTime	Yes	
verification_at	DateTime	Yes	
14. Database Relationships

The relational structure is:

assets
  │
  ├──────────────< services
  │
  └──────────────< findings
                       │
                       ├────────────── risk_assessments
                       │
                       ├──────────────< evidence
                       │
                       ├──────────────< remediations
                       │
                       └──────────────< finding_controls >──────── security_controls
                       
scans ────────────────< findings
Relationship Summary
Relationship	Type
Asset → Service	One-to-Many
Asset → Finding	One-to-Many
Scan → Finding	One-to-Many
Service → Finding	One-to-Many
Finding → Risk Assessment	One-to-One
Finding → Evidence	One-to-Many
Finding → Remediation	One-to-Many
Finding → Security Control	Many-to-Many
15. Initial Database Constraints

The initial schema will enforce:

Primary keys on all main entities.
Foreign keys for all entity relationships.
Unique control codes.
One risk assessment per finding.
Composite primary key for finding_controls.
Indexed asset IP addresses.
Indexed hostnames.
Indexed finding severity.
Indexed finding status.
Valid risk values from 1 through 5.
Required timestamps for security events.