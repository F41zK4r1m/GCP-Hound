# 🔐 GCP-Hound - Google Cloud Security Attack Path Discovery Tool

<div align="center">

**🚀 Advanced GCP Attack Surface Analysis & Privilege Escalation Discovery**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![BloodHound Compatible](https://img.shields.io/badge/BloodHound-8.0+-red.svg)](https://bloodhound.specterops.io/)

*Visualize complex GCP attack paths with the power of BloodHound*

</div>

---

## 🎯 Overview

**GCP-Hound** is a cutting-edge **attack path discovery and privilege escalation analysis tool** for Google Cloud Platform environments. Built on the BloodHound OpenGraph framework, it transforms complex GCP IAM relationships into interactive attack graphs, empowering security teams to identify and remediate critical cloud vulnerabilities.

> Example graphs:

<img width="1905" height="863" alt="image" src="https://github.com/user-attachments/assets/ecc54d6a-524a-4668-8163-1c716a0ee9bb" />

<img width="1887" height="953" alt="image" src="https://github.com/user-attachments/assets/b1cab70b-9bda-47bb-af2b-e5c1625a09a7" />

<img width="1923" height="778" alt="image" src="https://github.com/user-attachments/assets/fa8c187a-b171-48f4-b2d9-d77292c76136" />

<img width="1436" height="811" alt="image" src="https://github.com/user-attachments/assets/fddd41e3-4125-4869-b8d2-f475751f0cb4" />



### 🔥 What Makes GCP-Hound Special

- **🎨 Beautiful Visualizations**: Custom GCP icons and professional graph layouts in BloodHound
- **🚨 Real Vulnerability Detection**: Discovers actual privilege escalation paths and misconfigurations  
- **⚡ Lightning Fast**: Multi-threaded enumeration across GCP services

---

## 🛡️ Core Security Capabilities

### **Identity & Access Analysis**
- 🔐 **Service Account Enumeration** - Discover all service accounts and their permissions
- 👥 **User & Group Mapping** - Map user identities and group memberships  
- 🔑 **Service Account Key Analysis** - Detect dangerous key creation permissions
- 🎭 **Impersonation Detection** - Find service account impersonation chains

### **Resource Discovery**
- 📁 **Project Enumeration** - Discover all accessible GCP projects
- 🗄️ **Cloud Storage Analysis** - Find buckets and analyze access permissions
- 📊 **BigQuery Discovery** - Map datasets and table access patterns

### **Attack Path Analysis** 
- 🚨 **CRITICAL Privilege Escalations** - Service account key creation vulnerabilities
- ⚠️ **HIGH-Risk Impersonations** - Cross-account privilege escalation paths  
- 📈 **Risk Scoring** - CVSS-inspired risk ratings for each finding
- 🎯 **Attack Chains** - Multi-hop privilege escalation sequences

---

## 🚀 Quick Start

### **1. Setup Python Environment**

## Clone repository

```
git clone https://github.com/F41zK4r1m/GCP-Hound.git
cd GCP-Hound
```

## Create and activate virtual environment

```
python3 -m venv .venv
source .venv/bin/activate # On Windows: .venv\Scripts\activate
```

## Install dependencies

```
pip install -r requirements.txt
```

### **2. Configure GCP Authentication**

## Option A: Service Account Key

```
export GOOGLE_APPLICATION_CREDENTIALS="path/to/service-account-key.json"
```

## Option B: OAuth2 (Interactive)

```
gcloud auth application-default login
```


## Option C: Using gcloud CLI

```
gcloud auth login
```

### **3. Run GCP-Hound Analysis**

```
python3 gcp-hound.py
```


### **4. Import to BloodHound**
- Generated file: `./output/gcp-bhopengraph.json`
- Upload via BloodHound UI file import
- Explore interactive attack graphs

---

## 📊 Analysis Phases

GCP-Hound performs comprehensive security analysis in **6 phases**:

### **Phase 1: Authentication & Project Discovery** 
- Validates GCP credentials and discovers accessible projects

### **Phase 2: Identity Enumeration**
- Service account discovery, user enumeration, IAM analysis

### **Phase 3: Resource Discovery**
- Cloud Storage, BigQuery, and compute resource identification

### **Phase 4: Permission Analysis**
- Service account key access analysis and IAM permission mapping

### **Phase 5: Privilege Escalation Detection**
- Critical privilege escalation paths and attack chain synthesis

### **Phase 6: BloodHound Integration**
- OpenGraph format export and custom GCP icon registration

---

## 🎨 BloodHound Visualization

### **Custom GCP Node Types**
- 🔐 **Service Accounts** - Green user-secret icons
- 📁 **Projects** - Red folder-open icons  
- 🗄️ **Storage Buckets** - Blue database icons
- 📊 **BigQuery Datasets** - Purple chart-bar icons
- 👤 **Users** - Brown user-circle icons

### **Attack Relationship Types**
- **CanCreateKeys** - CRITICAL service account key creation
- **CanImpersonate** - HIGH-risk service account impersonation
- **CanListKeys** - MEDIUM key enumeration capabilities
- **BelongsTo** - Resource ownership relationships

### **Useful BloodHound Queries**

**Show all critical attack paths:**

```
MATCH (n)-[r]->(m)
WHERE r.riskLevel = "CRITICAL"
RETURN n, r, m
```

**Find service account privilege escalations:**

```
MATCH (n)-[r:CanCreateKeys]->(m)
RETURN n, r, m
```


**Show complete GCP attack surface:**


```
MATCH (n:GCPResource)-[r]->(m:GCPResource)
RETURN n, r, m LIMIT 100
```


---

## 📈 Sample Output

```
[*] Phase 1: Authentication & Project Discovery
✅ Authenticated as: user@example-project.iam.gserviceaccount.com
✅ Discovered 1 accessible projects

[*] Phase 2: Identity Enumeration
✅ Found 7 service accounts
✅ Discovered 2 users, 1 groups

[*] Phase 3: Resource Discovery
✅ Enumerated 1 storage buckets
✅ Found 1 BigQuery datasets

[*] Phase 4: Service Account Key Access Analysis
🚨 CRITICAL: Can create keys for 7 service accounts - PRIVILEGE ESCALATION POSSIBLE

[*] Phase 5: Comprehensive Privilege Escalation Analysis
💀 CRITICAL escalation targets: 7
⚠️ HIGH-risk escalation targets: 7

[*] Phase 6: BloodHound Integration
✅ Generated OpenGraph JSON with custom GCP icons
✅ FINAL RESULT: 10 nodes, 24 edges
📁 File: ./output/gcp-bhopengraph.json
```


---

## 🔒 Security & Ethics

**⚠️ Only use on GCP environments you own or have explicit authorization to test**

---

## 🛠️ Development & Contribution

### **Project Structure**

```
gcp-hound/
├── gcp-hound.py # Main enumeration script
├── bloodhound/
│ ├── json_builder.py # BloodHound JSON export
│ └── icon_registry.py # Custom icon registration
├── modules/
│ ├── gcp_enum.py # GCP resource enumeration
│ ├── iam_analysis.py # IAM permission analysis
│ └── privilege_escalation.py # Attack path detection
└── requirements.txt # Python dependencies
```


### **Future Roadmap**
- 🚀 **Compute Engine enumeration** (VMs, instance groups, images)
- 🌐 **Networking analysis** (VPCs, subnets, firewall rules)
- 🔔 **Pub/Sub and Cloud Functions** discovery
- 🎛️ **GKE cluster enumeration** and RBAC analysis
- 📊 **Compliance reporting** (CIS, NIST frameworks)
- 🔄 **CI/CD integration** for continuous monitoring

---

## 📞 Support & Contact

- 🐛 **Issues**: [GitHub Issues](https://github.com/F41zK4r1m/GCP-Hound/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/F41zK4r1m/GCP-Hound/discussions)

---

<div align="center">

**🎯 Deploy GCP security visibility and stay one step ahead of adversaries with GCP-Hound!**

*Made with ❤️ by the security community*

</div>
