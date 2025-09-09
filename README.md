# ☁️ GCP-Hound - Google Cloud Security Attack Path Discovery Tool

<div align="center">

**🚀 Advanced GCP Attack Surface Analysis & Privilege Escalation Discovery**

<img width="238" height="197" alt="image" src="https://github.com/user-attachments/assets/cad67dc4-de8d-4c9e-abcf-af2742d0224d" />


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![BloodHound Compatible](https://img.shields.io/badge/BloodHound-8.0+-red.svg)](https://bloodhound.specterops.io/)

*Visualize complex GCP attack paths with the power of BloodHound*

</div>

---

## 🎯 Overview

**GCP-Hound** is an open-source security enumeration and privilege escalation discovery tool designed specifically for Google Cloud Platform environments. Built to integrate seamlessly with **BloodHound's OpenGraph** framework, it transforms complex GCP IAM relationships into interactive attack graphs.

### 🎯 Project Background

This project began as a personal learning journey into GCP-focused penetration testing and red teaming techniques. While GCP-Hound already provides substantial reconnaissance and analysis capabilities, it remains a work-in-progress tool that will continue evolving with new features and improvements over time.

The tool may currently lack many advanced features, but I'm committed to gradually improving and expanding its capabilities based on community feedback and real-world testing scenarios.

---

## ✨ Key Features

### **🔥 Current Capabilities (Implemented)**
- **🔍 Comprehensive GCP Enumeration** - Projects, service accounts, storage buckets, BigQuery datasets
- **👥 Identity & Access Analysis** - Users, groups, and Google Workspace integration  
- **🚨 Advanced Privilege Escalation Detection** - Service account key analysis and impersonation chains
- **☸️ Container Security** - GKE cluster enumeration and Kubernetes RBAC analysis
- **🔐 Secret Management** - Secret Manager enumeration and access analysis
- **💻 Compute Infrastructure** - VM instances, disks, and compute resource discovery
- **🌐 Network Mapping** - VPC, subnets, firewall rules, and network topology
- **🏢 Organizational Structure** - Folder hierarchy and project organization mapping
- **🎨 Professional BloodHound Integration** - Custom GCP icons and OpenGraph compatibility

### **🚧 Future Enhancements (Planned)**
- [ ] **Pub/Sub Enumeration** - Topics, subscriptions, and messaging analysis
- [ ] **Cloud Functions Deep Analysis** - Serverless function security assessment

### 🚨 **Advanced Privilege Escalation Detection**
- **Service Account Key Analysis** - Detect dangerous key creation/management permissions
- **Impersonation Chain Discovery** - Map cross-account privilege escalation paths
- **Risk-Based Scoring** - CRITICAL, HIGH, MEDIUM risk classifications (Still working on it to make it perfect)
- **Multi-Hop Attack Chains** - Complex privilege escalation sequences

### 🎨 **Professional BloodHound Integration**
- **Custom GCP Icons** - Beautiful, distinct icons for each GCP resource type
- **OpenGraph Compatibility** - Full BloodHound v8.0+ support
- **Interactive Visualizations** - Explore attack paths through BloodHound's interface

## 🚀 Installation & Setup

### **Prerequisites**
- Python 3.9 or higher
- Access to target GCP environment(s)
- BloodHound (8.0 or higher) Community Edition or Enterprise (optional, for visualization)

### **1. Clone Repository**

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

### **3. BloodHound Integration Setup (Optional but Recommended)**

To enable custom GCP icons and node types in BloodHound:

```
python3 register_gcp_nodes.py -s http://localhost:8080 -u admin -p password
```

This step is required only once per BloodHound instance and enables:
- ✅ Custom GCP icons in the BloodHound UI  
- ✅ Searchable GCP node types
- ✅ Enhanced visualization experience

---

## 🎮 Usage

### **Basic Analysis**

### **4. Run GCP-Hound Analysis**

```
python3 gcp-hound.py
```

### Verbose output (recommended for first runs)

```
python3 gcp-hound.py -v
```

### Target specific project

```
python3 gcp-hound.py -p my-gcp-project
```

### Debug mode for troubleshooting

```
python3 gcp-hound.py -d
```

### Custom output directory

```
python3 gcp-hound.py -o /path/to/output
```

### Impersonate service account

```
python3 gcp-hound.py -i service@project.iam.gserviceaccount.com
```

### Quiet mode (minimal output)

```
python3 gcp-hound.py -q
```

### **4. Import to BloodHound**
- Generated file: `./output/gcp-bhopengraph.json`
- Upload via BloodHound UI file import
- Explore interactive attack graphs

---

### **Analysis Phases**

GCP-Hound performs analysis in **6 comprehensive phases**:

1. **🔍 Authentication & Project Discovery** - Validate credentials and discover accessible projects
2. **📊 API Capability Assessment** - Determine available GCP APIs and permissions
3. **🗂️ Resource Enumeration** - Discover service accounts, storage, BigQuery, GKE, and compute resources
4. **🔐 Privilege Analysis** - Analyze service account permissions and key access capabilities
5. **🚨 Privilege Escalation Detection** - Identify critical attack paths and escalation opportunities  
6. **📈 BloodHound Export** - Generate OpenGraph JSON with custom GCP visualizations

### **BloodHound Import**

After analysis completes:

1. Locate the generated file: `./output/gcp-bhopengraph.json`
2. Open BloodHound web interface
3. Navigate to "Data Collection" → "File Ingest"
4. Upload the JSON file
5. Explore your GCP attack surface!

---

## 📊 Enumerated Resources & Relationships

### **GCP Node Types**

GCP-Hound currently enumerates **23 distinct GCP node types** across the Google Cloud ecosystem:

| Category | Node Types | Description |
|----------|------------|-------------|
| **Identity & Access** | `GCPUser`, `GCPGroup`, `GCPServiceAccount`, `GCPServiceAccountKey` | User identities, groups, and service accounts |
| **Organization** | `GCPProject`, `GCPFolder`, `GCPOrganization` | Organizational structure and hierarchy |
| **Compute & Containers** | `GCPInstance`, `GCPCluster`, `GCPNode` | Compute Engine VMs and GKE clusters |
| **Storage & Data** | `GCPBucket`, `GCPDataset`, `GCPSecret`, `GCPFunction` | Storage, BigQuery, and Secret Manager |
| **Networking** | `GCPNetwork`, `GCPVPC`, `GCPSubnet`, `GCPFirewall`, `GCPRole` | Network infrastructure and security |
| **Additional Services** | `GCPPubSubTopic`, `GCPCloudFunction`, `GCPKMSKey` | Messaging, serverless, and encryption |

*Note: While `GCPPubSubTopic` is registered as a node type, **Pub/Sub enumeration is not yet implemented** in the current collectors.*


### **Attack Relationship Types**

| Edge Type | Risk Level | Description |
|-----------|------------|-------------|
| `CanCreateKeys` | **CRITICAL** | Ability to create service account keys (direct privilege escalation) |
| `CanImpersonate` | **HIGH** | Service account impersonation capabilities |
| `CanListKeys` | **MEDIUM** | Ability to enumerate existing service account keys |
| `ContainsServiceAccount` | **LOW** | Project ownership of service accounts |
| `OwnsStorageBucket` | **MEDIUM** | Resource ownership relationships |
| `BelongsTo` | **INFO** | Resource-to-project associations |

### **Understanding Attack Paths**

GCP-Hound focuses on discovering privilege escalation opportunities through:

- **Service Account Key Creation** → Direct credential access → Full service account privileges
- **Cross-Project Impersonation** → Privilege escalation across GCP projects  
- **Storage Bucket Access** → Data exfiltration or modification capabilities
- **BigQuery Data Access** → Sensitive data exposure and analysis

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

<img width="1045" height="679" alt="image" src="https://github.com/user-attachments/assets/9de82f6e-63da-4576-ae5c-9b0bb49a841d" />

**Show complete GCP attack surface:**


```
MATCH (n:GCPResource)-[r]->(m:GCPResource)
RETURN n, r, m LIMIT 100
```

<img width="1776" height="669" alt="image" src="https://github.com/user-attachments/assets/4389b377-567f-4d2f-8f53-80babc19cee5" />


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

Contributions are welcome! This project is a learning exercise, and I appreciate:

- Bug reports and feature requests
- Code contributions and improvements
- Documentation enhancements
- Testing in different GCP environments

Please feel free to:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 🔮 Roadmap & TODO

### **Immediate Priorities**
- [ ] **Work on making all objects searchable from BloodHound UI** - Fix search functionality for GCP nodes
- [ ] **Work on integrating with AD objects** - Connect GCP identities with Active Directory  
- [ ] **Work on adding more recon features and detailing** - Expand enumeration capabilities

### **Upcoming Features**
- [ ] **Pub/Sub & Messaging** - Topics, subscriptions, and Cloud Tasks enumeration
- [ ] **Advanced Serverless** - Cloud Functions, Cloud Run, and App Engine analysis
- [ ] **Enhanced Networking** - Load balancers, CDN, and interconnect discovery
---

## 🛠️ Project Structure

```
GCP-Hound/
├── bloodhound/
│   ├── __init__.py
│   └── json_builder.py
│
├── collectors/
│   ├── __init__.py
│   ├── bigquery_collector.py
│   ├── bucket_collector.py
│   ├── cloudfunctions_collector.py
│   ├── cloudsql_collector.py
│   ├── compute_collector.py
│   ├── discovery.py
│   ├── edge_builder.py
│   ├── folder_collector.py
│   ├── gke_collector.py
│   ├── iam_collector.py
│   ├── org_collector.py
│   ├── privesc_analyzer.py
│   ├── project_collector.py
│   ├── pubsub_collector.py
│   ├── sa_key_analyzer.py
│   ├── secret_collector.py
│   ├── service_account_collector.py
│   ├── user_collector.py
│   ├── users_groups_collector.py
│   └── util.py
│
├── utils/
│   └── auth.py
│
├── .gitignore
├── LICENSE
├── README.md
├── gcp-hound.py
├── gcp-model.json
├── register_gcp_nodes.py
└── requirements.txt
```

---

## 📞 Support & Contact

- 🐛 **Issues**: [GitHub Issues](https://github.com/F41zK4r1m/GCP-Hound/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/F41zK4r1m/GCP-Hound/discussions)

---

<div align="center">

**🎯 Enhance your GCP security posture with GCP-Hound!**

*Built as a learning project for the cybersecurity community*

</div>
