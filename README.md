# CloudIntelliGuard

### AI-Driven Cloud Security for Threat Detection, Risk Analysis & Automated Response

CloudIntelliGuard is an AI-driven cloud security system designed to analyze cloud activity, detect suspicious user behavior, identify potential attack paths, assess security risk, and support automated security response.

The system represents cloud activities as a dynamic temporal graph and applies Graph Neural Network (GNN)-based analysis together with behavioral analytics and risk assessment to identify potentially malicious activity.

---

## 🚀 Key Features

- **Data & Pipeline**
  - Upload and validate cloud activity datasets
  - Data preprocessing and normalization
  - Store processed security events in PostgreSQL
  - Generate temporal security graphs
  - Perform automated threat analysis

- **Security Overview**
  - Security posture overview based on processed data
  - User and activity statistics
  - Risk distribution and detected threats
  - Security event monitoring

- **Security Graph**
  - Dynamic representation of users, IP addresses, APIs, resources, and activities
  - Multi-hop relationship analysis
  - Attack-path exploration
  - Graph-based threat analysis

- **Threat Detection**
  - Detect suspicious cloud activities
  - Identify anomalous user behavior
  - Risk-based threat classification
  - Connect detected threats to the investigation workspace

- **User Behavior Analytics**
  - Analyze user activity patterns
  - Compare normal and current behavior
  - Monitor login times, IP addresses, API usage, and activity patterns
  - Identify behavioral deviations

- **Investigation Workspace**
  - User security profile
  - Continuous risk evolution
  - Evidence timeline
  - Suspicious activity explanation
  - Multi-hop attack-path analysis
  - Risk evidence fusion
  - Automated response status
  - Audit trail

- **Automated Response**
  - Risk-based security actions
  - Monitor low-risk activity
  - Alert on medium-risk activity
  - Restrict high-risk activity
  - Block critical-risk activity

- **AI Security Copilot**
  - Assist security investigation
  - Explain suspicious behavior and risk decisions
  - Help analyze security information

- **What-If Risk Simulator**
  - Simulate changes in user behavior
  - Analyze how behavioral changes affect security risk
  - Support security investigation and decision-making

---

## 🔐 Risk Classification

CloudIntelliGuard uses risk thresholds to determine the appropriate security response:

| Risk Level | Score | Response |
|---|---:|---|
| LOW | 0–24 | Monitor |
| MEDIUM | 25–49 | Alert |
| HIGH | 50–74 | Restrict |
| CRITICAL | 75+ | Block |

---

## 🧠 System Architecture

```text
Cloud Activity Dataset
        ↓
Data Validation & Preprocessing
        ↓
PostgreSQL
        ↓
Temporal Security Graph
        ↓
GNN-Based Threat Analysis
        ↓
User Behavior Analytics
        ↓
Risk Assessment
        ↓
Threat Detection
        ↓
Investigation Workspace
        ↓
Automated Response & Audit
```

---

## 🛠️ Technology Stack

### Frontend
- React
- Vite
- JavaScript / JSX
- Tailwind CSS

### Backend
- Python
- FastAPI

### Database
- PostgreSQL

### AI / Machine Learning
- Graph Neural Networks (GNN)
- Behavioral analytics
- Risk assessment
- Graph-based threat analysis

---

## 📁 Project Structure

```text
CloudIntelliGuard/
│
├── backend/
│   ├── ...
│   └── ...
│
├── frontend/
│   ├── src/
│   ├── ...
│   └── ...
│
├── src/
│
├── .env.example
├── .gitignore
├── package.json
├── README.md
└── ...
```

---

## ⚙️ Getting Started

### Prerequisites

Make sure the following are installed:

- Python 3.x
- Node.js
- npm
- PostgreSQL
- Git

### 1. Clone the repository

```bash
git clone https://github.com/deekshanetha10/my-project.git
cd my-project
```

### 2. Configure the environment

Create the required environment configuration using the provided example:

```bash
cp .env.example .env
```

Update the environment variables according to your local PostgreSQL and backend configuration.

### 3. Start the backend

Navigate to the backend directory:

```bash
cd backend
```

Install the required Python dependencies:

```bash
pip install -r requirements.txt
```

Start the FastAPI server using the project's configured entry point.

### 4. Start the frontend

Open another terminal and navigate to the frontend:

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

Open the URL displayed by Vite in your browser.

---

## 📊 Security Workflow

CloudIntelliGuard follows a security analysis workflow:

1. Upload cloud activity data.
2. Validate and preprocess the dataset.
3. Store security events in PostgreSQL.
4. Construct a temporal security graph.
5. Analyze graph relationships using GNN-based methods.
6. Analyze user behavior and activity patterns.
7. Calculate security risk.
8. Detect and classify suspicious activity.
9. Investigate evidence and potential attack paths.
10. Apply the appropriate risk-based response.
11. Record actions in the audit trail.

---

## 🎯 Project Objectives

CloudIntelliGuard aims to:

- Improve visibility into cloud security activity.
- Detect anomalous and potentially malicious behavior.
- Analyze relationships between users, resources, IPs, and APIs.
- Identify multi-hop attack paths.
- Provide explainable security risk assessment.
- Support automated risk-adaptive security responses.
- Assist security analysts during threat investigation.

---

## 🔮 Future Enhancements

Potential future improvements include:

- Integration with additional cloud platforms
- Advanced graph-based attack prediction
- Continuous real-time event streaming
- Improved explainable AI capabilities
- Additional security intelligence sources
- Advanced security analyst collaboration features

---

## 📌 Project Status

CloudIntelliGuard is an academic/final-year project focused on AI-driven cloud security, behavioral threat detection, graph-based security analysis, and automated risk-adaptive response.

---

## 👩‍💻 Author

**Chippa Deekshitha**

B.Tech – Information Technology

GitHub: [@deekshanetha10](https://github.com/deekshanetha10)

---

## 📄 License

This project is developed for academic and research purposes.