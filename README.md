# Threat Hunting & Security Monitoring Platform

A full-stack cybersecurity platform for detecting, investigating, and managing security threats using rule-based threat hunting, OpenSearch, PostgreSQL, FastAPI, and a modern React frontend.

The platform demonstrates an end-to-end security monitoring workflow:

**Security Events → OpenSearch → Detection Rules → Alerts → Incidents → Investigation → Threat Intelligence**

---

## 🚀 Live Demo

### 🌐 Live Application
https://threat-hunting-security-monitoring.vercel.app/

### ⚙️ Backend API Health
https://threat-hunting-security-monitoring.onrender.com/health

### 🔔 Alerts
https://threat-hunting-security-monitoring.vercel.app/alerts

### 🚨 Incidents
https://threat-hunting-security-monitoring.vercel.app/incidents

---

## 📌 Project Overview

The Threat Hunting & Security Monitoring Platform is designed to simulate the workflow of a security operations environment.

It allows security analysts to:

- Monitor security alerts
- Investigate suspicious activity
- Manage alert and incident lifecycles
- Assign alerts and incidents to analysts
- Add investigation notes
- Perform threat intelligence lookups
- Correlate related alerts into incidents
- Execute YAML-based threat hunting rules
- Detect suspicious Windows authentication activity
- Track investigation activity through audit logs

The project focuses on demonstrating how security telemetry can be transformed into actionable alerts and incidents.

---

## 🏗️ Architecture

```text
                    ┌──────────────────────┐
                    │   Security Events    │
                    │   Windows / Logs     │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │      OpenSearch      │
                    │  Event Storage &     │
                    │      Searching       │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Detection Engine   │
                    │   YAML Hunting Rules │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │        Alerts        │
                    │ Severity / MITRE     │
                    │ Assignment / Status  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │      Incidents       │
                    │ Alert Correlation &  │
                    │ Investigation        │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
       Investigation      Audit Logs      Threat Intel
           Notes                              Lookup
              │                │                │
              └────────────────┼────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │    React Frontend    │
                    │ Dashboard / Alerts / │
                    │ Incidents / Analysis │
                    └──────────────────────┘
