# Snowflake Infrastructure as Code (IaC) & Automation Blueprint

Automated Snowflake deployment framework utilizing Terraform and SQL to enforce active FinOps resource monitoring, warehouse right-sizing, and credit optimization.

## 📌 Architecture & Project Overview
This repository provides a production-grade blueprint for managing a complete Snowflake Data Cloud ecosystem using a localized development workflow. It separates account-level core infrastructure from logical database object configurations.

* **Account Architecture (`Snowflake_Infrastructure.tf`)**: Automates the provisioning of Virtual Warehouses, custom security Roles, Administrative Users, and FinOps Resource Monitors.
* **Database Objects (`Snowflake_Database_Objects.sql`)**: Manages the underlying structural schemas, tables, secure views, data masking policies, and access grants inside the Snowflake environment.

---

## 🛠️ Tech Stack & Requirements
* **Snowflake Data Cloud** (Enterprise Edition trial or higher recommended)
* **Terraform CLI** (v1.5.0+)
* **Snowflake SQL CLI / SnowSQL** (or any preferred database ideation/GUI interface)
* **Local Terminal** (bash/zsh or PowerShell)

---

## 🚀 Local Deployment Guide (CLI Workflow)

### Step 1: Secure Your Local Environment Variables
Before running the deployment scripts, isolate your authentication parameters within your terminal session. Replace the placeholders with your unique credentials.

```bash
# Set your Snowflake Account Identifier (e.g., orgname-accountname)
export SNOWFLAKE_ACCOUNT="your_account_identifier"

# Set administrative deployment credentials
export SNOWFLAKE_USER="ADMIN_USER"
export SNOWFLAKE_PASSWORD="YourSecurePassword123!"
export SNOWFLAKE_ROLE="ACCOUNTADMIN"
export SNOWFLAKE_WAREHOUSE="COMPUTE_WH"
```

### Step 2: Initialize & Apply Infrastructure via Terraform
Navigate to your project root to initialize the Snowflake Terraform provider and run your structural configuration execution plan.

```bash
# Initialize the local working directory and download provider plug-ins
terraform init

# Review the structural footprint before applying infrastructure modifications
terraform plan

# Execute the deployment to build Warehouses, Roles, and Monitors
terraform apply -auto-approve
```

### Step 3: Run Database Object DDL/DML Migrations
Once the core environment and security roles are active, apply your data structures. If utilizing SnowSQL via your local terminal, run the following command to deploy schemas, tables, and access controls:

```bash
snowsql -a \$SNOWFLAKE_ACCOUNT \
        -u \$SNOWFLAKE_USER \
        -r SYSADMIN \
        -w COMPUTE_WH \
        -f ./Snowflake_Database_Objects.sql
```

---

## 💰 FinOps & Security Implementations
* **Active Credit Caps:** Automated account-level and warehouse-level Resource Monitors configured via Terraform to immediately suspend compute resources if spending thresholds are breached.
* **Right-Sized Auto-Suspend:** Warehouses are tailored with programmatic auto-suspend limits (e.g., 60 seconds) to prevent run-away background compute overhead.
* **Least Privilege Security:** Implements a tailored functional and access-based RBAC hierarchy to ensure developers, analysts, and administrative service layers hold minimal required access profiles.
