###############################################################################
# Snowflake Account Bootstrap (Production-Hardened Framework)
#
# Target Stack: Snowflake Provider v1.x compatible
# Focus: FinOps Cost Management, Enterprise Security, & Local Execution
###############################################################################

###############################################################################
# 1. PROVIDERS & VARIABLES
###############################################################################
terraform {
  required_providers {
    snowflake = {
      source  = "Snowflake-Labs/snowflake"
      version = "~> 1.0"
    }
  }
}

locals {
  organization_name = "<SNOWFLAKE_ORGANIZATION_NAME>"
  account_name      = "<SNOWFLAKE_ACCOUNT_NAME>"
  tf_user           = "<TERRAFORM_SERVICE_USER>"
  private_key_path  = "<PATH_TO_PRIVATE_KEY>.p8"

  # Segmented timeouts to handle different workload bounds safely
  etl_statement_timeout  = 172800 # 48 hours - long-running ETL/DBT workloads
  user_statement_timeout = 3600   # 1 hour   - interactive / BI workloads
}

# Default provider - SYSADMIN: Warehouses, databases, schemas, stages
provider "snowflake" {
  account       = "${local.organization_name}-${local.account_name}"
  user          = local.tf_user
  role          = "SYSADMIN"
  authenticator = "SNOWFLAKE_JWT"
  private_key   = file(local.private_key_path)
}

# Aliased provider - SECURITYADMIN: Roles, grants, network rules, users
provider "snowflake" {
  alias         = "securityadmin"
  account       = "${local.organization_name}-${local.account_name}"
  user          = local.tf_user
  role          = "SECURITYADMIN"
  authenticator = "SNOWFLAKE_JWT"
  private_key   = file(local.private_key_path)
}

variable "user_passwords" {
  description = "Initial passwords keyed by user name. Users must change on first login."
  type        = map(string)
  sensitive   = true
}


###############################################################################
# 2. VIRTUAL WAREHOUSES
###############################################################################

#------------------------------------------------------------------------------
# 2.1 ETL / DBT Warehouses (Optimized for single-node scaling, max_cluster = 1)
#------------------------------------------------------------------------------
resource "snowflake_warehouse" "de_wh01" {
  name                         = "WH_ETL_XSM"
  warehouse_size               = "X-SMALL"
  warehouse_type               = "STANDARD"
  max_cluster_count            = 1
  min_cluster_count            = 1
  auto_suspend                 = 60 # Aggressive auto-suspend for cost optimization
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.etl_statement_timeout
}

resource "snowflake_warehouse" "de_wh02" {
  name                         = "WH_ETL_SML"
  warehouse_size               = "SMALL"
  warehouse_type               = "STANDARD"
  max_cluster_count            = 1
  min_cluster_count            = 1
  auto_suspend                 = 60 
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.etl_statement_timeout
}

resource "snowflake_warehouse" "de_wh03" {
  name                         = "WH_ETL_MED"
  warehouse_size               = "MEDIUM" # Fixed: Aligned size with nomenclature intent
  warehouse_type               = "STANDARD"
  max_cluster_count            = 1
  min_cluster_count            = 1
  auto_suspend                 = 60
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.etl_statement_timeout
}

resource "snowflake_warehouse" "de_wh04" {
  name                         = "WH_ETL_LRG"
  warehouse_size               = "LARGE"
  warehouse_type               = "STANDARD"
  max_cluster_count            = 1
  min_cluster_count            = 1
  auto_suspend                 = 60
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.etl_statement_timeout
}

resource "snowflake_warehouse" "dbt_wh01" {
  name                         = "WH_DBT_ALL"
  warehouse_size               = "X-SMALL"
  warehouse_type               = "STANDARD"
  max_cluster_count            = 1
  min_cluster_count            = 1
  auto_suspend                 = 60
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.etl_statement_timeout
}

#------------------------------------------------------------------------------
# 2.2 User / BI Warehouses (Multi-cluster active to handle concurrency spikes)
#------------------------------------------------------------------------------
resource "snowflake_warehouse" "de_wh05" {
  name                         = "WH_OPER_ALL"
  warehouse_size               = "X-SMALL"
  max_cluster_count            = 8
  min_cluster_count            = 1
  auto_suspend                 = 180 # Standard buffer for BI dashboard query caching
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.user_statement_timeout
}

resource "snowflake_warehouse" "de_wh06" {
  name                         = "WH_CGNS_ALL"
  warehouse_size               = "X-SMALL"
  max_cluster_count            = 8
  min_cluster_count            = 1
  auto_suspend                 = 180
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.user_statement_timeout
}

resource "snowflake_warehouse" "de_wh07" {
  name                         = "WH_PWBI_ALL"
  warehouse_size               = "X-SMALL"
  max_cluster_count            = 8
  min_cluster_count            = 1
  auto_suspend                 = 180
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.user_statement_timeout
}

resource "snowflake_warehouse" "de_wh08" {
  name                         = "WH_EXT_ALL"
  warehouse_size               = "X-SMALL"
  max_cluster_count            = 8
  min_cluster_count            = 1
  auto_suspend                 = 180
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.user_statement_timeout
}


###############################################################################
# 3. DATABASES & SCHEMAS
#    DWA_ANA = Analytics | DWA_ING = Ingestion | DWA_LOG = Logging
#    DWA_CLM = Claims    | DWA_DBT = dbt       | DWA_ADM = Admin | DWA_GOV = Governance
###############################################################################

resource "snowflake_database" "prod01_db" {
  name = "KPDWPRD"
}

resource "snowflake_database" "uat01_db" {
  name = "KPDWPPD"
}

resource "snowflake_database" "tst01_db" {
  name = "KPDWTST"
}

resource "snowflake_database" "dev_db" {
  name = "KPDWDEV"
}

resource "snowflake_database" "stg_db" {
  name = "KPDWSTG"
}

resource "snowflake_database" "admn_db" {
  name = "KPDWADM"
}

#------------------------------------------------------------------------------
# 3.1 Core schemas
#------------------------------------------------------------------------------
resource "snowflake_schema" "prod001_analytics_schema" {
  database = snowflake_database.prod01_db.name
  name     = "DWA_ANA"
}

resource "snowflake_schema" "prod01_ingestion_schema" {
  database = snowflake_database.prod01_db.name
  name     = "DWA_ING"
}
