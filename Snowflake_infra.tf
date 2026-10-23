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
#
#    PRD is the source of truth. Non-prod databases carry the same schema set
#    and are refreshed from PRD by the clone script in tpt_build.sql.
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
# 3.1 Core schemas (original resource addresses retained for state stability)
#------------------------------------------------------------------------------
resource "snowflake_schema" "prod001_analytics_schema" {
  database = snowflake_database.prod01_db.name
  name     = "DWA_ANA"
}

resource "snowflake_schema" "prod01_ingestion_schema" {
  database = snowflake_database.prod01_db.name
  name     = "DWA_ING"
}

resource "snowflake_schema" "uat01_analytics_schema" {
  database = snowflake_database.uat01_db.name
  name     = "DWA_ANA"
}

resource "snowflake_schema" "uat01_ingestion_schema" {
  database = snowflake_database.uat01_db.name
  name     = "DWA_ING"
}

resource "snowflake_schema" "tst01_analytics_schema" {
  database = snowflake_database.tst01_db.name
  name     = "DWA_ANA"
}

resource "snowflake_schema" "tst01_ingestion_schema" {
  database = snowflake_database.tst01_db.name
  name     = "DWA_ING"
}

resource "snowflake_schema" "dev_db_analytics_schema" {
  database = snowflake_database.dev_db.name
  name     = "DWA_ANA"
}

resource "snowflake_schema" "dev_db_ingestion_schema" {
  database = snowflake_database.dev_db.name
  name     = "DWA_ING"
}

resource "snowflake_schema" "dev_db_admn_schema" {
  database = snowflake_database.dev_db.name
  name     = "DWA_ADM"
}

resource "snowflake_schema" "admn_analytics_schema" {
  database = snowflake_database.admn_db.name
  name     = "DWA_ANA"
}

resource "snowflake_schema" "admn_ingestion_schema" {
  database = snowflake_database.admn_db.name
  name     = "DWA_ING"
}

resource "snowflake_schema" "admn_schema" {
  database = snowflake_database.admn_db.name
  name     = "DWA_ADM"
}

resource "snowflake_schema" "admn_gov_schema" {
  database = snowflake_database.admn_db.name
  name     = "DWA_GOV"
}

#------------------------------------------------------------------------------
# 3.2 Additional schemas (same set in PRD and every non-prod database)
#------------------------------------------------------------------------------
locals {
  env_databases = {
    PRD = snowflake_database.prod01_db.name
    PPD = snowflake_database.uat01_db.name
    TST = snowflake_database.tst01_db.name
    DEV = snowflake_database.dev_db.name
    STG = snowflake_database.stg_db.name
  }

  extra_schema_names = ["DWA_LOG", "DWA_CLM", "DWA_DBT"]

  extra_schemas = merge(
    {
      for pair in setproduct(keys(local.env_databases), local.extra_schema_names) :
      "${pair[0]}_${pair[1]}" => { database = local.env_databases[pair[0]], name = pair[1] }
    },
    # STG has no core schemas above
    {
      STG_DWA_ANA = { database = snowflake_database.stg_db.name, name = "DWA_ANA" }
      STG_DWA_ING = { database = snowflake_database.stg_db.name, name = "DWA_ING" }
    }
  )
}

resource "snowflake_schema" "env_schema" {
  for_each = local.extra_schemas
  database = each.value.database
  name     = each.value.name
}


###############################################################################
# 4. INTERNAL STAGES  (directory table enabled, CSV with header row)
#    Recreated by `terraform apply` after each non-prod clone refresh.
###############################################################################

resource "snowflake_stage_internal" "stg_prd" {
  name     = "STG_PRD"
  database = snowflake_database.prod01_db.name
  schema   = snowflake_schema.prod01_ingestion_schema.name
  comment  = "Internal stage managed by Terraform"

  directory {
    enable = true
  }

  file_format {
    csv {
      field_delimiter = ","
      skip_header     = 1
    }
  }
}

resource "snowflake_stage_internal" "stg_ppd" {
  name     = "STG_PPD"
  database = snowflake_database.uat01_db.name
  schema   = snowflake_schema.uat01_ingestion_schema.name
  comment  = "Internal stage managed by Terraform"

  directory {
    enable = true
  }

  file_format {
    csv {
      field_delimiter = ","
      skip_header     = 1
    }
  }
}

resource "snowflake_stage_internal" "stg_tst" {
  name     = "STG_TST"
  database = snowflake_database.tst01_db.name
  schema   = snowflake_schema.tst01_ingestion_schema.name
  comment  = "Internal stage managed by Terraform"

  directory {
    enable = true
  }

  file_format {
    csv {
      field_delimiter = ","
      skip_header     = 1
    }
  }
}

# TODO: Named STG_ADM but created in KPDWDEV - confirm target database.
resource "snowflake_stage_internal" "stg_adm" {
  name     = "STG_ADM"
  database = snowflake_database.dev_db.name
  schema   = snowflake_schema.dev_db_ingestion_schema.name
  comment  = "Internal stage managed by Terraform"

  directory {
    enable = true
  }

  file_format {
    csv {
      field_delimiter = ","
      skip_header     = 1
    }
  }
}


###############################################################################
# 5. ACCOUNT ROLES, HIERARCHY & WAREHOUSE GRANTS
#    Per-schema RO/RW/SVC roles are created by SP_SETUP_DATABASE_RBAC.
#    NONPROD_* roles never receive PRD privileges.
###############################################################################

resource "snowflake_account_role" "role_nonprod_all" {
  provider = snowflake.securityadmin
  name     = "RL_NONPROD_ALL_READONLY"
  comment  = "Non-prod read-only role (no PRD access)"
}

resource "snowflake_account_role" "dss_etl_role" {
  provider = snowflake.securityadmin
  name     = "RL_NONPROD_DSS_ETL"
  comment  = "Non-prod ETL developer role (no PRD access)"
}

resource "snowflake_account_role" "svc_etl_role" {
  provider = snowflake.securityadmin
  name     = "SVC_ROLE_ETL"
  comment  = "Non-prod ETL service account role (no PRD access)"
}

resource "snowflake_account_role" "purview_role" {
  provider = snowflake.securityadmin
  name     = "RL_PURVIEW_READER"
  comment  = "Microsoft Purview metadata reader role"
}

resource "snowflake_account_role" "tag_admin_role" {
  provider = snowflake.securityadmin
  name     = "RL_TAG_ADMIN"
  comment  = "Tag administration role (KPDWADM.DWA_GOV only)"
}

resource "snowflake_account_role" "git_admin_role" {
  provider = snowflake.securityadmin
  name     = "RL_GIT_ADMIN"
  comment  = "Git integration administration role"
}

# Roll every custom role up to SYSADMIN
locals {
  custom_roles = {
    nonprod_all = snowflake_account_role.role_nonprod_all.name
    dss_etl     = snowflake_account_role.dss_etl_role.name
    svc_etl     = snowflake_account_role.svc_etl_role.name
    purview     = snowflake_account_role.purview_role.name
    tag_admin   = snowflake_account_role.tag_admin_role.name
    git_admin   = snowflake_account_role.git_admin_role.name
  }
}

resource "snowflake_grant_account_role" "custom_to_sysadmin" {
  provider         = snowflake.securityadmin
  for_each         = local.custom_roles
  role_name        = each.value
  parent_role_name = "SYSADMIN"
}

# Warehouse usage - least privilege
locals {
  warehouse_grants = {
    nonprod_all_oper = { role = snowflake_account_role.role_nonprod_all.name, wh = snowflake_warehouse.de_wh05.name }
    dss_etl_xsm      = { role = snowflake_account_role.dss_etl_role.name, wh = snowflake_warehouse.de_wh01.name }
    dss_etl_sml      = { role = snowflake_account_role.dss_etl_role.name, wh = snowflake_warehouse.de_wh02.name }
    dss_etl_dbt      = { role = snowflake_account_role.dss_etl_role.name, wh = snowflake_warehouse.dbt_wh01.name }
    svc_etl_xsm      = { role = snowflake_account_role.svc_etl_role.name, wh = snowflake_warehouse.de_wh01.name }
    svc_etl_sml      = { role = snowflake_account_role.svc_etl_role.name, wh = snowflake_warehouse.de_wh02.name }
    svc_etl_med      = { role = snowflake_account_role.svc_etl_role.name, wh = snowflake_warehouse.de_wh03.name }
    svc_etl_lrg      = { role = snowflake_account_role.svc_etl_role.name, wh = snowflake_warehouse.de_wh04.name }
    svc_etl_dbt      = { role = snowflake_account_role.svc_etl_role.name, wh = snowflake_warehouse.dbt_wh01.name }
    purview_oper     = { role = snowflake_account_role.purview_role.name, wh = snowflake_warehouse.de_wh05.name }
  }
}

resource "snowflake_grant_privileges_to_account_role" "warehouse_usage" {
  provider          = snowflake.securityadmin
  for_each          = local.warehouse_grants
  account_role_name = each.value.role
  privileges        = ["USAGE"]

  on_account_object {
    object_type = "WAREHOUSE"
    object_name = each.value.wh
  }
}


