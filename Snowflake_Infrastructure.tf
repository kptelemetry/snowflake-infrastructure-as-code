###############################################################################
# Snowflake Account Bootstrap (template)
#
# Replace every <PLACEHOLDER> before use. Keep real values, keys and
# passwords out of source control (terraform.tfvars / TF_VAR_* env vars).
#
# Terraform is the single owner of account-level infrastructure:
#   1. Providers & variables
#   2. Virtual warehouses
#   3. Databases & schemas
#   4. Internal stages
#   5. Account roles, role hierarchy & warehouse grants
#   6. Network rules & network policies
#   7. Users
#
# Data objects, contacts, the RBAC procedure and the PRD -> non-prod clone
# refresh live in tpt_build.sql. Run `terraform apply` AFTER every non-prod
# clone refresh, since named internal stages are not cloned and must be recreated.
#
# SECRETS: user passwords are supplied through the sensitive variable
#          `user_passwords`, never committed to source control. Provide them via
#          the environment, e.g.
#            export TF_VAR_user_passwords='{"<USER_NAME_1>":"<PASSWORD_1>","<USER_NAME_2>":"<PASSWORD_2>"}'
#          or a git-ignored secrets.auto.tfvars file.
###############################################################################


###############################################################################
# 1. PROVIDERS & VARIABLES
###############################################################################
terraform {
  required_providers {
    snowflake = {
      source  = "snowflakedb/snowflake"
      version = ">= 1.0.0"
    }
  }
}

locals {
  organization_name = "<SNOWFLAKE_ORGANIZATION_NAME>"
  account_name      = "<SNOWFLAKE_ACCOUNT_NAME>"
  tf_user           = "<TERRAFORM_SERVICE_USER>"
  private_key_path  = "<PATH_TO_PRIVATE_KEY>.p8"

  etl_statement_timeout  = 172800 # 48 hours - long-running ETL/DBT workloads
  user_statement_timeout = 3600   # 1 hour   - interactive / BI workloads
}

# Default provider - SYSADMIN: warehouses, databases, schemas, stages
provider "snowflake" {
  organization_name = local.organization_name
  account_name      = local.account_name
  user              = local.tf_user
  role              = "SYSADMIN"
  authenticator     = "SNOWFLAKE_JWT"
  private_key       = file(local.private_key_path)
}

# SECURITYADMIN: roles, grants, network rules/policies, users
provider "snowflake" {
  alias             = "securityadmin"
  organization_name = local.organization_name
  account_name      = local.account_name
  user              = local.tf_user
  role              = "SECURITYADMIN"
  authenticator     = "SNOWFLAKE_JWT"
  private_key       = file(local.private_key_path)
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
# 2.1 ETL / DBT Warehouses
#------------------------------------------------------------------------------
resource "snowflake_warehouse" "de_wh01" {
  name                         = "WH_ETL_XSM"
  warehouse_size               = "X-SMALL"
  min_cluster_count            = 1
  max_cluster_count            = 4
  auto_suspend                 = 60 # seconds
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.etl_statement_timeout
}

resource "snowflake_warehouse" "de_wh02" {
  name                         = "WH_ETL_SML"
  warehouse_size               = "SMALL"
  min_cluster_count            = 1
  max_cluster_count            = 2
  auto_suspend                 = 90
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.etl_statement_timeout
}

# TODO: warehouse_size is "SMALL" but the name implies MEDIUM - confirm intent.
resource "snowflake_warehouse" "de_wh03" {
  name                         = "WH_ETL_MED"
  warehouse_size               = "SMALL"
  min_cluster_count            = 1
  max_cluster_count            = 2
  auto_suspend                 = 90
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.etl_statement_timeout
}

resource "snowflake_warehouse" "de_wh04" {
  name                         = "WH_ETL_LRG"
  warehouse_size               = "LARGE"
  min_cluster_count            = 1
  max_cluster_count            = 2
  auto_suspend                 = 90
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.etl_statement_timeout
}

resource "snowflake_warehouse" "dbt_wh01" {
  name                         = "WH_DBT_ALL"
  warehouse_size               = "X-SMALL"
  min_cluster_count            = 1
  max_cluster_count            = 4
  auto_suspend                 = 60
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.etl_statement_timeout
}

#------------------------------------------------------------------------------
# 2.2 User / BI Warehouses
#------------------------------------------------------------------------------
resource "snowflake_warehouse" "de_wh05" {
  name                         = "WH_OPER_ALL"
  warehouse_size               = "X-SMALL"
  min_cluster_count            = 1
  max_cluster_count            = 8
  auto_suspend                 = 180
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.user_statement_timeout
}

resource "snowflake_warehouse" "de_wh06" {
  name                         = "WH_CGNS_ALL"
  warehouse_size               = "X-SMALL"
  min_cluster_count            = 1
  max_cluster_count            = 8
  auto_suspend                 = 180
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.user_statement_timeout
}

resource "snowflake_warehouse" "de_wh07" {
  name                         = "WH_PWBI_ALL"
  warehouse_size               = "X-SMALL"
  min_cluster_count            = 1
  max_cluster_count            = 8
  auto_suspend                 = 180
  auto_resume                  = true
  initially_suspended          = true
  statement_timeout_in_seconds = local.user_statement_timeout
}

resource "snowflake_warehouse" "de_wh08" {
  name                         = "WH_EXT_ALL"
  warehouse_size               = "X-SMALL"
  min_cluster_count            = 1
  max_cluster_count            = 8
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


###############################################################################
# 6. NETWORK RULES & POLICIES  (KPDWADM.DWA_ADM, owned by SECURITYADMIN)
###############################################################################

# NOTE: Despite the name, these are private (RFC 1918), loopback and
#       documentation (RFC 5737) ranges - not public US IP space.
resource "snowflake_network_rule" "us_ips_rule" {
  provider = snowflake.securityadmin
  name     = "NETRULE_US_ALLOW"
  database = snowflake_database.admn_db.name
  schema   = snowflake_schema.admn_schema.name
  comment  = "Allow US IPs to access the account"
  type     = "IPV4"
  mode     = "INGRESS"
  value_list = [
    "10.0.0.0/8",
    "127.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.51.100.0/24",
    "203.0.113.0/24",
  ]
}

resource "snowflake_network_rule" "kpt_rule" {
  provider = snowflake.securityadmin
  name     = "NETRULE_KPT_ALLOW"
  database = snowflake_database.admn_db.name
  schema   = snowflake_schema.admn_schema.name
  comment  = "Allow KPT corporate IPs to access the account"
  type     = "IPV4"
  mode     = "INGRESS"
  value_list = [
    "128.35.0.0/16",
    "149.111.0.0/16",
    "161.249.0.0/16",
    "168.183.0.0/16",
    "198.203.174.0/23",
    "198.203.176.0/22",
    "198.203.180.0/23",
  ]
}

resource "snowflake_network_rule" "azure_westcentral_rule" {
  provider = snowflake.securityadmin
  name     = "NETRULE_AZUREWESTCENTRAL_ALLOW"
  database = snowflake_database.admn_db.name
  schema   = snowflake_schema.admn_schema.name
  comment  = "Allow Azure West Central US service IPs"
  type     = "IPV4"
  mode     = "INGRESS"
  value_list = [
    "4.255.128.0/17", "13.71.192.0/18", "13.77.192.0/19", "13.78.128.0/17",
    "13.104.145.64/26", "13.104.215.128/25", "13.104.219.0/25", "13.105.18.128/27",
    "13.105.28.64/26", "13.105.30.0/25", "13.105.30.128/26", "13.105.107.224/27",
    "13.105.108.0/28", "13.105.108.32/27", "20.20.190.0/23", "20.33.133.0/24",
    "20.33.211.0/24", "20.33.213.0/24", "20.47.4.0/24", "20.47.70.0/24",
    "20.47.104.0/24", "20.51.32.0/19", "20.55.128.0/18", "20.57.224.0/19",
    "20.59.128.0/18", "20.60.4.0/24", "20.60.119.0/24", "20.60.120.0/23",
    "20.60.122.0/24", "20.60.218.0/23", "20.69.0.0/18", "20.95.24.0/24",
    "20.95.62.0/24", "20.95.248.0/24", "20.95.250.0/24", "20.135.22.0/23",
    "20.135.72.0/23", "20.143.66.0/23", "20.150.81.0/24", "20.150.98.0/24",
    "20.152.16.0/22", "20.153.34.0/24", "20.153.57.0/24", "20.153.66.0/25",
    "20.153.69.128/26", "20.153.78.0/24", "20.157.41.0/24", "20.165.128.0/17",
    "20.168.176.0/20", "20.190.136.0/24", "20.190.158.0/24", "20.201.162.0/23",
    "20.201.207.0/24", "20.209.224.0/23", "40.64.146.160/28", "40.64.172.0/25",
    "40.67.120.0/21", "40.77.128.0/25", "40.77.131.192/27", "40.77.131.240/28",
    "40.77.135.0/24", "40.77.136.128/25", "40.77.166.0/25", "40.77.166.128/28",
    "40.77.173.0/24", "40.77.175.32/27", "40.77.182.160/27", "40.77.185.0/25",
    "40.77.224.16/28", "40.77.224.64/27", "40.77.227.0/24", "40.77.232.0/25",
    "40.77.235.0/24", "40.77.236.96/27", "40.77.246.0/24", "40.78.218.0/24",
    "40.79.205.240/28", "40.79.206.224/27", "40.79.207.0/27", "40.90.131.0/27",
    "40.90.138.192/28", "40.90.139.0/27", "40.90.143.96/27", "40.90.151.0/26",
    "40.90.151.128/28", "40.90.152.0/25", "40.93.6.0/24", "40.93.15.0/24",
    "40.93.198.0/23", "40.93.200.0/23", "40.93.202.0/24", "40.96.255.0/24",
    "40.97.13.0/24", "40.97.61.192/26", "40.97.62.0/25", "40.123.136.0/24",
    "40.126.8.0/24", "40.126.30.0/24", "48.208.45.0/24", "51.5.45.0/24",
    "52.101.24.0/22", "52.101.40.0/24", "52.102.133.0/24", "52.102.141.0/24",
    "52.103.7.0/24", "52.103.15.0/24", "52.103.133.0/24", "52.103.141.0/24",
    "52.106.122.128/27", "52.108.181.0/24", "52.108.202.0/24", "52.109.136.0/22",
    "52.111.206.0/24", "52.112.75.0/24", "52.112.93.0/24", "52.113.207.0/24",
    "52.123.56.0/24", "52.136.4.0/22", "52.143.214.0/24", "52.148.0.0/18",
    "52.150.128.0/17", "52.153.128.0/18", "52.159.0.0/18", "52.161.0.0/16",
    "52.239.164.0/25", "52.239.167.0/24", "52.239.244.0/23", "52.245.60.0/22",
    "52.253.128.0/20", "57.151.128.0/19", "64.4.8.0/24", "64.4.54.0/24",
    "65.55.209.192/26", "70.152.35.0/24", "104.44.89.96/27", "104.47.224.0/20",
    "128.24.128.0/17", "131.253.24.160/27", "131.253.40.160/28", "135.130.35.128/25",
    "135.130.36.0/24", "135.130.37.0/25", "135.130.37.128/26", "151.206.133.0/24",
    "157.55.12.128/26", "157.55.103.128/25", "172.208.128.0/17", "172.215.192.0/18",
    "207.68.174.48/29",
  ]
}

# Interactive users - KPT corporate network only
resource "snowflake_network_policy" "kpt_policy" {
  provider = snowflake.securityadmin
  name     = "NETWORK_POLICY_KPT_ALLOW"
  comment  = "KPT corporate network only"
  allowed_network_rule_list = [
    snowflake_network_rule.kpt_rule.fully_qualified_name,
  ]
}

# Service integrations - KPT + US + Azure West Central
resource "snowflake_network_policy" "azure_svc_policy" {
  provider = snowflake.securityadmin
  name     = "NETWORK_POLICY_AZURE_SVC_ALLOW"
  comment  = "KPT, US and Azure West Central service access"
  allowed_network_rule_list = [
    snowflake_network_rule.kpt_rule.fully_qualified_name,
    snowflake_network_rule.us_ips_rule.fully_qualified_name,
    snowflake_network_rule.azure_westcentral_rule.fully_qualified_name,
  ]
}


###############################################################################
# 7. USERS  (passwords from sensitive variable; change forced on first login)
###############################################################################

locals {
  # Replace with real users. Keys are Snowflake user names; each key must also
  # exist in var.user_passwords.
  users = {
    "<USER_NAME_1>" = {
      first_name = "<FIRST_NAME_1>"
      last_name  = "<LAST_NAME_1>"
      email      = "<EMAIL_1>"
      role       = "<USER_ROLE_1>"
      disabled   = false
    }
    "<USER_NAME_2>" = {
      first_name = "<FIRST_NAME_2>"
      last_name  = "<LAST_NAME_2>"
      email      = "<EMAIL_2>"
      role       = "<USER_ROLE_2>"
      disabled   = true
    }
  }
}

resource "snowflake_account_role" "user_role" {
  provider = snowflake.securityadmin
  for_each = local.users
  name     = each.value.role
  comment  = "Personal role for ${each.key}"
}

resource "snowflake_user" "user" {
  provider             = snowflake.securityadmin
  for_each             = local.users
  name                 = each.key
  login_name           = each.key
  first_name           = each.value.first_name
  last_name            = each.value.last_name
  display_name         = "${each.value.first_name} ${each.value.last_name}"
  email                = each.value.email
  comment              = "Managed by Terraform"
  password             = var.user_passwords[each.key]
  must_change_password = true
  disabled             = each.value.disabled
  default_namespace    = "KPDWPRD.DWA_ANA"
  default_warehouse    = snowflake_warehouse.de_wh05.name
  default_role         = snowflake_account_role.user_role[each.key].name
  network_policy       = snowflake_network_policy.kpt_policy.name
}

resource "snowflake_grant_account_role" "user_role_to_user" {
  provider  = snowflake.securityadmin
  for_each  = local.users
  role_name = snowflake_account_role.user_role[each.key].name
  user_name = snowflake_user.user[each.key].name
}

# Users get non-prod read access through their personal role
resource "snowflake_grant_account_role" "nonprod_ro_to_user_role" {
  provider         = snowflake.securityadmin
  for_each         = local.users
  role_name        = snowflake_account_role.role_nonprod_all.name
  parent_role_name = snowflake_account_role.user_role[each.key].name
}
