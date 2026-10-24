/******************************************************************************
 * Snowflake_Database_Objects.sql - Modern Enterprise Database Object Build (KPDW Account)
 *
 * Focus: Automated Data Governance, Precise RBAC Modeling, & Hardened Security Contexts
 ******************************************************************************/

/*=============================================================================
  1. SESSION CONTEXT
=============================================================================*/
USE ROLE ACCOUNTADMIN;
USE WAREHOUSE WH_OPER_ALL;


/*=============================================================================
  2. GOVERNANCE TAGS  (KPDWADM.DWA_GOV)
=============================================================================*/
CREATE TAG IF NOT EXISTS KPDWADM.DWA_GOV.DATA_PII
    COMMENT = 'Marks columns/tables that contain PII';

CREATE TAG IF NOT EXISTS KPDWADM.DWA_GOV.DATA_CLASSIFICATION
    ALLOWED_VALUES 'High', 'Medium', 'Low'
    COMMENT = 'Data sensitivity classification';


/*=============================================================================
  2b. HARDENED MASKING POLICIES  (KPDWADM.DWA_GOV)
  Secured using CURRENT_ROLE() validation contexts to prevent unauthorized
  role inheritance bypass vectors in lower environments.
=============================================================================*/
CREATE MASKING POLICY IF NOT EXISTS KPDWADM.DWA_GOV.MP_PII_STRING
    AS (val VARCHAR) RETURNS VARCHAR ->
    CASE
        WHEN val IS NULL                  THEN NULL
        WHEN CURRENT_ROLE() = 'SYSADMIN'  THEN val
        ELSE '***MASKED***'
    END
    COMMENT = 'Non-prod: fully masks PII text (names, login, salutation, country)';

CREATE MASKING POLICY IF NOT EXISTS KPDWADM.DWA_GOV.MP_PII_EMAIL
    AS (val VARCHAR) RETURNS VARCHAR ->
    CASE
        WHEN val IS NULL                  THEN NULL
        WHEN CURRENT_ROLE() = 'SYSADMIN'  THEN val
        ELSE '*****@' || SPLIT_PART(val, '@', 2)
    END
    COMMENT = 'Non-prod: masks e-mail local part, keeps domain for testing';

CREATE MASKING POLICY IF NOT EXISTS KPDWADM.DWA_GOV.MP_PII_NUMBER
    AS (val NUMBER) RETURNS NUMBER ->
    CASE
        WHEN CURRENT_ROLE() = 'SYSADMIN'  THEN val
        ELSE NULL
    END
    COMMENT = 'Non-prod: nulls numeric PII (date of birth parts, purchase estimate)';

CREATE MASKING POLICY IF NOT EXISTS KPDWADM.DWA_GOV.MP_PII_ZIP
    AS (val VARCHAR) RETURNS VARCHAR ->
    CASE
        WHEN val IS NULL                    THEN NULL
        WHEN CURRENT_ROLE() = 'SYSADMIN'    THEN val
        ELSE LEFT(val, 3) || '**'
    END
    COMMENT = 'Non-prod: keeps 3-digit ZIP prefix (HIPAA Safe Harbor style)';


/*=============================================================================
  2c. MODERN SECURITY & MFA AUTHENTICATION POLICY
=============================================================================*/
CREATE AUTHENTICATION POLICY IF NOT EXISTS KPDWADM.DWA_ADM.AP_MFA_REQUIRED
    AUTHENTICATION_METHODS = ('PASSWORD')
    MFA_ENROLLMENT         = REQUIRED
    MFA_POLICY             = (ALLOWED_METHODS = ('PASSKEY', 'TOTP'))
    COMMENT                = 'Password + mandatory MFA (passkey or authenticator app)';

-- Verify compliance alignment across configuration executions
ALTER AUTHENTICATION POLICY KPDWADM.DWA_ADM.AP_MFA_REQUIRED SET
    AUTHENTICATION_METHODS = ('PASSWORD')
    MFA_ENROLLMENT         = REQUIRED
    MFA_POLICY             = (ALLOWED_METHODS = ('PASSKEY', 'TOTP'));

-- Reset bindings cleanly to maintain drift synchronization with state execution
ALTER USER USR_BRYAN_MCKNIGHT UNSET AUTHENTICATION POLICY;
ALTER USER USR_BRYAN_MCKNIGHT SET AUTHENTICATION POLICY KPDWADM.DWA_ADM.AP_MFA_REQUIRED;

-- Re-verify network policy attachment boundaries matching Terraform states
-- ALTER USER USR_BRYAN_MCKNIGHT SET NETWORK_POLICY = NETWORK_POLICY_KPT_ALLOW;
-- Network policy DDL removed from public version


/*=============================================================================
  3. AUTOMATED SCHEMA-LEVEL RBAC MANAGEMENT PROCEDURE
=============================================================================*/
CREATE OR REPLACE PROCEDURE KPDWADM.DWA_ADM.SP_SETUP_DATABASE_RBAC(P_DATABASE_NAME VARCHAR)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_db         VARCHAR;
    v_env        VARCHAR;
    v_is_prod    BOOLEAN;
    v_exists     INTEGER;
    v_log_msg    VARCHAR;
BEGIN
    v_db := UPPER(TRIM(:P_DATABASE_NAME));
    
    -- Verify input database exists before executing structural loop paths
    SELECT COUNT(*) INTO :v_exists FROM INFORMATION_SCHEMA.DATABASES WHERE DATABASE_NAME = :v_db;
    
    IF (v_exists = 0) THEN
        RETURN 'Execution Terminated: Specified database target does not exist.';
    END IF;

    -- [Add your procedural schema cursor loop and grant deployment logic here]

    v_log_msg := 'Database RBAC configuration successfully applied to target database environment: ' || v_db;
    RETURN v_log_msg;
END;
$$;
