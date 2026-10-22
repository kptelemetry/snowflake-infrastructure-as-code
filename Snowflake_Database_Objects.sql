/******************************************************************************
 * tpt_build.sql - Database object build for the KPDW Snowflake account
 *
 * PREREQUISITES (in order)
 *   1. `terraform apply` of tpt_tf.sql: warehouses, databases, schemas, stages,
 *      roles, network rules/policies and users.
 *   2. Secret KPDWADM.DWA_ADM.GIT_SEC001 created manually (GitHub PAT).
 *      The API integration and Git repository are created in section 5b.
 *
 * SECTIONS
 *   1. Session context
 *   2. Governance tags, masking policies, contacts & MFA policy
 *   3. Procedure: SP_SETUP_DATABASE_RBAC        (per-schema RO/RW/SVC roles)
 *   4. Procedure: SP_REFRESH_NONPROD_FROM_PRD   (clone PRD -> non-prod)
 *   5. PRD data objects                         (PRD is the source of truth)
 *   6. dbt project
 *   7. Apply RBAC to PRD + shared grants
 *   8. Refresh non-prod from PRD
 *
 * Re-runnable: objects use IF NOT EXISTS, except the non-prod refresh, which
 * replaces non-prod schemas by design. After every refresh run
 * `terraform apply`, because named internal stages are not cloned.
 *
 * Objects owned by Terraform (do NOT create here): warehouses, databases,
 * schemas, internal stages, account roles, users, network rules/policies.
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
  2b. MASKING POLICIES  (KPDWADM.DWA_GOV)
  Attached only to non-prod copies by SP_APPLY_NONPROD_MASKING (section 4b).
  PRD tables carry no masking policy, so clones of PRD start unmasked and are
  masked immediately after each refresh. SYSADMIN (and roles above it) see
  clear values; every other role sees masked values.
=============================================================================*/
CREATE MASKING POLICY IF NOT EXISTS KPDWADM.DWA_GOV.MP_PII_STRING
    AS (val VARCHAR) RETURNS VARCHAR ->
    CASE
        WHEN val IS NULL                  THEN NULL
        WHEN IS_ROLE_IN_SESSION('SYSADMIN') THEN val
        ELSE '***MASKED***'
    END
    COMMENT = 'Non-prod: fully masks PII text (names, login, salutation, country)';

CREATE MASKING POLICY IF NOT EXISTS KPDWADM.DWA_GOV.MP_PII_EMAIL
    AS (val VARCHAR) RETURNS VARCHAR ->
    CASE
        WHEN val IS NULL                  THEN NULL
        WHEN IS_ROLE_IN_SESSION('SYSADMIN') THEN val
        ELSE '*****@' || SPLIT_PART(val, '@', 2)
    END
    COMMENT = 'Non-prod: masks e-mail local part, keeps domain for testing';

CREATE MASKING POLICY IF NOT EXISTS KPDWADM.DWA_GOV.MP_PII_NUMBER
    AS (val NUMBER) RETURNS NUMBER ->
    CASE
        WHEN IS_ROLE_IN_SESSION('SYSADMIN') THEN val
        ELSE NULL
    END
    COMMENT = 'Non-prod: nulls numeric PII (date of birth parts, purchase estimate)';

CREATE MASKING POLICY IF NOT EXISTS KPDWADM.DWA_GOV.MP_PII_ZIP
    AS (val VARCHAR) RETURNS VARCHAR ->
    CASE
        WHEN val IS NULL                    THEN NULL
        WHEN IS_ROLE_IN_SESSION('SYSADMIN') THEN val
        ELSE LEFT(val, 3) || '**'
    END
    COMMENT = 'Non-prod: keeps 3-digit ZIP prefix (HIPAA Safe Harbor style)';


/*=============================================================================
  2c. CONTACTS  (KPDWADM.DWA_ADM)
  Referenced by tables via WITH CONTACT. Users in DB_ADMINS are created by
  Terraform. Account-level ACCESS_APPROVAL was set twice in the original
  script; the final value, SECURITY_OFFICERS, is kept.
=============================================================================*/
CREATE CONTACT IF NOT EXISTS KPDWADM.DWA_ADM.SUPPORT_DEPT
    EMAIL_DISTRIBUTION_LIST = 'support@kpt.org';

CREATE CONTACT IF NOT EXISTS KPDWADM.DWA_ADM.FINANCE_DEPT
    EMAIL_DISTRIBUTION_LIST = 'finance@kpt.org';

CREATE CONTACT IF NOT EXISTS KPDWADM.DWA_ADM.SECURITY_OFFICERS
    EMAIL_DISTRIBUTION_LIST = 'security@kpt.org';

CREATE CONTACT IF NOT EXISTS KPDWADM.DWA_ADM.DB_ADMINS
    USERS = ('USR_JANET_DOH', 'USR_JOHN_DOE');

ALTER ACCOUNT SET CONTACT
    ACCESS_APPROVAL     = KPDWADM.DWA_ADM.SECURITY_OFFICERS,
    SECURITY_COMPLIANCE = KPDWADM.DWA_ADM.SECURITY_OFFICERS,
    SUPPORT             = KPDWADM.DWA_ADM.SECURITY_OFFICERS,
    STEWARD             = KPDWADM.DWA_ADM.FINANCE_DEPT;


/*=============================================================================
  2d. MFA AUTHENTICATION POLICY  - USR_BRYAN_MCKNIGHT only
  -----------------------------------------------------------------------------
  Snowflake enforces MFA through an AUTHENTICATION POLICY (there is no
  "authentication integration" object for native MFA). This policy:
    - allows password sign-in only, from any client
    - requires MFA enrollment (mandatory second factor)
    - allows passkey or authenticator app (TOTP) as the second factor
  It is attached to a single user; no other user or the account is affected.
  Other users do not have IP restrictions to permit connectivity from diverse 
  regions.

  Network policy: Terraform already sets NETWORK_POLICY_KPT_ALLOW on this
  user. It is set again here with the SAME value so there is no Terraform
  drift. 
=============================================================================*/
CREATE AUTHENTICATION POLICY IF NOT EXISTS KPDWADM.DWA_ADM.AP_MFA_REQUIRED
    AUTHENTICATION_METHODS = ('PASSWORD')
    MFA_ENROLLMENT         = REQUIRED
    MFA_POLICY             = (ALLOWED_METHODS = ('PASSKEY', 'TOTP'))
    COMMENT                = 'Password + mandatory MFA (passkey or authenticator app)';

-- Enforce settings even if the policy pre-existed with different values
ALTER AUTHENTICATION POLICY KPDWADM.DWA_ADM.AP_MFA_REQUIRED SET
    AUTHENTICATION_METHODS = ('PASSWORD')
    MFA_ENROLLMENT         = REQUIRED
    MFA_POLICY             = (ALLOWED_METHODS = ('PASSKEY', 'TOTP'));

-- Re-attach cleanly on every run (SET fails if a policy is already attached)
ALTER USER USR_BRYAN_MCKNIGHT UNSET AUTHENTICATION POLICY;
ALTER USER USR_BRYAN_MCKNIGHT SET AUTHENTICATION POLICY KPDWADM.DWA_ADM.AP_MFA_REQUIRED;

ALTER USER USR_BRYAN_MCKNIGHT SET NETWORK_POLICY = NETWORK_POLICY_KPT_ALLOW;


/*=============================================================================
  3. PROCEDURE: SP_SETUP_DATABASE_RBAC
  -----------------------------------------------------------------------------
  For every schema in the target database (excl. INFORMATION_SCHEMA, PUBLIC):
    RL_<ENV>_<SCHEMA>_RO   SELECT on tables/views, USAGE on functions
    RL_<ENV>_<SCHEMA>_RW   RO + DML, USAGE on procedures
    RL_<ENV>_<SCHEMA>_SVC  owns the schema and all objects in it

  Role hierarchy
    All environments : RO/RW/SVC -> SYSADMIN
    Non-prod only    : RO  -> RL_NONPROD_ALL_READONLY
                       RW  -> RL_NONPROD_DSS_ETL
                       SVC -> SVC_ROLE_ETL
    PRD              : SYSADMIN only. Any PRD role previously granted to a
                       NONPROD_* / SVC_ROLE_ETL role is revoked.

  Ownership is transferred with REVOKE CURRENT GRANTS, so grants inherited
  from PRD through cloning are stripped from non-prod objects before the
  environment's own grants are applied.

  RL_PURVIEW_READER: USAGE + REFERENCES (metadata only, no data access).
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
    v_schema     VARCHAR;
    v_fq         VARCHAR;
    v_role_ro    VARCHAR;
    v_role_rw    VARCHAR;
    v_role_svc   VARCHAR;
    v_stmts      ARRAY;
    v_stmt       VARCHAR;
    v_last       INTEGER;
    v_fg_plural  VARCHAR;
    v_errors     INTEGER DEFAULT 0;
    v_log        VARCHAR DEFAULT '';
BEGIN
    -- 1. Validate input: strict allow-list + database must exist
    v_db := UPPER(TRIM(:P_DATABASE_NAME));
    IF (NOT REGEXP_LIKE(:v_db, '^KPDW(DEV|TST|PPD|STG|PRD)$')) THEN
        RETURN 'ERROR: Database must be one of KPDWDEV, KPDWTST, KPDWPPD, KPDWSTG, KPDWPRD. Got: ' || :v_db;
    END IF;

    SELECT COUNT(*) INTO :v_exists
      FROM KPDWADM.INFORMATION_SCHEMA.DATABASES
     WHERE DATABASE_NAME = :v_db;
    IF (v_exists = 0) THEN
        RETURN 'ERROR: Database ' || :v_db || ' does not exist.';
    END IF;

    v_env     := RIGHT(:v_db, 3);
    v_is_prod := (v_env = 'PRD');

    -- 2. Iterate schemas (v_db is allow-listed above, safe to concatenate)
    LET rs RESULTSET := (EXECUTE IMMEDIATE
        'SELECT SCHEMA_NAME FROM ' || :v_db || '.INFORMATION_SCHEMA.SCHEMATA ' ||
        'WHERE SCHEMA_NAME NOT IN (''INFORMATION_SCHEMA'', ''PUBLIC'') ORDER BY SCHEMA_NAME');
    LET cur CURSOR FOR rs;

    FOR rec IN cur DO
        v_schema := rec.SCHEMA_NAME;

        -- Role names are derived from schema names; reject anything unexpected
        IF (NOT REGEXP_LIKE(:v_schema, '^[A-Z0-9_]+$')) THEN
            v_log := v_log || 'SKIPPED schema ' || v_schema || ': invalid name.\n';
            CONTINUE;
        END IF;

        v_fq       := v_db || '.' || v_schema;
        v_role_ro  := 'RL_' || v_env || '_' || v_schema || '_RO';
        v_role_rw  := 'RL_' || v_env || '_' || v_schema || '_RW';
        v_role_svc := 'RL_' || v_env || '_' || v_schema || '_SVC';

        -- 3. Remove all existing future grants (incl. any inherited via clone)
        EXECUTE IMMEDIATE 'SHOW FUTURE GRANTS IN SCHEMA ' || :v_fq;
        LET fg_rs RESULTSET := (SELECT "privilege" AS priv, "grant_on" AS obj, "grantee_name" AS grantee
                                  FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())));
        LET fg_cur CURSOR FOR fg_rs;
        FOR fg IN fg_cur DO
            v_fg_plural := CASE fg.obj
                               WHEN 'FILE_FORMAT'   THEN 'FILE FORMATS'
                               WHEN 'DYNAMIC_TABLE' THEN 'DYNAMIC TABLES'
                               ELSE fg.obj || 'S'
                           END;
            v_stmt := 'REVOKE ' || fg.priv || ' ON FUTURE ' || v_fg_plural ||
                      ' IN SCHEMA ' || v_fq || ' FROM ROLE "' || fg.grantee || '"';
            BEGIN
                EXECUTE IMMEDIATE :v_stmt;
            EXCEPTION WHEN OTHER THEN
                v_errors := v_errors + 1;
                v_log := v_log || 'FAILED: ' || v_stmt || ' -> ' || SQLERRM || '\n';
            END;
        END FOR;

        -- 4. Build the grant set for this schema
        v_stmts := ARRAY_CONSTRUCT(
            -- Roles & hierarchy
            'CREATE ROLE IF NOT EXISTS ' || v_role_ro,
            'CREATE ROLE IF NOT EXISTS ' || v_role_rw,
            'CREATE ROLE IF NOT EXISTS ' || v_role_svc,
            'GRANT ROLE ' || v_role_ro  || ' TO ROLE SYSADMIN',
            'GRANT ROLE ' || v_role_rw  || ' TO ROLE SYSADMIN',
            'GRANT ROLE ' || v_role_svc || ' TO ROLE SYSADMIN',

            -- Ownership: schema + existing objects to SVC, stripping prior grants
            'GRANT OWNERSHIP ON SCHEMA ' || v_fq || ' TO ROLE ' || v_role_svc || ' REVOKE CURRENT GRANTS',
            'GRANT OWNERSHIP ON ALL TABLES     IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_svc || ' REVOKE CURRENT GRANTS',
            'GRANT OWNERSHIP ON ALL VIEWS      IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_svc || ' REVOKE CURRENT GRANTS',
            'GRANT OWNERSHIP ON ALL FUNCTIONS  IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_svc || ' REVOKE CURRENT GRANTS',
            'GRANT OWNERSHIP ON ALL PROCEDURES IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_svc || ' REVOKE CURRENT GRANTS',
            'GRANT OWNERSHIP ON ALL SEQUENCES  IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_svc || ' REVOKE CURRENT GRANTS',

            -- Future ownership to SVC
            'GRANT OWNERSHIP ON FUTURE TABLES     IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_svc,
            'GRANT OWNERSHIP ON FUTURE VIEWS      IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_svc,
            'GRANT OWNERSHIP ON FUTURE FUNCTIONS  IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_svc,
            'GRANT OWNERSHIP ON FUTURE PROCEDURES IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_svc,
            'GRANT OWNERSHIP ON FUTURE SEQUENCES  IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_svc,

            -- Database & schema usage
            'GRANT USAGE ON DATABASE ' || v_db || ' TO ROLE ' || v_role_ro,
            'GRANT USAGE ON DATABASE ' || v_db || ' TO ROLE ' || v_role_rw,
            'GRANT USAGE ON DATABASE ' || v_db || ' TO ROLE ' || v_role_svc,
            'GRANT USAGE ON SCHEMA '   || v_fq || ' TO ROLE ' || v_role_ro,
            'GRANT USAGE ON SCHEMA '   || v_fq || ' TO ROLE ' || v_role_rw,

            -- RO: read only
            'GRANT SELECT ON ALL TABLES       IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_ro,
            'GRANT SELECT ON ALL VIEWS        IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_ro,
            'GRANT USAGE  ON ALL FUNCTIONS    IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_ro,
            'GRANT SELECT ON FUTURE TABLES    IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_ro,
            'GRANT SELECT ON FUTURE VIEWS     IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_ro,
            'GRANT USAGE  ON FUTURE FUNCTIONS IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_ro,

            -- RW: read + DML (no DDL, no ownership)
            'GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES    IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_rw,
            'GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON FUTURE TABLES IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_rw,
            'GRANT SELECT ON ALL VIEWS           IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_rw,
            'GRANT SELECT ON FUTURE VIEWS        IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_rw,
            'GRANT USAGE  ON ALL FUNCTIONS       IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_rw,
            'GRANT USAGE  ON FUTURE FUNCTIONS    IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_rw,
            'GRANT USAGE  ON ALL PROCEDURES      IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_rw,
            'GRANT USAGE  ON FUTURE PROCEDURES   IN SCHEMA ' || v_fq || ' TO ROLE ' || v_role_rw,

            -- Purview: metadata only
            'GRANT USAGE ON DATABASE ' || v_db || ' TO ROLE RL_PURVIEW_READER',
            'GRANT USAGE ON SCHEMA '   || v_fq || ' TO ROLE RL_PURVIEW_READER',
            'GRANT REFERENCES ON ALL TABLES    IN SCHEMA ' || v_fq || ' TO ROLE RL_PURVIEW_READER',
            'GRANT REFERENCES ON ALL VIEWS     IN SCHEMA ' || v_fq || ' TO ROLE RL_PURVIEW_READER',
            'GRANT REFERENCES ON FUTURE TABLES IN SCHEMA ' || v_fq || ' TO ROLE RL_PURVIEW_READER',
            'GRANT REFERENCES ON FUTURE VIEWS  IN SCHEMA ' || v_fq || ' TO ROLE RL_PURVIEW_READER'
        );

        IF (v_is_prod) THEN
            -- PRD isolation: ensure no non-prod role inherits PRD access
            v_stmts := ARRAY_CAT(v_stmts, ARRAY_CONSTRUCT(
                'REVOKE ROLE ' || v_role_ro  || ' FROM ROLE RL_NONPROD_ALL_READONLY',
                'REVOKE ROLE ' || v_role_rw  || ' FROM ROLE RL_NONPROD_DSS_ETL',
                'REVOKE ROLE ' || v_role_svc || ' FROM ROLE RL_NONPROD_DSS_ETL',
                'REVOKE ROLE ' || v_role_rw  || ' FROM ROLE SVC_ROLE_ETL',
                'REVOKE ROLE ' || v_role_svc || ' FROM ROLE SVC_ROLE_ETL'
            ));
        ELSE
            v_stmts := ARRAY_CAT(v_stmts, ARRAY_CONSTRUCT(
                'GRANT ROLE ' || v_role_ro  || ' TO ROLE RL_NONPROD_ALL_READONLY',
                'GRANT ROLE ' || v_role_rw  || ' TO ROLE RL_NONPROD_DSS_ETL',
                'GRANT ROLE ' || v_role_svc || ' TO ROLE SVC_ROLE_ETL'
            ));
        END IF;

        -- 5. Execute; log every failure instead of silently ignoring it
        v_last := ARRAY_SIZE(v_stmts) - 1;
        FOR i IN 0 TO v_last DO
            v_stmt := GET(v_stmts, i)::VARCHAR;
            BEGIN
                EXECUTE IMMEDIATE :v_stmt;
            EXCEPTION WHEN OTHER THEN
                v_errors := v_errors + 1;
                v_log := v_log || 'FAILED: ' || v_stmt || ' -> ' || SQLERRM || '\n';
            END;
        END FOR;

        v_log := v_log || 'Schema ' || v_fq || ': ' || v_role_ro || ', ' || v_role_rw || ', ' || v_role_svc || ' configured.\n';
    END FOR;

    IF (v_errors > 0) THEN
        RETURN 'COMPLETED WITH ' || v_errors || ' ERROR(S) for ' || v_db || '.\n' || v_log;
    END IF;
    RETURN 'SUCCESS: RBAC setup complete for ' || v_db || '.\n' || v_log;
END;
$$;


/*=============================================================================
  4. PROCEDURE: SP_REFRESH_NONPROD_FROM_PRD
  -----------------------------------------------------------------------------
  Replaces every KPDWPRD schema (excl. INFORMATION_SCHEMA, PUBLIC, DWA_DBT) in
  the target non-prod database with a zero-copy clone, then re-applies the
  target's RBAC (which strips grants inherited from PRD).
  DWA_DBT is excluded: each environment deploys its own dbt project.
  Schemas that exist only in the target (e.g. KPDWDEV.DWA_ADM) are untouched.
=============================================================================*/
CREATE OR REPLACE PROCEDURE KPDWADM.DWA_ADM.SP_REFRESH_NONPROD_FROM_PRD(P_TARGET_DATABASE VARCHAR)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_target  VARCHAR;
    v_schema  VARCHAR;
    v_log     VARCHAR DEFAULT '';
    v_rbac    VARCHAR;
    v_mask    VARCHAR;
BEGIN
    v_target := UPPER(TRIM(:P_TARGET_DATABASE));
    IF (NOT REGEXP_LIKE(:v_target, '^KPDW(DEV|TST|PPD|STG)$')) THEN
        RETURN 'ERROR: Target must be KPDWDEV, KPDWTST, KPDWPPD or KPDWSTG. Got: ' || :v_target;
    END IF;

    LET cur CURSOR FOR
        SELECT SCHEMA_NAME
          FROM KPDWPRD.INFORMATION_SCHEMA.SCHEMATA
         WHERE SCHEMA_NAME NOT IN ('INFORMATION_SCHEMA', 'PUBLIC', 'DWA_DBT')
           AND REGEXP_LIKE(SCHEMA_NAME, '^[A-Z0-9_]+$')
         ORDER BY SCHEMA_NAME;

    FOR rec IN cur DO
        v_schema := rec.SCHEMA_NAME;
        EXECUTE IMMEDIATE 'CREATE OR REPLACE SCHEMA ' || :v_target || '.' || :v_schema ||
                          ' CLONE KPDWPRD.' || :v_schema;
        v_log := v_log || 'Cloned KPDWPRD.' || v_schema || ' -> ' || v_target || '.' || v_schema || '\n';
    END FOR;

    -- Mask PII before any non-prod role is granted access
    CALL KPDWADM.DWA_ADM.SP_APPLY_NONPROD_MASKING(:v_target) INTO :v_mask;

    CALL KPDWADM.DWA_ADM.SP_SETUP_DATABASE_RBAC(:v_target) INTO :v_rbac;

    RETURN v_log || '\n' || v_mask || '\n' || v_rbac ||
           '\nNEXT STEP: run `terraform apply` to recreate internal stages in ' || v_target || '.';
END;
$$;


/*=============================================================================
  4b. PROCEDURE: SP_APPLY_NONPROD_MASKING
  -----------------------------------------------------------------------------
  Attaches the PII masking policies to every customer table in <target>:
    DWA_ING.KP_CUSTOMER (+ 6 regional clones)  names, login, e-mail, DOB
    DWA_ING.KP_CUSTOMER_ADDRESS                street, suite, ZIP
    DWA_ANA.CUSTOMER_LOCS                      (copy of KP_CUSTOMER_ADDRESS)
    DWA_ING.KP_CUSTOMER_DEMOGRAPHICS           gender, marital, education,
                                               credit rating, purchase estimate
  Refuses to run against KPDWPRD. Uses FORCE so re-runs are idempotent.
  Tables that don't exist are reported and skipped.
=============================================================================*/
CREATE OR REPLACE PROCEDURE KPDWADM.DWA_ADM.SP_APPLY_NONPROD_MASKING(P_TARGET_DATABASE VARCHAR)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_target    VARCHAR;
    v_customer  OBJECT;   -- column -> policy maps
    v_address   OBJECT;
    v_demo      OBJECT;
    v_targets   ARRAY;    -- [{s: schema, t: table, c: column map}]
    v_cols      OBJECT;
    v_keys      ARRAY;
    v_schema    VARCHAR;
    v_table     VARCHAR;
    v_fq        VARCHAR;
    v_col       VARCHAR;
    v_stmt      VARCHAR;
    v_exists    INTEGER;
    v_last_t    INTEGER;
    v_last_c    INTEGER;
    v_errors    INTEGER DEFAULT 0;
    v_log       VARCHAR DEFAULT '';
BEGIN
    v_target := UPPER(TRIM(:P_TARGET_DATABASE));
    IF (NOT REGEXP_LIKE(:v_target, '^KPDW(DEV|TST|PPD|STG)$')) THEN
        RETURN 'ERROR: Masking applies to non-prod only (KPDWDEV, KPDWTST, KPDWPPD, KPDWSTG). Got: ' || :v_target;
    END IF;

    v_customer := OBJECT_CONSTRUCT(
        'C_SALUTATION',    'MP_PII_STRING',
        'C_FIRST_NAME',    'MP_PII_STRING',
        'C_LAST_NAME',     'MP_PII_STRING',
        'C_LOGIN',         'MP_PII_STRING',
        'C_BIRTH_COUNTRY', 'MP_PII_STRING',
        'C_EMAIL_ADDRESS', 'MP_PII_EMAIL',
        'C_BIRTH_DAY',     'MP_PII_NUMBER',
        'C_BIRTH_MONTH',   'MP_PII_NUMBER',
        'C_BIRTH_YEAR',    'MP_PII_NUMBER');

    -- City, county, state and country are left clear for realistic testing
    v_address := OBJECT_CONSTRUCT(
        'CA_STREET_NUMBER', 'MP_PII_STRING',
        'CA_STREET_NAME',   'MP_PII_STRING',
        'CA_STREET_TYPE',   'MP_PII_STRING',
        'CA_SUITE_NUMBER',  'MP_PII_STRING',
        'CA_ZIP',           'MP_PII_ZIP');

    v_demo := OBJECT_CONSTRUCT(
        'CD_GENDER',            'MP_PII_STRING',
        'CD_MARITAL_STATUS',    'MP_PII_STRING',
        'CD_EDUCATION_STATUS',  'MP_PII_STRING',
        'CD_CREDIT_RATING',     'MP_PII_STRING',
        'CD_PURCHASE_ESTIMATE', 'MP_PII_NUMBER');

    v_targets := ARRAY_CONSTRUCT(
        OBJECT_CONSTRUCT('s', 'DWA_ING', 't', 'KP_CUSTOMER',              'c', v_customer),
        OBJECT_CONSTRUCT('s', 'DWA_ING', 't', 'KP_US_CUSTOMER',           'c', v_customer),
        OBJECT_CONSTRUCT('s', 'DWA_ING', 't', 'KP_NA_CUSTOMER',           'c', v_customer),
        OBJECT_CONSTRUCT('s', 'DWA_ING', 't', 'KP_SA_CUSTOMER',           'c', v_customer),
        OBJECT_CONSTRUCT('s', 'DWA_ING', 't', 'KP_EU_CUSTOMER',           'c', v_customer),
        OBJECT_CONSTRUCT('s', 'DWA_ING', 't', 'KP_AF_CUSTOMER',           'c', v_customer),
        OBJECT_CONSTRUCT('s', 'DWA_ING', 't', 'KP_AS_CUSTOMER',           'c', v_customer),
        OBJECT_CONSTRUCT('s', 'DWA_ING', 't', 'KP_CUSTOMER_ADDRESS',      'c', v_address),
        OBJECT_CONSTRUCT('s', 'DWA_ANA', 't', 'CUSTOMER_LOCS',            'c', v_address),
        OBJECT_CONSTRUCT('s', 'DWA_ING', 't', 'KP_CUSTOMER_DEMOGRAPHICS', 'c', v_demo));

    v_last_t := ARRAY_SIZE(v_targets) - 1;

    FOR t IN 0 TO v_last_t DO
        v_schema := GET(GET(v_targets, t), 's')::VARCHAR;
        v_table  := GET(GET(v_targets, t), 't')::VARCHAR;
        v_cols   := GET(GET(v_targets, t), 'c')::OBJECT;
        v_keys   := OBJECT_KEYS(v_cols);
        v_last_c := ARRAY_SIZE(v_keys) - 1;
        v_fq     := v_target || '.' || v_schema || '.' || v_table;

        EXECUTE IMMEDIATE 'SHOW TABLES LIKE ''' || :v_table || ''' IN SCHEMA ' || :v_target || '.' || :v_schema;
        SELECT COUNT(*) INTO :v_exists FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));
        IF (v_exists = 0) THEN
            v_log := v_log || 'SKIPPED ' || v_fq || ': table not found.\n';
            CONTINUE;
        END IF;

        FOR c IN 0 TO v_last_c DO
            v_col  := GET(v_keys, c)::VARCHAR;
            v_stmt := 'ALTER TABLE ' || v_fq || ' MODIFY COLUMN ' || v_col ||
                      ' SET MASKING POLICY KPDWADM.DWA_GOV.' || GET(v_cols, v_col)::VARCHAR || ' FORCE';
            BEGIN
                EXECUTE IMMEDIATE :v_stmt;
            EXCEPTION WHEN OTHER THEN
                v_errors := v_errors + 1;
                v_log := v_log || 'FAILED: ' || v_stmt || ' -> ' || SQLERRM || '\n';
            END;
        END FOR;
        v_log := v_log || 'Masked ' || v_fq || '\n';
    END FOR;

    IF (v_errors > 0) THEN
        RETURN 'MASKING COMPLETED WITH ' || v_errors || ' ERROR(S) for ' || v_target || '.\n' || v_log;
    END IF;
    RETURN 'MASKING SUCCESS for ' || v_target || '.\n' || v_log;
END;
$$;


/*=============================================================================
  5. PRD DATA OBJECTS  (KPDWPRD - single source of truth)
  Contacts are created in section 2c (KPDWADM.DWA_ADM).
=============================================================================*/

---------------------------------------------------------------------------
-- 5.1 Ingestion layer: KPDWPRD.DWA_ING
---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_LEIE (
    LASTNAME     VARCHAR(20)  COMMENT 'Last name of the excluded individual',
    FIRSTNAME    VARCHAR(15)  COMMENT 'First name of the excluded individual',
    MIDNAME      VARCHAR(15)  COMMENT 'Middle name of the excluded individual',
    BUSNAME      VARCHAR(30)  COMMENT 'Business name of the excluded entity',
    GENERAL      VARCHAR(20)  COMMENT 'General classification or provider type',
    SPECIALTY    VARCHAR(20)  COMMENT 'Provider specialty',
    UPIN         VARCHAR(6)   COMMENT 'Unique Physician Identification Number',
    NPI          VARCHAR(10)  COMMENT 'National Provider Identifier',
    DOB          VARCHAR(8)   COMMENT 'Date of birth (YYYYMMDD)',
    ADDRESS      VARCHAR(30)  COMMENT 'Street address',
    CITY         VARCHAR(20)  COMMENT 'City',
    STATE        VARCHAR(2)   COMMENT 'State abbreviation',
    ZIP          VARCHAR(5)   COMMENT 'ZIP code',
    EXCLTYPE     VARCHAR(9)   COMMENT 'Exclusion authority type (e.g. 1128a1)',
    EXCLDATE     VARCHAR(8)   COMMENT 'Date of exclusion (YYYYMMDD)',
    REINDATE     VARCHAR(8)   COMMENT 'Date of reinstatement (YYYYMMDD)',
    WAIVERDATE   VARCHAR(8)   COMMENT 'Date of waiver (YYYYMMDD)',
    WAIVERSTATE  VARCHAR(2)   COMMENT 'State that requested the waiver'
);

CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_LUNCH_MENU (
    MENU_ID                       NUMBER(19,0),
    MENU_TYPE_ID                  NUMBER(38,0),
    MENU_TYPE                     VARCHAR,
    TRUCK_BRAND_NAME              VARCHAR,
    MENU_ITEM_ID                  NUMBER(38,0),
    MENU_ITEM_NAME                VARCHAR,
    ITEM_CATEGORY                 VARCHAR,
    ITEM_SUBCATEGORY              VARCHAR,
    COST_OF_GOODS_USD             NUMBER(38,4),
    SALE_PRICE_USD                NUMBER(38,4),
    MENU_ITEM_HEALTH_METRICS_OBJ  VARIANT
);

-- External sample-data stage (Tasty Bytes quickstart)
CREATE STAGE IF NOT EXISTS KPDWPRD.DWA_ING.STG_TASTYBYTES
    URL = 's3://sfquickstarts/tastybytes/'
    FILE_FORMAT = (TYPE = CSV);

-- COPY load metadata prevents reloading the same files on re-run
COPY INTO KPDWPRD.DWA_ING.KP_LUNCH_MENU
    FROM @KPDWPRD.DWA_ING.STG_TASTYBYTES/raw_pos/menu/;

-- TPC-DS sample tables
CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_CALLCENTER
    WITH CONTACT (ACCESS_APPROVAL = KPDWADM.DWA_ADM.FINANCE_DEPT)
    AS SELECT * FROM SNOWFLAKE_SAMPLE_DATA.TPCDS_SF100TCL.CALL_CENTER;

CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_CATALOG_PAGE
    WITH CONTACT (ACCESS_APPROVAL = KPDWADM.DWA_ADM.FINANCE_DEPT)
    AS SELECT * FROM SNOWFLAKE_SAMPLE_DATA.TPCDS_SF100TCL.CATALOG_PAGE;

CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_CATALOG_RETURNS
    WITH CONTACT (ACCESS_APPROVAL = KPDWADM.DWA_ADM.FINANCE_DEPT)
    AS SELECT * FROM SNOWFLAKE_SAMPLE_DATA.TPCDS_SF100TCL.CATALOG_RETURNS;

CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_CUSTOMER_ADDRESS
    WITH CONTACT (ACCESS_APPROVAL = KPDWADM.DWA_ADM.FINANCE_DEPT)
    AS SELECT * FROM SNOWFLAKE_SAMPLE_DATA.TPCDS_SF100TCL.CUSTOMER_ADDRESS;

CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_CUSTOMER_DEMOGRAPHICS
    WITH CONTACT (ACCESS_APPROVAL = KPDWADM.DWA_ADM.FINANCE_DEPT)
    AS SELECT * FROM SNOWFLAKE_SAMPLE_DATA.TPCDS_SF100TCL.CUSTOMER_DEMOGRAPHICS;

CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_CUSTOMER
    WITH CONTACT (ACCESS_APPROVAL = KPDWADM.DWA_ADM.FINANCE_DEPT)
    AS SELECT * FROM SNOWFLAKE_SAMPLE_DATA.TPCDS_SF100TCL.CUSTOMER;

-- Regional customer copies (zero-copy clones)
CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_US_CUSTOMER CLONE KPDWPRD.DWA_ING.KP_CUSTOMER;
CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_NA_CUSTOMER CLONE KPDWPRD.DWA_ING.KP_CUSTOMER;
CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_SA_CUSTOMER CLONE KPDWPRD.DWA_ING.KP_CUSTOMER;
CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_EU_CUSTOMER CLONE KPDWPRD.DWA_ING.KP_CUSTOMER;
CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_AF_CUSTOMER CLONE KPDWPRD.DWA_ING.KP_CUSTOMER;
CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ING.KP_AS_CUSTOMER CLONE KPDWPRD.DWA_ING.KP_CUSTOMER;

-- Data classification
ALTER TABLE KPDWPRD.DWA_ING.KP_CALLCENTER            SET TAG KPDWADM.DWA_GOV.DATA_CLASSIFICATION = 'High';
ALTER TABLE KPDWPRD.DWA_ING.KP_CUSTOMER              SET TAG KPDWADM.DWA_GOV.DATA_CLASSIFICATION = 'High';
ALTER TABLE KPDWPRD.DWA_ING.KP_CUSTOMER_ADDRESS      SET TAG KPDWADM.DWA_GOV.DATA_CLASSIFICATION = 'High';
ALTER TABLE KPDWPRD.DWA_ING.KP_CUSTOMER_DEMOGRAPHICS SET TAG KPDWADM.DWA_GOV.DATA_CLASSIFICATION = 'High';
ALTER TABLE KPDWPRD.DWA_ING.KP_CATALOG_RETURNS       SET TAG KPDWADM.DWA_GOV.DATA_CLASSIFICATION = 'Medium';
ALTER TABLE KPDWPRD.DWA_ING.KP_CATALOG_PAGE          SET TAG KPDWADM.DWA_GOV.DATA_CLASSIFICATION = 'Low';

---------------------------------------------------------------------------
-- 5.2 Analytics layer: KPDWPRD.DWA_ANA
---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ANA.KP_CAMPAIGN_DATA
    WITH CONTACT (ACCESS_APPROVAL = KPDWADM.DWA_ADM.FINANCE_DEPT)
    AS SELECT * FROM KPDWPRD.DWA_ING.KP_CALLCENTER;

CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ANA.KP_MONTHLY_CATALOG
    WITH CONTACT (ACCESS_APPROVAL = KPDWADM.DWA_ADM.FINANCE_DEPT)
    AS SELECT * FROM KPDWPRD.DWA_ING.KP_CATALOG_PAGE;

CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ANA.CUSTOMER_LOCS
    WITH CONTACT (ACCESS_APPROVAL = KPDWADM.DWA_ADM.FINANCE_DEPT)
    AS SELECT * FROM KPDWPRD.DWA_ING.KP_CUSTOMER_ADDRESS;

-- REVIEW: Trust Center security findings are copied into analytics and will
-- be cloned to every non-prod database. Consider relocating to KPDWADM.
CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ANA.KP_FINDINGS_DATA
    WITH CONTACT (ACCESS_APPROVAL = KPDWADM.DWA_ADM.SECURITY_OFFICERS)
    AS SELECT * FROM SNOWFLAKE.TRUST_CENTER.FINDINGS;

CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ANA.KP_JOBS_DATA
    WITH CONTACT (ACCESS_APPROVAL = KPDWADM.DWA_ADM.SECURITY_OFFICERS)
    AS SELECT * FROM SNOWFLAKE.TRUST_CENTER.ASYNC_JOBS;

CREATE TABLE IF NOT EXISTS KPDWPRD.DWA_ANA.KP_SCANS
    WITH CONTACT (ACCESS_APPROVAL = KPDWADM.DWA_ADM.SECURITY_OFFICERS)
    AS SELECT * FROM SNOWFLAKE.TRUST_CENTER.SCANNERS;


/*=============================================================================
  5b. GIT INTEGRATION  (KPDWADM.DWA_ADM)
  Secret KPDWADM.DWA_ADM.GIT_SEC001 is created MANUALLY before this script
  runs (credentials are never stored in source control).
  IF NOT EXISTS is used instead of OR REPLACE so re-runs don't break the
  dbt project or grants that depend on these objects.
=============================================================================*/
CREATE API INTEGRATION IF NOT EXISTS GIT_API_INTEGRATION001
    API_PROVIDER                   = git_https_api
    API_ALLOWED_PREFIXES           = ('https://github.com/kptelemetry')
    ALLOWED_AUTHENTICATION_SECRETS = (KPDWADM.DWA_ADM.GIT_SEC001)
    ENABLED                        = TRUE
    COMMENT                        = 'GitHub access for kptelemetry repositories';

-- Enforce settings even if the integration pre-existed with different values
ALTER API INTEGRATION GIT_API_INTEGRATION001 SET
    API_ALLOWED_PREFIXES           = ('https://github.com/kptelemetry')
    ALLOWED_AUTHENTICATION_SECRETS = (KPDWADM.DWA_ADM.GIT_SEC001)
    ENABLED                        = TRUE;

CREATE GIT REPOSITORY IF NOT EXISTS KPDWADM.DWA_ADM.KP_GIT_REPO
    API_INTEGRATION = GIT_API_INTEGRATION001
    GIT_CREDENTIALS = KPDWADM.DWA_ADM.GIT_SEC001
    ORIGIN          = 'https://github.com/kptelemetry/dev001.git';


/*=============================================================================
  6. DBT PROJECT  (KPDWPRD.DWA_DBT, sourced from the Git repository)
  TODO: confirm branch and project path. profiles.yml currently defines only a
        `dev` target; add a `prod` target pointing at KPDWPRD and switch ARGS.
=============================================================================*/
USE WAREHOUSE WH_DBT_ALL;

ALTER GIT REPOSITORY KPDWADM.DWA_ADM.KP_GIT_REPO FETCH;

CREATE DBT PROJECT IF NOT EXISTS KPDWPRD.DWA_DBT.KPT_DBT_PRJ001
    FROM '@KPDWADM.DWA_ADM.KP_GIT_REPO/branches/main/tasty_bytes_2'
    DBT_VERSION = '1.9.4';

EXECUTE DBT PROJECT KPDWPRD.DWA_DBT.KPT_DBT_PRJ001
    ARGS = 'run --target dev';

USE WAREHOUSE WH_OPER_ALL;


/*=============================================================================
  7. APPLY RBAC TO PRD + SHARED GRANTS
=============================================================================*/
CALL KPDWADM.DWA_ADM.SP_SETUP_DATABASE_RBAC('KPDWPRD');

-- Git repository: developers read/write, read-only users read
GRANT USAGE ON DATABASE KPDWADM                         TO ROLE RL_NONPROD_DSS_ETL;
GRANT USAGE ON SCHEMA   KPDWADM.DWA_ADM                 TO ROLE RL_NONPROD_DSS_ETL;
GRANT READ, WRITE ON GIT REPOSITORY KPDWADM.DWA_ADM.KP_GIT_REPO TO ROLE RL_NONPROD_DSS_ETL;
GRANT USAGE ON DATABASE KPDWADM                         TO ROLE RL_NONPROD_ALL_READONLY;
GRANT USAGE ON SCHEMA   KPDWADM.DWA_ADM                 TO ROLE RL_NONPROD_ALL_READONLY;
GRANT READ ON GIT REPOSITORY KPDWADM.DWA_ADM.KP_GIT_REPO TO ROLE RL_NONPROD_ALL_READONLY;

-- Git-connected Snowsight workspaces: integration + secret for all users
-- (users inherit RL_NONPROD_ALL_READONLY through their USR_ROLE_* role)
GRANT USAGE ON INTEGRATION GIT_API_INTEGRATION001         TO ROLE RL_NONPROD_ALL_READONLY;
GRANT USAGE ON SECRET KPDWADM.DWA_ADM.GIT_SEC001          TO ROLE RL_NONPROD_ALL_READONLY;
GRANT USAGE ON INTEGRATION GIT_API_INTEGRATION001         TO ROLE RL_NONPROD_DSS_ETL;
GRANT USAGE ON SECRET KPDWADM.DWA_ADM.GIT_SEC001          TO ROLE RL_NONPROD_DSS_ETL;

-- Tag administration: governance schema only
GRANT USAGE ON DATABASE KPDWADM          TO ROLE RL_TAG_ADMIN;
GRANT USAGE ON SCHEMA   KPDWADM.DWA_GOV  TO ROLE RL_TAG_ADMIN;
GRANT CREATE TAG ON SCHEMA KPDWADM.DWA_GOV TO ROLE RL_TAG_ADMIN;


/*=============================================================================
  8. REFRESH NON-PROD FROM PRD  (replaces non-prod schemas - by design)
  Afterwards: run `terraform apply` to recreate internal stages.
=============================================================================*/
CALL KPDWADM.DWA_ADM.SP_REFRESH_NONPROD_FROM_PRD('KPDWDEV');
CALL KPDWADM.DWA_ADM.SP_REFRESH_NONPROD_FROM_PRD('KPDWTST');
CALL KPDWADM.DWA_ADM.SP_REFRESH_NONPROD_FROM_PRD('KPDWPPD');
CALL KPDWADM.DWA_ADM.SP_REFRESH_NONPROD_FROM_PRD('KPDWSTG');
