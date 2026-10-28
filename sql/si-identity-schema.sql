-- si-identity-schema.sql -- the IDENTITY LEDGER store (V3-ARCHITECTURE 2.3a).
--
-- Holds the one thing SI cannot recompute: which real-world object an anchor belongs to.
-- Everything else in SI is derived from a fresh snapshot every run and needs no memory. This does,
-- because a ServiceNow CI binds to SI_CorrelationId permanently and that id must not move when a
-- source times out, an anchor rotates, or a member joins the group.
--
-- ADDITIVE AND IDEMPOTENT ONLY, and that is enforced, not merely intended: every statement is guarded
-- so re-running is a no-op, and Test-SISchemaIsAdditive refuses this file if a destructive verb ever
-- appears in it. Reverting a schema add could drop a column with data, which is why PIM marks its
-- schema step non-rollbackable and why this one is too.
--
-- 🔒 SCHEMA-1 (DOCS/REQUIREMENTS.md, resolved 2026-08-13): applying this to a customer database
-- requires an EXPLICIT, RECORDED approval for THAT customer and THAT schema version. Absent one the
-- schema step refuses and reports -- it does not skip silently, and it does not apply.

IF SCHEMA_ID('si') IS NULL EXEC ('CREATE SCHEMA si');

-- ---------------------------------------------------------------------------------------------
-- The ledger: one row per ANCHOR, many anchors per object.
-- Anchors are how we RECOGNISE an asset; they are never what we CALL it.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('si.ObjectIdentity') IS NULL
CREATE TABLE si.ObjectIdentity (
    IdentifierType   NVARCHAR(64)  NOT NULL,   -- canonical, e.g. ExposureGraphNodeId
    IdentifierValue  NVARCHAR(256) NOT NULL,   -- lower-cased at write time
    SI_CorrelationId NVARCHAR(64)  NOT NULL,   -- the minted UUIDv5, never re-derived at runtime
    FirstSeen        DATETIME2(0)  NOT NULL,   -- decides which id survives a MERGE
    LastSeen         DATETIME2(0)  NOT NULL,
    -- Composite PK on the anchor, NOT on the id: an anchor belongs to exactly one object at a time,
    -- and that uniqueness is the invariant the whole ledger rests on. Enforce it in the database
    -- rather than trusting every future caller to check.
    CONSTRAINT PK_ObjectIdentity PRIMARY KEY (IdentifierType, IdentifierValue)
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ObjectIdentity_CorrelationId')
CREATE INDEX IX_ObjectIdentity_CorrelationId ON si.ObjectIdentity (SI_CorrelationId);

-- ---------------------------------------------------------------------------------------------
-- Superseded ids. THIS is the "data is not synced later under another id" guarantee: on a merge the
-- connector is handed old -> new and reconciles its CI, instead of orphaning one and creating another.
-- Rows are never deleted -- an id that ever existed may still be referenced by a CI somewhere.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('si.ObjectIdentitySuperseded') IS NULL
CREATE TABLE si.ObjectIdentitySuperseded (
    OldId       NVARCHAR(64) NOT NULL,
    NewId       NVARCHAR(64) NOT NULL,
    SupersededAt DATETIME2(0) NOT NULL,
    Reason      NVARCHAR(200) NULL,
    CONSTRAINT PK_ObjectIdentitySuperseded PRIMARY KEY (OldId)
);

-- ---------------------------------------------------------------------------------------------
-- Applied schema versions. The schema step reads this to decide whether work is needed, and the
-- SCHEMA-1 gate reads it to prove an approval was recorded BEFORE the apply, not after.
-- ---------------------------------------------------------------------------------------------
IF OBJECT_ID('si.SchemaVersion') IS NULL
CREATE TABLE si.SchemaVersion (
    SchemaVersion NVARCHAR(32)  NOT NULL,
    AppliedAt     DATETIME2(0)  NOT NULL,
    AppliedBy     NVARCHAR(128) NOT NULL,
    ApprovedBy    NVARCHAR(128) NOT NULL,   -- NOT NULL on purpose: an unapproved apply cannot be recorded
    ApprovalRef   NVARCHAR(200) NULL,
    CONSTRAINT PK_SchemaVersion PRIMARY KEY (SchemaVersion)
);
