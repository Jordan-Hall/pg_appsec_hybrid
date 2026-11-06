-- Run as an authenticated database Manager/operator in a disposable database.
-- Access levels: 0 No Access, 1 Depositor, 2 Reader, 3 Author,
-- 4 Editor, 5 Designer, 6 Manager.

-- Grant a user Reader access to the database, then document Readers further narrow visibility.
SELECT appsec.set_database_acl('*', 'user', '00000000-0000-0000-0000-000000000002', 2);

-- Grant a group Author access; users still edit only documents in whose Authors list they appear.
SELECT appsec.set_database_acl('*', 'group', '00000000-0000-0000-0000-000000000010', 3);

-- Grant a user Editor access to all documents in this database resource.
SELECT appsec.set_database_acl('documents', 'user', '00000000-0000-0000-0000-000000000003', 4);

-- Grant a user Depositor access: can create documents but cannot read existing ones.
SELECT appsec.set_database_acl('documents', 'user', '00000000-0000-0000-0000-000000000004', 1);

-- Assign field-level JSONB policy. App roles are managed in appsec.user_roles.
SELECT appsec.set_jsonb_field_policy(
  'documents.body', '{finance,bank_account}',
  ARRAY['finance.reader','finance.admin'], ARRAY['finance.admin']
);

-- The document owner can grant additional readers/authors after creation.
SELECT appsec.add_document_reader('00000000-0000-0000-0000-000000000100', '00000000-0000-0000-0000-000000000002');
SELECT appsec.add_document_author('00000000-0000-0000-0000-000000000100', '00000000-0000-0000-0000-000000000003');
