-- Keep legacy identities intact: earlier versions permitted duplicate names.
-- Guards prevent every new collision, including direct SQL writes and races,
-- without renaming existing Cedar principals or deleting their audit history.
CREATE INDEX clients_tenant_name ON clients (tenant, name);

CREATE TRIGGER clients_unique_name_insert
BEFORE INSERT ON clients
WHEN EXISTS (SELECT 1 FROM clients WHERE tenant = NEW.tenant AND name = NEW.name)
BEGIN
  SELECT RAISE(ABORT, 'Client name already exists in this workspace. Choose a different name.');
END;

CREATE TRIGGER clients_unique_name_update
BEFORE UPDATE OF tenant, name ON clients
WHEN (NEW.tenant != OLD.tenant OR NEW.name != OLD.name)
  AND EXISTS (
    SELECT 1 FROM clients
    WHERE tenant = NEW.tenant AND name = NEW.name AND id != OLD.id
  )
BEGIN
  SELECT RAISE(ABORT, 'Client name already exists in this workspace. Choose a different name.');
END;
