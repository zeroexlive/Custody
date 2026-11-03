"""Intent expiry remains live through preparation/approval/private-start commit."""

from django.db import migrations

FORWARD = r"""
CREATE FUNCTION custody_sol_fin_intent_deadline_guard() RETURNS trigger AS $$
BEGIN
 IF NEW.status IN ('WAITING_POLICY','READY','IN_PROGRESS')
    AND OLD.status IS DISTINCT FROM NEW.status THEN
   IF ((NEW.intent->>'expires_at') ~ '^[0-9]+$') IS NOT TRUE
      OR ((NEW.intent->>'issued_at') ~ '^[0-9]+$') IS NOT TRUE
      OR (NEW.intent->>'expires_at')::numeric <= extract(epoch FROM clock_timestamp())
      OR (NEW.intent->>'expires_at')::numeric <= (NEW.intent->>'issued_at')::numeric
      OR (NEW.intent->>'expires_at')::numeric - (NEW.intent->>'issued_at')::numeric > 300
      OR (NEW.intent->>'issued_at')::numeric > extract(epoch FROM clock_timestamp()) THEN
     RAISE EXCEPTION 'original financial intent expired or invalid before commit'; END IF;
 END IF;
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER custody_sol_fin_session_deadline
AFTER UPDATE ON custody_mpcsolanafinancialsession DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_intent_deadline_guard();
"""

REVERSE = r"""
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM custody_mpcsolanafinancialsession WHERE intent<>'{}'::jsonb) THEN
   RAISE EXCEPTION 'prepared financial history cannot lose its deadline guard'; END IF;
END $$;
DROP TRIGGER custody_sol_fin_session_deadline ON custody_mpcsolanafinancialsession;
DROP FUNCTION custody_sol_fin_intent_deadline_guard();
"""


def install(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(FORWARD, params=None)


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(REVERSE, params=None)


class Migration(migrations.Migration):
    dependencies = [("custody", "0039_solana_financial_sessions")]
    operations = [migrations.RunPython(install, uninstall)]
