"""Durable exact dispatch before private I/O; fresh signature ownership at commit."""

from django.db import migrations

FORWARD = r"""
CREATE FUNCTION custody_sol_fin_dispatch_guard() RETURNS trigger AS $$
DECLARE q custody_mpcsolanafinancialquery%ROWTYPE;
DECLARE c custody_mpcsolanaclaim%ROWTYPE;
DECLARE item record;
BEGIN
 IF OLD.coordinator_evidence ? 'request' THEN
   IF (NEW.coordinator_evidence-ARRAY['response','reports']) IS DISTINCT FROM
      (OLD.coordinator_evidence-ARRAY['response','reports']) THEN
     RAISE EXCEPTION 'original dispatch request/observation identity cannot change'; END IF;
   FOR item IN SELECT * FROM jsonb_each(OLD.coordinator_evidence->'reports') LOOP
     IF NEW.coordinator_evidence->'reports'->item.key IS DISTINCT FROM item.value THEN
       RAISE EXCEPTION 'original public report cache cannot be erased or replaced'; END IF;
   END LOOP;
 END IF;
 IF NEW.status='IN_PROGRESS' AND OLD.status='READY' THEN
   SELECT c0.* INTO STRICT c FROM custody_mpcsolanaclaim c0
     JOIN custody_mpcsolanafinancialoperation o ON o.source_id=c0.reservation_id
     WHERE o.reservation_id=NEW.operation_id;
   SELECT * INTO STRICT q FROM custody_mpcsolanafinancialquery
     WHERE challenge=NEW.coordinator_evidence->>'dispatch_query';
   IF q.session_id<>NEW.session_id OR q.purpose<>'ADMISSION' OR q.status<>'VERIFIED'
      OR q.expires_at<=clock_timestamp()
      OR NEW.coordinator_evidence->'request'->'witness' IS DISTINCT FROM q.evidence
      OR NEW.coordinator_evidence->'request'->'binding' IS DISTINCT FROM jsonb_build_object(
        'selected_signers',NEW.selected_signers,'authorized',jsonb_build_object(
          'intent',NEW.intent,'payload_hex',encode(NEW.payload,'hex'),
          'claim_evidence',c.evidence,'custody_authorization',NEW.custody_authorization,
          'operator_authorization',NEW.policy_authorization)) THEN
     RAISE EXCEPTION 'exact committed dispatch and fresh original query required'; END IF;
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER custody_sol_fin_dispatch_identity BEFORE UPDATE
ON custody_mpcsolanafinancialsession FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_dispatch_guard();

CREATE FUNCTION custody_sol_fin_dispatch_deadline() RETURNS trigger AS $$
DECLARE q custody_mpcsolanafinancialquery%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='custody_mpcsolanafinancialsession' THEN
   IF NEW.status<>'IN_PROGRESS' OR OLD.status<>'READY' THEN RETURN NULL; END IF;
   SELECT * INTO STRICT q FROM custody_mpcsolanafinancialquery
     WHERE challenge=NEW.coordinator_evidence->>'dispatch_query';
 ELSE
   SELECT * INTO STRICT q FROM custody_mpcsolanafinancialquery
     WHERE challenge=NEW.evidence->'value'->'query'->>'challenge';
   IF q.session_id<>NEW.session_id OR q.purpose<>'RECOVERY' OR q.status<>'VERIFIED'
      OR q.evidence IS DISTINCT FROM NEW.evidence
      OR NEW.evidence->'value'->'execution'->>'status' IS DISTINCT FROM 'SignedPending'
      OR NEW.evidence->'value'->'execution'->>'signature' IS DISTINCT FROM
         (SELECT signature_hex FROM custody_mpcsolanafinancialsession
           WHERE session_id=NEW.session_id) THEN
     RAISE EXCEPTION 'exact verified witness signature recovery required'; END IF;
 END IF;
 IF q.expires_at<=clock_timestamp() THEN
   RAISE EXCEPTION 'financial dispatch/signature query expired before commit'; END IF;
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER custody_sol_fin_dispatch_freshness
AFTER UPDATE ON custody_mpcsolanafinancialsession DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_dispatch_deadline();
CREATE CONSTRAINT TRIGGER custody_sol_fin_signature_freshness
AFTER INSERT ON custody_mpcsolanasignatureowner DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_dispatch_deadline();
"""

REVERSE = r"""
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM custody_mpcsolanafinancialsession WHERE coordinator_evidence<>'{}'::jsonb)
    OR EXISTS (SELECT 1 FROM custody_mpcsolanasignatureowner) THEN
   RAISE EXCEPTION 'dispatched financial history cannot lose its guards'; END IF;
END $$;
DROP TRIGGER custody_sol_fin_signature_freshness ON custody_mpcsolanasignatureowner;
DROP TRIGGER custody_sol_fin_dispatch_freshness ON custody_mpcsolanafinancialsession;
DROP FUNCTION custody_sol_fin_dispatch_deadline();
DROP TRIGGER custody_sol_fin_dispatch_identity ON custody_mpcsolanafinancialsession;
DROP FUNCTION custody_sol_fin_dispatch_guard();
"""


def install(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(FORWARD, params=None)


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(REVERSE, params=None)


class Migration(migrations.Migration):
    dependencies = [("custody", "0040_solana_financial_preparation")]
    operations = [migrations.RunPython(install, uninstall)]
