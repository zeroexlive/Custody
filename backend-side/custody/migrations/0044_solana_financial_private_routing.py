"""Prevent financial-customer legacy private fallback before allocation."""

from django.db import migrations

FORWARD = r"""
-- Intentionally VOLATILE: the lookup runs after the asset/parent lock and must
-- see a financial enrollment that committed while this transaction waited.
CREATE FUNCTION custody_sol_fin_customer_route(owner_ref text, asset_ref text)
RETURNS boolean AS $$
 SELECT EXISTS (
   SELECT 1 FROM custody_mpcsolanafinancialwallet f
   JOIN custody_mpcsolanaclaim c ON c.reservation_id=f.claim_id
   JOIN custody_custodyprincipal p ON p.principal_id=c.principal_id
   JOIN custody_mpcsolanaroot r ON r.keyset_id=c.root_id
   JOIN custody_asset asset ON asset.id=c.asset_id
   WHERE f.role='CUSTOMER_DEPOSIT' AND r.tenant_id=p.tenant_id
     AND 'p1:'||p.principal_id::text=owner_ref AND asset.chain_id='SOL'
     AND asset.asset_key=asset_ref
 );
$$ LANGUAGE sql VOLATILE;

CREATE FUNCTION custody_sol_fin_route_attempt_guard() RETURNS trigger AS $$
DECLARE request_row custody_withdrawalrequest%ROWTYPE;
DECLARE needs_typed boolean:=false;
BEGIN
 IF NEW.chain_id<>'SOL' THEN RETURN NEW; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN
   RAISE EXCEPTION 'Solana private routing requires READ COMMITTED'; END IF;
 IF TG_OP='UPDATE' AND NOT (NEW.status='SIGNING' AND OLD.status<>'SIGNING') THEN RETURN NEW; END IF;
 PERFORM 1 FROM custody_asset WHERE asset_key=NEW.asset_key AND chain_id='SOL' FOR UPDATE;
 IF NEW.operation_type='WITHDRAWAL' THEN
   SELECT * INTO request_row FROM custody_withdrawalrequest WHERE id=NEW.operation_id;
   needs_typed:=FOUND AND custody_sol_fin_customer_route(request_row.user_id,request_row.asset_key);
   IF EXISTS (SELECT 1 FROM custody_mpcsolanafinancialoperation WHERE
   withdrawal_id=NEW.operation_id) THEN
     RETURN NEW; END IF;
 ELSIF NEW.operation_type='SWEEP' THEN
   needs_typed:=EXISTS (SELECT 1 FROM custody_sweepjob s JOIN custody_userwallet u ON
   u.id=s.user_wallet_id
      WHERE s.id=NEW.operation_id AND u.solana_claim_id IS NOT NULL);
   IF EXISTS (SELECT 1 FROM custody_mpcsolanafinancialoperation WHERE
   sweep_id=NEW.operation_id) THEN
     RETURN NEW; END IF;
 END IF;
 IF needs_typed THEN RAISE EXCEPTION
   'financial customer cannot start a legacy private attempt'; END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER a_sol_fin_route_attempt BEFORE INSERT OR UPDATE ON custody_onchaintransactionattempt
FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_route_attempt_guard();

CREATE FUNCTION custody_sol_fin_route_session_guard() RETURNS trigger AS $$
DECLARE attempt_row custody_onchaintransactionattempt%ROWTYPE;
DECLARE request_row custody_withdrawalrequest%ROWTYPE;
DECLARE needs_typed boolean:=false;
BEGIN
 SELECT * INTO STRICT attempt_row FROM custody_onchaintransactionattempt WHERE id=NEW.attempt_id;
 IF attempt_row.chain_id<>'SOL' THEN RETURN NEW; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN
   RAISE EXCEPTION 'Solana private session routing requires READ COMMITTED'; END IF;
 IF TG_OP='UPDATE' AND NOT (NEW.status='STARTING' AND OLD.status<>'STARTING') THEN RETURN NEW;
   END IF;
 PERFORM 1 FROM custody_asset WHERE asset_key=attempt_row.asset_key AND chain_id='SOL' FOR UPDATE;
 IF attempt_row.operation_type='WITHDRAWAL' THEN
   SELECT * INTO request_row FROM custody_withdrawalrequest WHERE id=attempt_row.operation_id;
   needs_typed:=FOUND AND custody_sol_fin_customer_route(request_row.user_id,request_row.asset_key);
   IF EXISTS (SELECT 1 FROM custody_mpcsolanafinancialoperation
              WHERE withdrawal_id=attempt_row.operation_id) THEN RETURN NEW; END IF;
 ELSIF attempt_row.operation_type='SWEEP' THEN
   needs_typed:=EXISTS (SELECT 1 FROM custody_sweepjob s JOIN custody_userwallet u ON
   u.id=s.user_wallet_id
      WHERE s.id=attempt_row.operation_id AND u.solana_claim_id IS NOT NULL);
   IF EXISTS (SELECT 1 FROM custody_mpcsolanafinancialoperation
              WHERE sweep_id=attempt_row.operation_id) THEN RETURN NEW; END IF;
 END IF;
 IF needs_typed THEN RAISE EXCEPTION 'financial customer cannot enter generic MPC signing'; END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER a_sol_fin_route_session BEFORE INSERT OR UPDATE ON custody_mpcsigningsession
FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_route_session_guard();

CREATE FUNCTION custody_sol_fin_route_enrollment_guard() RETURNS trigger AS $$
DECLARE claim_row custody_mpcsolanaclaim%ROWTYPE;
DECLARE owner_ref text;
DECLARE asset_ref text;
DECLARE asset_precision integer;
BEGIN
 IF NEW.role<>'CUSTOMER_DEPOSIT' THEN RETURN NEW; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN
   RAISE EXCEPTION 'financial enrollment requires READ COMMITTED'; END IF;
 SELECT * INTO STRICT claim_row FROM custody_mpcsolanaclaim WHERE reservation_id=NEW.claim_id;
 SELECT asset_key,decimals INTO STRICT asset_ref,asset_precision
   FROM custody_asset WHERE id=claim_row.asset_id FOR UPDATE;
 owner_ref:='p1:'||claim_row.principal_id::text;
 IF EXISTS (
   SELECT 1 FROM custody_onchaintransactionattempt a
   JOIN custody_withdrawalrequest w ON w.id=a.operation_id
   WHERE a.operation_type='WITHDRAWAL'
     AND w.user_id=owner_ref AND w.chain_id='SOL' AND w.asset_key=asset_ref AND (
       a.chain_id<>w.chain_id OR a.asset_key<>w.asset_key OR a.amount<>w.amount
       OR a.to_address<>w.to_address
       OR a.base_unit_amount<>w.amount*power(10::numeric,asset_precision)
       OR
       NOT coalesce(((a.status IN ('CONFIRMED','FAILED') AND a.signed_payload<>''
           AND a.network_tx_id IS NOT NULL AND a.confirmation_metadata->'finalized'='true'::jsonb
           AND a.confirmation_metadata->>'signature'=a.network_tx_id
           AND CASE WHEN jsonb_typeof(a.confirmation_metadata->'slot')='number'
             THEN (a.confirmation_metadata->>'slot')::numeric>0 ELSE false END)
         OR (a.status='FAILED' AND a.error_code='PREPARATION_FAILED' AND a.signed_payload=''
           AND NOT EXISTS (SELECT 1 FROM custody_mpcsigningsession WHERE attempt_id=a.id))),false)
       OR EXISTS (SELECT 1 FROM custody_mpcsigningsession WHERE attempt_id=a.id
          AND status NOT IN ('COMPLETED','FAILED'))
     )
 ) THEN RAISE EXCEPTION 'resolve original legacy financial attempts before enrollment'; END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER a_sol_fin_route_enrollment BEFORE INSERT ON custody_mpcsolanafinancialwallet
FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_route_enrollment_guard();

CREATE FUNCTION custody_sol_fin_unallocated_parent_guard() RETURNS trigger AS $$
BEGIN
 IF TG_OP='DELETE' THEN
   IF OLD.chain_id='SOL' AND current_setting('transaction_isolation')<>'read committed' THEN
     RAISE EXCEPTION 'Solana financial deletion requires READ COMMITTED'; END IF;
   IF OLD.chain_id='SOL' AND custody_sol_fin_customer_route(OLD.user_id,OLD.asset_key) THEN
     RAISE EXCEPTION 'original financial request history cannot be deleted'; END IF;
   RETURN OLD;
 END IF;
 IF OLD.chain_id<>'SOL' AND NEW.chain_id<>'SOL' THEN RETURN NEW; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN
   RAISE EXCEPTION 'Solana financial parent requires READ COMMITTED'; END IF;
 IF custody_sol_fin_customer_route(OLD.user_id,OLD.asset_key)
    OR custody_sol_fin_customer_route(NEW.user_id,NEW.asset_key) THEN
   IF (to_jsonb(NEW)-ARRAY['status','tx_hash','admin_notes','updated_at']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['status','tx_hash','admin_notes','updated_at'])
      OR (OLD.status IN ('DENIED','CONFIRMED','FAILED')
        AND ROW(NEW.status,NEW.tx_hash) IS DISTINCT FROM ROW(OLD.status,OLD.tx_hash)) THEN
     RAISE EXCEPTION 'financial request identity/terminal state is immutable'; END IF;
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER a_sol_fin_unallocated_parent BEFORE UPDATE OR DELETE ON custody_withdrawalrequest
FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_unallocated_parent_guard();

CREATE FUNCTION custody_sol_fin_unallocated_outcome(request_row custody_withdrawalrequest,
                                                   releasing boolean) RETURNS boolean AS $$
DECLARE attempt_row custody_onchaintransactionattempt%ROWTYPE;
BEGIN
 IF releasing AND request_row.status='DENIED' AND NOT EXISTS (
   SELECT 1 FROM custody_onchaintransactionattempt
    WHERE operation_type='WITHDRAWAL' AND operation_id=request_row.id) THEN RETURN true; END IF;
 SELECT * INTO attempt_row FROM custody_onchaintransactionattempt
   WHERE operation_type='WITHDRAWAL' AND operation_id=request_row.id ORDER BY attempt_number
   DESC LIMIT 1;
 RETURN FOUND AND attempt_row.signed_payload<>'' AND attempt_row.network_tx_id IS NOT NULL
   AND attempt_row.chain_id=request_row.chain_id AND attempt_row.asset_key=request_row.asset_key
   AND attempt_row.to_address=request_row.to_address AND attempt_row.amount=request_row.amount
   AND attempt_row.base_unit_amount=request_row.amount*power(10::numeric,
      (SELECT decimals FROM custody_asset WHERE asset_key=request_row.asset_key
       AND chain_id=request_row.chain_id))
   AND attempt_row.confirmation_metadata->>'signature'=attempt_row.network_tx_id
   AND CASE WHEN jsonb_typeof(attempt_row.confirmation_metadata->'slot')='number'
     THEN (attempt_row.confirmation_metadata->>'slot')::numeric>0 ELSE false END
   AND attempt_row.confirmation_metadata->'finalized'='true'::jsonb
   AND ((releasing AND attempt_row.status='FAILED'
         AND attempt_row.confirmation_metadata->'err' IS NOT NULL
         AND attempt_row.confirmation_metadata->'err'<>'null'::jsonb)
      OR (NOT releasing AND attempt_row.status='CONFIRMED'
         AND attempt_row.confirmation_metadata->'err'='null'::jsonb));
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION custody_sol_fin_unallocated_journal_guard() RETURNS trigger AS $$
DECLARE request_row custody_withdrawalrequest%ROWTYPE;
DECLARE releasing boolean;
BEGIN
 IF NEW.ref_type<>'WithdrawalRequest' OR NEW.event_type NOT IN
   ('WITHDRAWAL_RELEASE','WITHDRAWAL_SETTLE') THEN
   RETURN NEW; END IF;
 SELECT * INTO request_row FROM custody_withdrawalrequest WHERE id::text=NEW.ref_id;
 IF NOT FOUND OR request_row.chain_id<>'SOL' THEN RETURN NEW; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN
   RAISE EXCEPTION 'Solana financial journal requires READ COMMITTED'; END IF;
 SELECT * INTO STRICT request_row FROM custody_withdrawalrequest WHERE id=request_row.id FOR
   UPDATE NOWAIT;
 IF EXISTS (SELECT 1 FROM custody_mpcsolanafinancialoperation WHERE withdrawal_id=request_row.id)
    OR NOT custody_sol_fin_customer_route(request_row.user_id,request_row.asset_key) THEN
   RETURN NEW; END IF;
 releasing:=NEW.event_type='WITHDRAWAL_RELEASE';
 IF NOT coalesce(custody_sol_fin_unallocated_outcome(request_row,releasing),false)
    OR NEW.asset_key<>request_row.asset_key
    OR NEW.event_key<>'withdrawal:'||request_row.id::text||':'||
       (CASE WHEN releasing THEN 'release' ELSE 'settle' END)
    OR EXISTS (SELECT 1 FROM custody_ledgertransaction WHERE event_key=
       'withdrawal:'||request_row.id::text||':'||(CASE WHEN releasing THEN 'settle' ELSE
   'release' END)) THEN
   RAISE EXCEPTION 'financial journal needs safe denial or original finalized outcome'; END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER a_sol_fin_unallocated_journal BEFORE INSERT ON custody_ledgertransaction
FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_unallocated_journal_guard();

CREATE FUNCTION custody_sol_fin_unallocated_consistent() RETURNS trigger AS $$
DECLARE request_row custody_withdrawalrequest%ROWTYPE;
DECLARE journal custody_ledgertransaction%ROWTYPE;
DECLARE releasing boolean;
DECLARE reservation_only boolean:=false;
BEGIN
 IF TG_TABLE_NAME='custody_withdrawalrequest' THEN
   SELECT * INTO STRICT request_row FROM custody_withdrawalrequest WHERE id=NEW.id;
   IF request_row.status NOT IN ('DENIED','CONFIRMED','FAILED') THEN RETURN NULL; END IF;
   releasing:=request_row.status<>'CONFIRMED';
 ELSE
   IF TG_TABLE_NAME='custody_ledgerposting' THEN
     SELECT * INTO STRICT journal FROM custody_ledgertransaction WHERE id=NEW.transaction_id;
   ELSE journal:=NEW; END IF;
   IF journal.ref_type<>'WithdrawalRequest'
      OR journal.event_type NOT IN
   ('WITHDRAWAL_RESERVE','WITHDRAWAL_RELEASE','WITHDRAWAL_SETTLE') THEN RETURN NULL;
   END IF;
   SELECT * INTO request_row FROM custody_withdrawalrequest WHERE id::text=journal.ref_id;
   IF NOT FOUND THEN RETURN NULL; END IF;
   releasing:=journal.event_type='WITHDRAWAL_RELEASE';
   reservation_only:=journal.event_type='WITHDRAWAL_RESERVE';
 END IF;
 IF request_row.chain_id='SOL' AND current_setting('transaction_isolation')<>'read committed' THEN
   RAISE EXCEPTION 'Solana journal consistency requires READ COMMITTED'; END IF;
 IF request_row.chain_id<>'SOL' OR NOT
   custody_sol_fin_customer_route(request_row.user_id,request_row.asset_key)
    OR EXISTS (SELECT 1 FROM custody_mpcsolanafinancialoperation WHERE
   withdrawal_id=request_row.id) THEN
   RETURN NULL; END IF;
 IF reservation_only THEN
   IF journal.event_key<>'withdrawal:'||request_row.id::text||':reserve'
      OR journal.asset_key<>request_row.asset_key
      OR (SELECT count(*) FROM custody_ledgerposting WHERE transaction_id=journal.id)<>2
      OR (SELECT coalesce(sum(p.amount),0) FROM custody_ledgerposting p WHERE
   transaction_id=journal.id)<>0
      OR (SELECT count(*) FROM custody_ledgerposting p JOIN custody_ledgeraccount la ON
   la.id=p.account_id
          WHERE p.transaction_id=journal.id AND la.asset_key=request_row.asset_key
            AND la.owner_type='USER' AND la.owner_id=request_row.user_id AND (
              (la.bucket='AVAILABLE' AND p.amount=-request_row.amount)
              OR (la.bucket='RESERVED' AND p.amount=request_row.amount)))<>2 THEN
     RAISE EXCEPTION 'original unallocated financial reserve posting set is immutable'; END IF;
   RETURN NULL;
 END IF;
 SELECT * INTO journal FROM custody_ledgertransaction WHERE event_key=
   'withdrawal:'||request_row.id::text||':'||(CASE WHEN releasing THEN 'release' ELSE 'settle' END);
 IF NOT FOUND OR NOT coalesce(custody_sol_fin_unallocated_outcome(request_row,releasing),false)
    OR (releasing AND request_row.status NOT IN ('DENIED','FAILED'))
    OR (NOT releasing AND request_row.status<>'CONFIRMED')
    OR journal.event_type<>(CASE WHEN releasing THEN 'WITHDRAWAL_RELEASE' ELSE
   'WITHDRAWAL_SETTLE' END)
    OR journal.asset_key<>request_row.asset_key OR journal.ref_type<>'WithdrawalRequest'
    OR journal.ref_id<>request_row.id::text
    OR (SELECT count(*) FROM custody_ledgerposting WHERE transaction_id=journal.id)<>2
    OR (SELECT coalesce(sum(p.amount),0) FROM custody_ledgerposting p WHERE
   transaction_id=journal.id)<>0
    OR (SELECT count(*) FROM custody_ledgerposting p JOIN custody_ledgeraccount la ON
   la.id=p.account_id
        WHERE p.transaction_id=journal.id AND la.asset_key=request_row.asset_key AND (
          (la.owner_type='USER' AND la.owner_id=request_row.user_id AND la.bucket='RESERVED'
            AND p.amount=-request_row.amount) OR
          (p.amount=request_row.amount AND ((releasing AND la.owner_type='USER'
            AND la.owner_id=request_row.user_id AND la.bucket='AVAILABLE') OR
            (NOT releasing AND la.owner_type='SYSTEM' AND la.owner_id='custody'
              AND la.bucket='CUSTODY_CLEARING')))))<>2 THEN
   RAISE EXCEPTION 'unallocated financial terminal state requires original balanced journal';
   END IF;
 IF TG_TABLE_NAME='custody_withdrawalrequest' THEN
   IF NEW.status='DENIED' AND OLD.status<>'DENIED' AND NOT EXISTS (
      SELECT 1 FROM custody_adminactionlog WHERE action_type='WITHDRAWAL_DENY'
       AND entity_type='WithdrawalRequest' AND entity_id=request_row.id::text) THEN
     RAISE EXCEPTION 'financial denial requires its mandatory audit'; END IF;
 END IF;
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER custody_sol_fin_unallocated_parent_consistent
AFTER UPDATE ON custody_withdrawalrequest DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_unallocated_consistent();
CREATE CONSTRAINT TRIGGER custody_sol_fin_unallocated_journal_consistent
AFTER INSERT ON custody_ledgertransaction DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_unallocated_consistent();
CREATE CONSTRAINT TRIGGER custody_sol_fin_unallocated_posting_consistent
AFTER INSERT ON custody_ledgerposting DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_unallocated_consistent();

CREATE FUNCTION custody_sol_fin_customer_journal_immutable() RETURNS trigger AS $$
DECLARE journal custody_ledgertransaction%ROWTYPE;
DECLARE request_row custody_withdrawalrequest%ROWTYPE;
DECLARE side_number integer;
BEGIN
 FOR side_number IN 1..(CASE WHEN TG_OP='UPDATE' THEN 2 ELSE 1 END) LOOP
   IF TG_TABLE_NAME='custody_ledgerposting' THEN
     SELECT * INTO STRICT journal FROM custody_ledgertransaction WHERE id=
       (CASE WHEN side_number=1 THEN OLD.transaction_id ELSE NEW.transaction_id END);
   ELSE
     IF side_number=1 THEN journal:=OLD; ELSE journal:=NEW; END IF;
   END IF;
   IF journal.ref_type='WithdrawalRequest' THEN
     SELECT * INTO request_row FROM custody_withdrawalrequest WHERE id::text=journal.ref_id;
     IF FOUND AND request_row.chain_id='SOL' THEN
       IF current_setting('transaction_isolation')<>'read committed' THEN
         RAISE EXCEPTION 'Solana customer journal mutation requires READ COMMITTED'; END IF;
       IF custody_sol_fin_customer_route(request_row.user_id,request_row.asset_key) THEN
         RAISE EXCEPTION 'original financial customer journal is append-only'; END IF;
     END IF;
   END IF;
 END LOOP;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER a_sol_fin_customer_journal_immutable BEFORE UPDATE OR DELETE ON
   custody_ledgertransaction
FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_customer_journal_immutable();
CREATE TRIGGER a_sol_fin_customer_posting_immutable BEFORE UPDATE OR DELETE ON custody_ledgerposting
FOR EACH ROW EXECUTE FUNCTION custody_sol_fin_customer_journal_immutable();

"""

REVERSE = r"""
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM custody_mpcsolanafinancialwallet) THEN
   RAISE EXCEPTION 'financial customer routing history cannot be downgraded'; END IF;
END $$;
DROP TRIGGER custody_sol_fin_unallocated_posting_consistent ON custody_ledgerposting;
DROP TRIGGER custody_sol_fin_unallocated_journal_consistent ON custody_ledgertransaction;
DROP TRIGGER custody_sol_fin_unallocated_parent_consistent ON custody_withdrawalrequest;
DROP FUNCTION custody_sol_fin_unallocated_consistent();
DROP TRIGGER a_sol_fin_unallocated_journal ON custody_ledgertransaction;
DROP FUNCTION custody_sol_fin_unallocated_journal_guard();
DROP FUNCTION custody_sol_fin_unallocated_outcome(custody_withdrawalrequest,boolean);
DROP TRIGGER a_sol_fin_unallocated_parent ON custody_withdrawalrequest;
DROP FUNCTION custody_sol_fin_unallocated_parent_guard();
DROP TRIGGER a_sol_fin_route_enrollment ON custody_mpcsolanafinancialwallet;
DROP FUNCTION custody_sol_fin_route_enrollment_guard();
DROP TRIGGER a_sol_fin_route_session ON custody_mpcsigningsession;
DROP FUNCTION custody_sol_fin_route_session_guard();
DROP TRIGGER a_sol_fin_route_attempt ON custody_onchaintransactionattempt;
DROP FUNCTION custody_sol_fin_route_attempt_guard();
DROP TRIGGER a_sol_fin_customer_posting_immutable ON custody_ledgerposting;
DROP TRIGGER a_sol_fin_customer_journal_immutable ON custody_ledgertransaction;
DROP FUNCTION custody_sol_fin_customer_journal_immutable();
DROP FUNCTION custody_sol_fin_customer_route(text,text);
"""


def install(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(FORWARD, params=None)


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(REVERSE, params=None)


class Migration(migrations.Migration):
    dependencies = [("custody", "0043_solana_seeded_deposit_provenance")]
    operations = [migrations.RunPython(install, uninstall)]
