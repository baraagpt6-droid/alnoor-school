-- Auditable queue for user-submitted account/data deletion requests.
CREATE TABLE IF NOT EXISTS public.account_deletion_requests (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 request_reference text NOT NULL UNIQUE,
 account_id uuid NULL,
 login_id text NOT NULL,
 account_role text NULL CHECK (account_role IS NULL OR account_role IN ('admin','teacher','student','parent')),
 contact_phone text NOT NULL,
 request_source text NOT NULL CHECK (request_source IN ('web','in-app')),
 request_ip_hash text NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','verified','completed','rejected')),
 requested_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 resolved_at timestamptz NULL,
 resolution_note text NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS account_deletion_requests_one_pending_per_login ON public.account_deletion_requests(login_id) WHERE status='pending';
CREATE INDEX IF NOT EXISTS account_deletion_requests_status_date_idx ON public.account_deletion_requests(status, requested_at DESC);
CREATE INDEX IF NOT EXISTS account_deletion_requests_ip_date_idx ON public.account_deletion_requests(request_ip_hash, requested_at DESC);
DO $grant$
BEGIN
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='alnoor_school_api') THEN
  GRANT SELECT, INSERT, UPDATE, DELETE ON public.account_deletion_requests TO alnoor_school_api;
 END IF;
END
$grant$;
