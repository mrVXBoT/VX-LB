# Web panel operation feedback and responsiveness

Pool creation, tunnel changes, pool deletion and node deletion now keep progress
near the top of each pool card. Secondary connection/monitoring information and
advanced management controls are collapsed; failures stay visible with clearly labeled retry and inventory-only deletion actions.

## Performance and live behavior

- `/api/status` uses one loaded inventory snapshot for all node telemetry and
  server counts. Previously each member triggered another inventory load through
  `get_node_telemetry`, plus two reads for server counts. Domain configuration
  still has its own constant-size configuration read.
- Authenticated `/api/events` sends only invalidation revisions, never inventory
  contents. It notices atomic inventory replacements, checks session validity,
  flushes changes and sends a heartbeat every 15 seconds. Proxy buffering is
  disabled. The browser coalesces invalidations before fetching a fresh snapshot.
- Reconnection reconciles a fresh snapshot. Polling remains a fallback: every
  second during active work, every four seconds while idle, and every 15 seconds
  as reconciliation while streaming works. Hidden tabs close the stream.
- Unchanged cards keep their DOM nodes. Changed cards preserve open details and
  matching keyboard focus. Creation and terminal transitions update even when
  the user has focus inside the pool list.
- Busy creation/deletion admission rejects promptly before waiting for the SSH
  worker's mutation lock, then rechecks under the lock to serialize admission.
- HTTP requests time out (10 seconds for reads; 20 seconds for submissions).
  A timed-out submission does not imply that server work stopped; inline feedback
  tells the user to verify the operation before retrying.

## Truthful operation results

Creation counts come from persisted provisioned members, not elapsed time or log
line counts. Phase labels represent coarse callback activity; elapsed time is not
an ETA. Deletion does not show an invented percentage. Workers preserve failed
resources for retry, reject stale node-removal jobs, and never replay removal after
an internal TypeError. Inventory credentials are redacted from public job errors.

A deleted pool's terminal task remains visible in a compact dismissible notice
(up to five recent tasks). Failed deletion shows inventory-only deletion and retry directly, with a description of each outcome. Neither action is hidden behind a disclosure. Changed SSH host keys receive a Persian explanation, while raw technical details are collapsible. Closing an error uses a labeled text button so it cannot be mistaken for deleting the resource. Inventory-only deletion still requires explicit confirmation.
Confirmation cancellation, including Escape/backdrop/close, resolves the pending
confirmation so a subsequent retry can proceed. Pool filtering cannot hide the
global mutation lock.

## Verification

- Local focused Python suite: 212 passed, including lifecycle, creation, pool
  tasks, node removal, event authentication/revocation/heartbeat/atomic replacement,
  and a 100-member status snapshot read-count regression.
- Existing browser request/presentation suite and JavaScript syntax pass.
- Real headless Chromium with mocked API responses: viewport widths 360, 390,
  768 and 1440; no horizontal document overflow or uncaught page errors; live
  progress/completion while focused, preserved details/focus, unchanged card
  identity, safe retry, confirmation cancellation, inline HTTP errors, deleted-pool
  feedback, stream fallback, and the global mutation lock. The creation sheet is
  also checked at mobile and desktop widths.
- CI runs the complete Python suite and the same Playwright browser regression;
  screenshots and JUnit results are uploaded as workflow artifacts.

These browser tests use synthetic inventory and API responses. They validate UI
behavior, not SSH provisioning speed or a production reverse proxy. No live user
servers were changed. Real remote setup/cleanup still takes as long as the target
servers require; the panel now explains and follows that work.
