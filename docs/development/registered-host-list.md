# Registered hosts in the Console

The Nodes page loads registered hosts automatically through `GET /api/v1/hosts`. The server reads its existing SQLite registration records and returns only hosts covered by the current caller's exact active `host.read` grants. It does not connect to managed machines, rediscover them, or grant access. The collection is sorted by host ID and capped at 1,000 visible registrations. If that bound is exceeded, the request fails without returning a misleading partial list.

Select **Inspect <host ID>** to open the existing registration details and baseline/role admission checks. The manual host-ID inspection field remains available. Successful registration runs refresh the host queries automatically. **Refresh registered hosts** rereads the collection; failed reads show an error rather than presenting an empty inventory. An empty successful read means no registered hosts are visible to that account.

Registration and inventory drafts remain separate. A registered host is shown as registered; workload admission still requires the applicable current checks. This feature does not deploy the Console, choose a control host, qualify physical machines or authorize live onboarding.
