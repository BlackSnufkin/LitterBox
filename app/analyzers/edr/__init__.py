# EDR-integration analyzers. Dispatches payloads to a Whiskers agent on a
# user-managed EDR VM, then resolves alerts via a profile-specific path:
#   * kind: elastic   — queries an Elastic Detection-Engine cluster.
#   * kind: fibratus  — polls Whiskers's /api/alerts/fibratus/since which
#                       wevtutil-queries the Windows Application event log.
#
# See Config/edr_profiles/*.yml.example for the per-kind schema.
