# EDR-integration analyzers. Dispatches payloads to a Whiskers agent on a
# user-managed EDR VM, then queries the user's local EDR backend (e.g. an
# Elastic stack) for alerts raised against the run.
#
# See ROADMAP.md (Phase L) for the architecture, and Config/edr_profiles/
# *.yml.example for the per-profile schema.
