# Lookups for splunk-savedsearches.conf

| file | who fills it | used by |
|---|---|---|
| llm_api_domains.csv | shipped; a versioned snapshot (Morpheus rule: external context is pinned, never fetched live) - add your providers, bump `snapshot` | R-B-AGT-004, R-C-AGT-003-M, baseline |
| agt_scheduled_clients.csv | you: uptime monitors, authorized scanners | R-B-AGT-002, R-B-AGT-002-M |
| agt_host_roles.csv | you / CMDB export: `server` or other | R-B-AGT-004, R-D-AGT-016 |
| agt_asset_ip.csv | you / CMDB: IP to hostname, so network-keyed and host-keyed rules join in the chain | R-D-AGT-001, 002, 004, 011, 015, 016, R-C-AGT-001 |
| agt_sp_change_actors.csv | you: automation identities allowed to change app credentials / AWS keys | R-B-AGT-008, R-D-AGT-009 |
| agt_host_history.csv, agt_host_llm_seen.csv, agt_web_proc_pairs.csv | **header-only seeds, shipped**: the baselines read them back with `inputlookup`, which errors on a missing file, so upload these before the first run; then the `AGT baseline - *` searches accumulate them nightly | detections |
| agt_http_client_peak.csv, agt_identity_op_envelope.csv | generated fresh by their baseline searches; run the baselines for 7+ days before enabling the behavioral detections (warm-up) | detections |

Only api.deepseek.com, open.bigmodel.cn, api.x.ai, api.anthropic.com and xcai.pro are named in the reporting. The rest are coverage choices: ARTEX takes any OpenAI-compatible endpoint. All are legitimate services, so never use this list as a blocklist.
