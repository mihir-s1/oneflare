// ============================================================================
// DETECTION BODY (scheduled rule): DNS tunneling / C2 beaconing
// OneFlare lab — Cloudflare Gateway DNS. MITRE T1071.004, T1048.
// ----------------------------------------------------------------------------
// Alert-safe: NO arrays, NO subqueries, NO nolimit/compare. One row per finding
// (source host + zone). This is the exact text that goes into
// data.scheduledParams.query (see dns-tunneling.rule.json, JSON-escaped there).
//
// entityMappings (asset binding): src_ip, host, device_uid  (<=3 columns).
// device_uid binds the Target Asset only after the asset-enrichment solution
// populates device.uid on Cloudflare events; until then the alert still fires
// but shows "Unknown Device" (bind via src_ip/host).
// ============================================================================

class_uid=4003 dataSource.cloudflare_dataset='Gateway DNS' unmapped.QueryName=*
| let fqdn        = lower(unmapped.QueryName)
| let label       = replace(fqdn, '\\..*', '')
| let zone        = replace(fqdn, '^.*\\.([^.]+\\.[^.]+\\.[^.]+)$', '$1')
| let label_len   = len(label)
| let digit_cnt   = len(replace(label, '[^0-9]', ''))
| let digit_ratio = label_len > 0 ? digit_cnt / label_len : 0
| let is_txt      = query.type in:anycase ('txt')
| let src_ip      = src_endpoint.ip
| let host        = device.name
| group
    total_queries = count(),
    uniq_labels   = estimate_distinct(label),
    max_label_len = max(label_len),
    long_labels   = count(label_len >= 40),
    txt_long      = count(is_txt AND label_len >= 20),
    hi_entropy    = count(label_len >= 12 AND digit_ratio >= 0.15),
    device_uid    = any(device.uid),
    evidence      = max_by(unmapped.QueryName, label_len),
    first_seen    = oldest(timestamp),
    last_seen     = newest(timestamp)
  by src_ip, host, zone
// Corroboration required — each branch needs CLUSTERING, not one weak signal.
// A single long label is NOT enough: a DNS label is capped at 63 chars by spec,
// so a legit SaaS/CDN host (e.g. saas.atlassian.com, leftmost label 61 chars)
// is indistinguishable from a tunnel on max_label_len alone — that clause was
// removed after it produced a false positive in testing (see README). Tunneling
// shows up as MANY long, UNIQUE labels; DGA as high unique-subdomain volume;
// exfil as repeated long TXT. max_label_len stays as evidence, never a trigger.
// Volume alone is NOT a signal — legit cloud services (Azure/AWS/CDN) resolve
// dozens of unique, structured subdomains (observed FP: cloudapp.azure.com, 67
// unique labels, 0 entropy). Real DGA/tunneling labels are RANDOM: high entropy
// (digit-mixed) or long. So the high-volume branch is gated on hi_entropy, and
// every branch requires clustering. (Attack: uniq=33/hi=28/long=10/txt=3.)
| filter (hi_entropy >= 10 AND uniq_labels >= 10) OR (long_labels >= 5 AND uniq_labels >= 5) OR txt_long >= 3
| let reason = txt_long >= 3 ? 'Data-in-DNS exfil (TXT long labels)' : ((long_labels >= 5 AND uniq_labels >= 5) ? 'Long-label DNS tunneling' : 'DGA / high-entropy beaconing')
| let detection_time = simpledateformat(last_seen, 'yyyy-MM-dd HH:mm:ss z', 'America/Chicago')
| sort -uniq_labels
// detection_time (most-recent matching query in the window) is projected FIRST.
| columns detection_time, src_ip, host, zone, reason, total_queries, uniq_labels, long_labels, txt_long, hi_entropy, max_label_len, evidence, device_uid, first_seen
| limit 100
