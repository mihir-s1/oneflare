// ============================================================================
// HUNT: DNS tunneling / C2 beaconing on Cloudflare Gateway DNS
// OneFlare lab — scenario 05 (attack-scripts/scenarios/05_dns_tunnel.py)
// ----------------------------------------------------------------------------
// Behaviour-based (does NOT hard-code soledrop-lab.workers.dev). Returns one
// row per (source host, DNS zone) with computed label-length, unique-label
// count, digit-ratio ("entropy" proxy), and sample labels so a human can eyeball.
//
// Run ad-hoc via LRQ / powerquery_run over a 1-6h window. Arrays (array_agg_*)
// are used here for eyeballing — they are NOT allowed in the scheduled-rule body
// (see dns-tunneling.detection.pq), which is why the two files differ.
//
// Fields per live SDL export of this tenant's Gateway DNS:
//   class_uid = 4003 (DNS Activity)
//   dataSource.cloudflare_dataset = 'Gateway DNS'
//   unmapped.QueryName            <-- the queried FQDN (OCSF query.hostname is EMPTY here)
//   query.type                    <-- A / AAAA / TXT
//   src_endpoint.ip, device.name, device.uid  <-- source identity
// ============================================================================

class_uid=4003 dataSource.cloudflare_dataset='Gateway DNS' unmapped.QueryName=*
| let fqdn        = lower(unmapped.QueryName)
| let label       = replace(fqdn, '\\..*', '')                                  // leftmost label
| let zone        = replace(fqdn, '^.*\\.([^.]+\\.[^.]+\\.[^.]+)$', '$1')       // rightmost 3 labels (registered-zone proxy)
| let label_len   = len(label)
| let digit_cnt   = len(replace(label, '[^0-9]', ''))                           // digits in leftmost label
| let digit_ratio = label_len > 0 ? digit_cnt / label_len : 0                   // entropy proxy
| let is_txt      = query.type in:anycase ('txt')
| let src_ip      = src_endpoint.ip
| let host        = device.name
| group
    total_queries = count(),
    uniq_labels   = estimate_distinct(label),                                   // distinct leftmost labels under the zone
    max_label_len = max(label_len),
    avg_label_len = avg(label_len),
    long_labels   = count(label_len >= 40),                                     // dnscat2/iodine-style long single labels
    txt_long      = count(is_txt AND label_len >= 20),                          // data-in-DNS exfil (base32 in the query name)
    hi_entropy    = count(label_len >= 12 AND digit_ratio >= 0.15),             // DGA-looking labels
    rec_types     = array_agg_distinct(query.type, 5),
    sample_labels = array_agg_distinct(label, 8),
    first_seen    = oldest(timestamp),
    last_seen     = newest(timestamp)
  by src_ip, host, zone
| filter uniq_labels >= 10 OR long_labels >= 2 OR max_label_len >= 40 OR txt_long >= 2 OR hi_entropy >= 6
| sort -uniq_labels
| limit 100

// ----------------------------------------------------------------------------
// OPTIONAL — raw offending queries (drop the group) to inspect individual rows:
//
// class_uid=4003 dataSource.cloudflare_dataset='Gateway DNS' unmapped.QueryName=*
// | let fqdn        = lower(unmapped.QueryName)
// | let label       = replace(fqdn, '\\..*', '')
// | let label_len   = len(label)
// | let digit_cnt   = len(replace(label, '[^0-9]', ''))
// | let digit_ratio = label_len > 0 ? digit_cnt / label_len : 0
// | filter label_len >= 30 OR (query.type in:anycase ('txt') AND label_len >= 20) OR (label_len >= 12 AND digit_ratio >= 0.15)
// | columns timestamp, src_endpoint.ip, device.name, query.type, unmapped.QueryName, label_len, digit_ratio
// | sort -label_len
// | limit 200
// ----------------------------------------------------------------------------
