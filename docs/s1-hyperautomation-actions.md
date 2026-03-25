# SentinelOne Hyperautomation — Cloudflare Actions Reference

Documented from available actions in the SentinelOne Hyperautomation platform.

## IP Access Rules
| Action | Use Case |
|---|---|
| `Create an IP Access rule` | Block attacker IP at zone level |
| `Delete an IP Access rule` | Remove rule after threat resolved |
| `Update an IP Access rule` | Change mode (block → challenge → allow) |
| `List IP Access rules` | Audit current block list |
| `Get IP Overview` | Enrich attacker IP with ASN, geo, threat intel |

## Firewall Rules
| Action | Use Case |
|---|---|
| `Create firewall rules` | Create expression-based rules (e.g., block country + URI combo) |
| `Delete a firewall rule` | Clean up temporary rules |
| `Update a firewall rule` | Change action (block, challenge, log) |
| `Update priority of firewall rule` | Promote a new rule above existing ones |
| `Get a firewall rule` | Inspect a specific rule |
| `Get firewall rules` | List all active rules |

## WAF
| Action | Use Case |
|---|---|
| `Get a WAF package` | Inspect WAF ruleset status |
| `Get a WAF rule` | Check if a specific rule is enabled |
| `List WAF packages` | Enumerate rulesets |
| `List WAF rules` | Full rule inventory |
| `Update a WAF package` | Enable/disable entire ruleset |
| `Update a WAF rule` | Change sensitivity or action for a specific rule |

## DNS Firewall / DNS Records
| Action | Use Case |
|---|---|
| `Create DNS Firewall Cluster` | Block C2/tunneling domain at DNS layer |
| `Delete DNS Firewall Cluster` | Remove after remediation |
| `Update dns firewall` | Adjust upstream DNS settings |
| `List DNS Firewall Clusters` | Audit DNS protection |
| `DNS Firewall Cluster Details` | Inspect cluster config |
| `Create DNS Record` | Sinkhole a domain (point to 0.0.0.0) |
| `Delete DNS Record` | Remove sinkhole |
| `Update DNS Record` | Modify sinkhole target |
| `List DNS Records` | Audit DNS zone |
| `DNS Record Details` | Inspect specific record |
| `Export DNS Records` | Full zone export for forensics |

## Zero Trust / Access
| Action | Use Case |
|---|---|
| `Get zero trust user failed logins` | Gather evidence on credential attack |
| `Get zero trust users` | List users for context / disable |
| `Get user audit logs` | Full audit trail for incident |

## PCAP / Forensics
| Action | Use Case |
|---|---|
| `Create PCAP request` | Capture live traffic for forensic analysis |
| `Create simple pcap` | Lightweight capture |
| `Get PCAP request` | Check capture status |
| `Download Simple PCAP` | Retrieve capture file |
| `List packet capture requests` | Audit captures |

## Zone Management
| Action | Use Case |
|---|---|
| `Edit Zone` | Modify zone security level (e.g., escalate to "Under Attack") |
| `Zone Details` | Inspect zone config |
| `List Zones` | Enumerate zones |
| `Create Zone` | Provision new zone |
| `Delete Zone in Cloudflare` | Decommission |

## Load Balancer
| Action | Use Case |
|---|---|
| `Create Load Balancer` | Failover during DDoS |
| `Update load balancer` | Shift traffic away from attacked origin |
| `Delete Load Balancer` | Decommission |
| `List load balancers` | Audit |
| `Search load balancer resources` | Find resources |

## Logging / Storage
| Action | Use Case |
|---|---|
| `Update log retention flag` | Preserve evidence — extend log retention |
| `Create Bucket` | Create R2 bucket for log archive |
| `Delete Bucket` | Clean up |

## Workers
| Action | Use Case |
|---|---|
| `List Workers` | Identify suspicious/unexpected Worker deployments |

## Other
| Action | Use Case |
|---|---|
| `JD Cloud IP Details` | IP enrichment |
| `Get billing profile` | Detect unexpected resource creation (cost anomaly) |
