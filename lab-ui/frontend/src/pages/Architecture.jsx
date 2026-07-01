import { ArrowRight, Server, Shield, Database, Globe, Cpu, AlertCircle } from 'lucide-react'

const WORKERS = [
  {
    name: 'Shop Worker',
    description: 'NovaMind webstore — WAF attack surface',
    url: 'https://novamind-shop.novamind-lab.workers.dev',
    routes: ['/search', '/products', '/reviews'],
    color: 'orange',
    borderClass: 'border-orange-500/30',
    bgClass: 'bg-orange-500/5',
    textClass: 'text-orange-400',
  },
  {
    name: 'Portal Worker',
    description: 'Cloudflare Access-protected admin portal',
    url: 'https://novamind-portal.novamind-lab.workers.dev',
    routes: ['/login', '/dashboard'],
    color: 'purple',
    borderClass: 'border-purple-500/30',
    bgClass: 'bg-purple-500/5',
    textClass: 'text-purple-400',
  },
  {
    name: 'API Worker',
    description: 'REST API with bulk export endpoint',
    url: 'https://novamind-api.novamind-lab.workers.dev',
    routes: ['/api/v1/auth/login', '/api/v1/customers/export'],
    color: 'blue',
    borderClass: 'border-blue-500/30',
    bgClass: 'bg-blue-500/5',
    textClass: 'text-blue-400',
  },
]

const FLOW_NODES = [
  {
    label: 'Attack Scripts',
    sublabel: 'Python / FastAPI',
    items: ['demo.py', '01_sqli.py', '02_xss.py', '03_path_traversal.py', '04_cred_stuffing.py', '05_dns_tunnel.py', '06_data_exfil.py'],
    icon: Cpu,
    color: 'text-slate-400',
    borderClass: 'border-slate-600/40',
    bgClass: 'bg-slate-800/40',
    dotColor: 'bg-slate-500',
  },
  {
    label: 'Cloudflare',
    sublabel: 'Security Stack',
    items: ['WAF / Firewall Rules', 'Gateway (DNS)', 'Access (ZTNA)', 'Workers (Apps)', 'Logpush → SIEM'],
    icon: Shield,
    color: 'text-orange-400',
    borderClass: 'border-orange-500/30',
    bgClass: 'bg-orange-500/5',
    dotColor: 'bg-orange-400',
  },
  {
    label: 'SentinelOne',
    sublabel: 'Detection & Response',
    items: ['Logpush Ingestion', 'STAR Detections', 'Hyperautomation', 'CF API Actions', 'Incident Stories'],
    icon: Database,
    color: 'text-purple-400',
    borderClass: 'border-purple-500/30',
    bgClass: 'bg-purple-500/5',
    dotColor: 'bg-purple-400',
  },
]

export default function Architecture() {
  return (
    <div className="page-enter space-y-8 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Lab Architecture</h1>
        <p className="text-sm text-slate-400 mt-1">
          How attack scripts, Cloudflare controls, and SentinelOne detections connect
        </p>
      </div>

      {/* Architecture diagram */}
      <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] p-6">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-6 flex items-center gap-2">
          <Globe className="w-4 h-4 text-orange-400" />
          Data Flow Diagram
        </h2>

        {/* Three column layout with arrows */}
        <div className="flex flex-col md:flex-row items-stretch gap-0">
          {FLOW_NODES.map((node, i) => {
            const Icon = node.icon
            return (
              <div key={node.label} className="flex md:flex-row items-center flex-1">
                {/* Node card */}
                <div className={`flex-1 rounded-xl border p-4 ${node.borderClass} ${node.bgClass}`}>
                  <div className="flex items-center gap-2 mb-3">
                    <Icon className={`w-4 h-4 ${node.color}`} />
                    <div>
                      <div className={`text-sm font-bold ${node.color}`}>{node.label}</div>
                      <div className="text-xs text-slate-500">{node.sublabel}</div>
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    {node.items.map((item, j) => (
                      <div key={j} className="flex items-center gap-2 text-xs text-slate-400">
                        <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${node.dotColor}`} />
                        <span className="font-mono">{item}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Arrow between nodes */}
                {i < FLOW_NODES.length - 1 && (
                  <div className="flex items-center justify-center shrink-0 px-3 py-6 md:py-0 md:px-4">
                    <div className="flex flex-col md:flex-row items-center gap-1">
                      <div className="hidden md:block h-px w-8 bg-gradient-to-r from-orange-500/50 to-purple-500/50" />
                      <ArrowRight className="w-5 h-5 text-slate-500 md:text-orange-500/60 rotate-90 md:rotate-0" />
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>

        {/* Flow labels below */}
        <div className="hidden md:grid grid-cols-[1fr_auto_1fr_auto_1fr] gap-0 mt-3">
          <div className="text-center">
            <span className="text-xs text-slate-600 font-mono">HTTP/DNS requests</span>
          </div>
          <div />
          <div className="text-center">
            <span className="text-xs text-slate-600 font-mono">Logpush → S1 (~60s)</span>
          </div>
          <div />
          <div className="text-center">
            <span className="text-xs text-slate-600 font-mono">STAR → Response</span>
          </div>
        </div>
      </div>

      {/* Detailed flow */}
      <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] p-6">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-5 flex items-center gap-2">
          <ArrowRight className="w-4 h-4 text-purple-400" />
          End-to-End Attack Flow
        </h2>

        <div className="space-y-0">
          {[
            {
              step: '01',
              title: 'Attack Script Executes',
              desc: 'Python script sends malicious HTTP requests or DNS queries to the target NovaMind Worker endpoint',
              color: 'text-slate-400',
              bg: 'bg-slate-500/10',
              border: 'border-slate-500/20',
            },
            {
              step: '02',
              title: 'Cloudflare Intercepts',
              desc: 'WAF, Gateway DNS, or Access evaluates the request. Matching rules block or log the traffic and emit a structured event',
              color: 'text-orange-400',
              bg: 'bg-orange-500/10',
              border: 'border-orange-500/20',
            },
            {
              step: '03',
              title: 'Logpush Streams Events',
              desc: 'Cloudflare Logpush sends JSON log events to SentinelOne in near real-time (typically within 60 seconds)',
              color: 'text-yellow-400',
              bg: 'bg-yellow-500/10',
              border: 'border-yellow-500/20',
            },
            {
              step: '04',
              title: 'STAR Rule Fires',
              desc: 'SentinelOne STAR engine evaluates incoming log events against custom detection rules. Threshold breaches create an alert',
              color: 'text-purple-400',
              bg: 'bg-purple-500/10',
              border: 'border-purple-500/20',
            },
            {
              step: '05',
              title: 'Hyperautomation Responds',
              desc: 'SentinelOne Hyperautomation playbook executes: enriches IP, creates block rules via CF API, captures PCAP, notifies SOC',
              color: 'text-green-400',
              bg: 'bg-green-500/10',
              border: 'border-green-500/20',
            },
          ].map((item, i, arr) => (
            <div key={item.step} className="flex gap-3">
              <div className="flex flex-col items-center shrink-0">
                <div className={`w-9 h-9 rounded-xl flex items-center justify-center text-xs font-mono font-bold border ${item.bg} ${item.border} ${item.color}`}>
                  {item.step}
                </div>
                {i < arr.length - 1 && (
                  <div className="w-px flex-1 bg-gradient-to-b from-[#2d1b4e] to-transparent min-h-[28px] my-1" />
                )}
              </div>
              <div className="flex-1 pt-1 pb-5">
                <div className={`text-sm font-semibold mb-1 ${item.color}`}>{item.title}</div>
                <p className="text-sm text-slate-400 leading-relaxed">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Workers table */}
      <div className="rounded-xl border border-[#2d1b4e] overflow-hidden">
        <div className="px-5 py-4 bg-[#1a0a2e] border-b border-[#2d1b4e] flex items-center gap-2">
          <Server className="w-4 h-4 text-orange-400" />
          <h2 className="text-sm font-semibold text-slate-300">NovaMind Lab Workers</h2>
        </div>
        <div className="divide-y divide-[#1e1235]">
          {WORKERS.map(worker => (
            <div key={worker.name} className="p-5 hover:bg-white/[0.02] transition-colors">
              <div className="flex items-start gap-4 flex-wrap">
                <div className={`shrink-0 rounded-xl px-3 py-2 border text-xs font-bold font-mono ${worker.borderClass} ${worker.bgClass} ${worker.textClass}`}>
                  {worker.name}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-slate-300 mb-1">{worker.description}</div>
                  <a href={worker.url} target="_blank" rel="noopener noreferrer"
                    className={`text-xs font-mono ${worker.textClass} mb-2 hover:underline inline-block`}>
                    {worker.url}
                  </a>
                  <div className="flex flex-wrap gap-2">
                    {worker.routes.map(route => (
                      <span key={route} className="text-xs font-mono text-slate-500 bg-white/5 border border-white/10 rounded px-2 py-0.5">
                        {route}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Logpush note */}
      <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4 flex gap-3">
        <AlertCircle className="w-5 h-5 text-yellow-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-semibold text-yellow-300 mb-1">Logpush Configuration Required</p>
          <p className="text-sm text-slate-400 leading-relaxed">
            For detections to flow from Cloudflare to SentinelOne, configure a Logpush job in your Cloudflare dashboard:
            <strong className="text-slate-300"> Analytics → Logpush → Create job</strong>. Select HTTP Requests, Firewall Events, Gateway DNS, and Access Audit logs. Set the destination to your SentinelOne HTTP input endpoint.
          </p>
        </div>
      </div>
    </div>
  )
}
