// The status page at / on the admin listener: it polls /ui/status.json and shows the node's health, the cluster, and
// the hub's counters, turning them into rates between polls. Alpine's CSP build runs the page's expressions without
// eval, so the page's Content-Security-Policy allows scripts from this server only.
import Alpine from '@alpinejs/csp'
import './ui.css'

const POLL_MS = 3000
const THEME_KEY = 'gossiper-theme'

// The page starts dark, whatever the OS prefers, until the user picks light.
function storedTheme() {
  try {
    return localStorage.getItem(THEME_KEY)
  } catch {
    return null
  }
}

function applyTheme(dark) {
  document.documentElement.classList.toggle('dark', dark)
}

applyTheme(storedTheme() !== 'light')

const nf = new Intl.NumberFormat()
const startedFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })

function num(v) {
  return v === undefined || v === null ? '—' : nf.format(v)
}

function rate(v) {
  if (v === null || v === undefined) return '—'
  if (v >= 100) return nf.format(Math.round(v)) + '/s'
  return (Math.round(v * 10) / 10).toFixed(1) + '/s'
}

function bytes(n) {
  if (n === undefined || n === null) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return (i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)) + ' ' + units[i]
}

function duration(s) {
  s = Math.max(0, Math.floor(s))
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60)
  if (d > 0) return d + 'd ' + h + 'h'
  if (h > 0) return h + 'h ' + m + 'm'
  if (m > 0) return m + 'm ' + (s % 60) + 's'
  return s + 's'
}

// The counters whose rates the page shows.
const RATED = ['published', 'delivered', 'applied']

Alpine.data('status', () => ({
  data: null,
  rates: {},
  error: '',
  dark: document.documentElement.classList.contains('dark'),
  lastOK: 0,
  clock: Date.now(),
  timer: null,

  init() {
    this.poll()
    setInterval(() => { this.clock = Date.now() }, 1000)
  },

  async poll() {
    try {
      const r = await fetch('/ui/status.json', { cache: 'no-store' })
      if (!r.ok) throw new Error('HTTP ' + r.status)
      const next = await r.json()
      const prev = this.data
      const rates = {}
      if (prev && prev.node === next.node) {
        const dt = (Date.parse(next.now) - Date.parse(prev.now)) / 1000
        for (const k of RATED) {
          const d = next.hub[k] - prev.hub[k]
          rates[k] = dt > 0 && d >= 0 ? d / dt : null // a restart resets the counters
        }
      }
      this.rates = rates
      this.data = next
      this.error = ''
      this.lastOK = Date.now()
    } catch (e) {
      this.error = 'Cannot reach the server: ' + (e && e.message ? e.message : e) + '. Retrying.'
    }
    this.timer = setTimeout(() => this.poll(), POLL_MS)
  },

  toggleTheme() {
    this.dark = !this.dark
    applyTheme(this.dark)
    try {
      localStorage.setItem(THEME_KEY, this.dark ? 'dark' : 'light')
    } catch {
      // not stored: the page starts dark next time
    }
  },

  themeLabel() {
    return this.dark ? 'Switch to the light theme' : 'Switch to the dark theme'
  },

  readinessLabel() {
    if (this.error && this.data) return 'unreachable'
    if (!this.data) return this.error ? 'unreachable' : 'loading'
    return this.data.readiness
  },

  readinessClass() {
    const r = this.readinessLabel()
    if (r === 'ready') return 'ok'
    if (r === 'syncing' || r === 'draining') return 'warn'
    if (r === 'loading') return 'idle'
    return 'bad'
  },

  modeLabel() {
    const d = this.data
    if (!d) return ''
    const mode = d.mode === 'cluster' ? 'Cluster of ' + d.node_count : 'Single node'
    return mode + ' · ' + (d.multi_tenant ? 'multi-tenant' : 'single hub')
  },

  nodes() {
    return this.data ? this.data.nodes : []
  },

  nodesSummary() {
    const d = this.data
    if (!d) return ''
    return d.nodes_alive + ' alive of ' + d.node_count
  },

  stateClass(s) {
    if (s === 'alive') return 'ok'
    if (s === 'suspect' || s === 'leaving') return 'warn'
    if (s === 'dead') return 'bad'
    return 'idle'
  },

  tiles() {
    const d = this.data
    if (!d) return []
    const h = d.hub
    return [
      { label: 'Subscribers', value: num(h.subscribers), sub: 'open streams' },
      { label: 'Publishes', value: rate(this.rates.published), sub: num(h.published) + ' total' },
      { label: 'Events delivered', value: rate(this.rates.delivered), sub: num(h.delivered) + ' total' },
      { label: 'Updates applied', value: rate(this.rates.applied), sub: num(h.applied) + ' total' },
      { label: 'History', value: num(h.history_updates), sub: bytes(h.history_bytes) },
      {
        label: 'Tenants', value: d.multi_tenant ? num(d.tenants.total) : '—',
        sub: d.multi_tenant ? num(d.tenants.file) + ' file · ' + num(d.tenants.database) + ' database' : 'single hub',
      },
      { label: 'Nodes', value: num(d.node_count), sub: num(d.nodes_alive) + ' alive' },
      { label: 'Uptime', value: duration(d.uptime_seconds), sub: 'since ' + startedFmt.format(new Date(d.started)) },
    ]
  },

  counters() {
    const d = this.data
    if (!d) return []
    const h = d.hub
    const rows = [
      { label: 'Dropped subscribers', value: num(h.dropped), warn: h.dropped > 0 },
      { label: 'Publishes refused', value: num(h.publish_rejected), warn: false },
      { label: 'Replayed events', value: num(h.replayed), warn: false },
      { label: 'Replay misses', value: num(h.replay_misses), warn: false },
      { label: 'Duplicates ignored', value: num(h.duplicates), warn: false },
      { label: 'Refused (clock ahead)', value: num(h.refused), warn: h.refused > 0 },
      { label: 'Key sets failing', value: num(h.key_sets_failing), warn: h.key_sets_failing > 0 },
    ]
    if (d.history_unwritten !== undefined) {
      rows.push({ label: 'History unwritten', value: num(d.history_unwritten), warn: d.history_unwritten > 0 })
    }
    return rows
  },

  storeRows() {
    const d = this.data
    if (!d) return []
    const rows = []
    const s = d.store
    if (s) {
      rows.push(
        { label: 'Records', value: num(s.records), warn: false },
        { label: 'Tombstones', value: num(s.tombstones), warn: false },
      )
      if (d.mode === 'cluster') {
        rows.push(
          { label: 'Peers synced', value: num(s.peers_synced) + ' of ' + num(s.peers), warn: s.peers_synced < s.peers },
          { label: 'Last sync', value: this.ago(s.last_sync), warn: false },
          { label: 'Syncs', value: num(s.syncs), warn: false },
          { label: 'Repairs', value: num(s.repairs), warn: false },
          { label: 'Sync errors', value: num(s.sync_errors), warn: s.sync_errors > 0 },
          { label: 'Push errors', value: num(s.push_errors), warn: s.push_errors > 0 },
        )
      }
    }
    if (d.replication_dropped !== undefined) {
      rows.push({ label: 'Replication dropped', value: num(d.replication_dropped), warn: d.replication_dropped > 0 })
    }
    return rows
  },

  // ago turns a server timestamp into "12s ago", against the server's clock at the last poll.
  ago(ts) {
    if (!ts || !this.data) return '—'
    const s = (Date.parse(this.data.now) - Date.parse(ts)) / 1000 + (this.clock - this.lastOK) / 1000
    return duration(s) + ' ago'
  },

  versionLabel() {
    const d = this.data
    if (!d) return ''
    return 'Version ' + d.version + (d.build_date ? ' (built ' + d.build_date + ')' : '')
  },

  updatedLabel() {
    if (!this.lastOK) return ''
    const s = Math.max(0, Math.round((this.clock - this.lastOK) / 1000))
    return 'Updated ' + (s < 2 ? 'just now' : s + 's ago') + ' · every ' + POLL_MS / 1000 + 's'
  },
}))

Alpine.start()
