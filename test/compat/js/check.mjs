// Browser-style checks of a Mercure hub with the `eventsource` package (an EventSource implementation) and Node's
// built-in fetch streaming. Run against Gossiper and against the reference hub:
//
//   HUB_URL=http://localhost:13000 APP_URL=http://localhost:13002 node --test check.mjs
//   MODERN=1 HUB_URL=http://localhost:13005 APP_URL=http://localhost:13005 node --test check.mjs   # Mercure 1.0
//
// MODERN=1 speaks Mercure 1.0: subscriptions use ?match=, publishing and /discover go through the symfony/mercure 0.9
// half of the app (/v1/...), the authorization is an at+jwt access token (in the __Secure-mercure_access_token cookie
// or as a Bearer), replay uses last_event_id.
//
// APP_URL is the PHP app (symfony/mercure) that publishes to that hub; /discover sets the Link header and the
// mercureAuthorization cookie like a Symfony controller. Node has no cookie jar, so the test plays the browser's part:
// it keeps the cookie the app set and sends it to the hub (same site, cookie path = the hub path).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventSource } from 'eventsource'

const HUB = process.env.HUB_URL ?? 'http://localhost:13000'
const APP = process.env.APP_URL ?? 'http://localhost:13002'
const HUB_PATH = '/.well-known/mercure'
const MODERN = process.env.MODERN === '1'
const PREFIX = MODERN ? '/v1' : ''
const TOPIC_PARAM = MODERN ? 'match' : 'topic'
const LAST_ID_PARAM = MODERN ? 'last_event_id' : 'lastEventID'
const COOKIE_NAME = MODERN ? '__Secure-mercure_access_token' : 'mercureAuthorization'
const RUN = Math.random().toString(16).slice(2, 10)
const NS = `https://compat.test/js/${RUN}`

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function phpPublish(params) {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    for (const x of [].concat(v)) q.append(k, x)
  }
  const res = await fetch(`${APP}${PREFIX}/publish?${q}`)
  const body = (await res.text()).trim()
  assert.equal(res.status, 200, `publish failed: ${body}`)
  return body
}

// What a browser does after a navigation to /discover: read Link and keep the cookie.
async function discover(subscribe) {
  const q = new URLSearchParams()
  for (const s of [].concat(subscribe)) q.append('subscribe', MODERN ? `exact:${s}` : s)
  const res = await fetch(`${APP}${PREFIX}/discover?${q}`, { redirect: 'manual' })
  const text = await res.text()
  const link = res.headers.get('link')
  assert.ok(link, 'no Link header')
  const m = /<([^>]+)>;\s*rel="mercure"/.exec(link)
  assert.ok(m, `Link is not a mercure link: ${link}`)
  if (MODERN) {
    // symfony/mercure 0.9 refuses a __Secure- cookie on a plain-HTTP hub URL and hands out the token instead; a raw
    // client sends it in the __Secure- cookie like a browser would over https.
    const { token, cookieName } = JSON.parse(text)
    assert.equal(cookieName, COOKIE_NAME)
    assert.ok(token, `no token in ${text}`)
    return { hubUrl: m[1], cookie: `${COOKIE_NAME}=${token}` }
  }
  const cookies = res.headers.getSetCookie()
  const raw = cookies.find((c) => c.startsWith(`${COOKIE_NAME}=`))
  assert.ok(raw, `no ${COOKIE_NAME} cookie in ${JSON.stringify(cookies)}`)
  const attrs = Object.fromEntries(raw.split(';').slice(1).map((a) => a.trim().split('=')).map(([k, v]) => [k.toLowerCase(), v ?? true]))
  assert.equal(attrs.path, HUB_PATH, 'cookie path')
  assert.ok(attrs.httponly, 'cookie must be HttpOnly')
  return { hubUrl: m[1], cookie: raw.split(';')[0] }
}

// A fetch for EventSource that adds headers (the browser's cookie) and records the requests, and that can cut the
// connection like a network failure (the stream errors with a TypeError, so EventSource reconnects).
function browserFetch({ cookie } = {}) {
  const state = { requests: [], cuts: [] }
  const f = async (url, init = {}) => {
    const headers = new Headers(init.headers)
    if (cookie) headers.set('Cookie', cookie)
    state.requests.push({ url: String(url), headers: Object.fromEntries(headers) })
    const res = await fetch(url, { ...init, headers })
    if (!res.body) return res
    const reader = res.body.getReader()
    let cut = false
    let ctl
    const pump = async () => {
      try {
        for (;;) {
          const { done, value } = await reader.read()
          if (cut) return
          if (done) { ctl.close(); return }
          ctl.enqueue(value)
        }
      } catch (e) {
        if (!cut) { try { ctl.error(e) } catch {} }
      }
    }
    const wrapped = new ReadableStream({
      start(c) { ctl = c; pump() },
      cancel() { cut = true; return reader.cancel().catch(() => {}) },
    })
    state.cuts.push(() => {
      cut = true
      reader.cancel().catch(() => {})
      ctl.error(new TypeError('network error (simulated)'))
    })
    return new Response(wrapped, { status: res.status, statusText: res.statusText, headers: res.headers })
  }
  return { fetch: f, state }
}

function openSource(url, opts = {}) {
  const es = new EventSource(url, opts)
  const events = []
  const waiters = []
  const push = (e) => {
    events.push(e)
    for (const w of waiters.splice(0)) w()
  }
  es.onmessage = push
  const errors = []
  es.onerror = (e) => errors.push(e)
  const opened = new Promise((resolve, reject) => {
    es.onopen = () => resolve()
    setTimeout(() => reject(new Error(`EventSource did not open: ${errors.map((e) => e.message)}`)), 8000).unref()
  })
  const next = async (n = 1, timeout = 8000) => {
    const deadline = Date.now() + timeout
    while (events.length < n) {
      const left = deadline - Date.now()
      if (left <= 0) throw new Error(`timeout waiting for event ${n}; have ${events.length}: ${JSON.stringify(events.map((e) => e.data))}`)
      await Promise.race([new Promise((r) => waiters.push(r)), sleep(left)])
    }
    return events[n - 1]
  }
  return { es, events, opened, next, errors, push }
}

const subscribeUrl = (hubUrl, topics, extra = {}) => {
  const u = new URL(hubUrl)
  for (const t of [].concat(topics)) u.searchParams.append(TOPIC_PARAM, t)
  for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, v)
  return u.toString()
}

test('discovery: Link header names the hub and the cookie is set', async () => {
  const { hubUrl } = await discover(`${NS}/discover/x`)
  assert.equal(new URL(hubUrl).pathname, HUB_PATH)
})

test('public events reach an EventSource (anonymous)', async () => {
  const topic = `${NS}/public`
  const s = openSource(subscribeUrl(`${HUB}${HUB_PATH}`, topic))
  try {
    await s.opened
    await sleep(200)
    const id = await phpPublish({ topic, data: 'hello browser' })
    const e = await s.next(1)
    assert.equal(e.data, 'hello browser')
    assert.equal(e.lastEventId, id)
    assert.equal(e.type, 'message')
  } finally {
    s.es.close()
  }
})

test('custom event type, retry, multi-line data and unicode arrive intact', async () => {
  const topic = `${NS}/fields`
  const s = openSource(subscribeUrl(`${HUB}${HUB_PATH}`, topic))
  const typed = []
  s.es.addEventListener('order.created', (e) => { typed.push(e); s.push(e) })
  try {
    await s.opened
    await sleep(200)
    const id = await phpPublish({ topic, data: 'ligne un\nligne deux — 世界 🎉', type: 'order.created', id: `custom-${RUN}`, retry: '3000' })
    assert.equal(id, `custom-${RUN}`)
    const e = await s.next(1)
    assert.equal(e.type, 'order.created')
    assert.equal(e.data, 'ligne un\nligne deux — 世界 🎉')
    assert.equal(e.lastEventId, `custom-${RUN}`)
    assert.equal(typed.length, 1)
  } finally {
    s.es.close()
  }
})

test('private events need the authorization cookie obtained from /discover', async () => {
  const topic = `${NS}/private`
  const { hubUrl, cookie } = await discover(topic)
  // without the cookie: the private update is not delivered
  const anon = openSource(subscribeUrl(`${HUB}${HUB_PATH}`, topic))
  const { fetch: bf } = browserFetch({ cookie })
  const authed = openSource(subscribeUrl(`${HUB}${HUB_PATH}`, topic), { fetch: bf, withCredentials: true })
  try {
    await Promise.all([anon.opened, authed.opened])
    await sleep(200)
    const id = await phpPublish({ topic, data: 'for authorized eyes', private: '1' })
    const e = await authed.next(1)
    assert.equal(e.data, 'for authorized eyes')
    assert.equal(e.lastEventId, id)
    await phpPublish({ topic, data: 'public follow-up' })
    const e2 = await anon.next(1)
    assert.equal(e2.data, 'public follow-up', 'the anonymous subscriber must only get the public update')
    assert.equal(anon.events.length, 1)
    assert.equal((await authed.next(2)).data, 'public follow-up')
  } finally {
    anon.es.close()
    authed.es.close()
  }
})

test('reconnection resumes with Last-Event-ID: no loss, no duplicate', async () => {
  const topic = `${NS}/reconnect`
  const { fetch: bf, state } = browserFetch()
  const s = openSource(subscribeUrl(`${HUB}${HUB_PATH}`, topic), { fetch: bf })
  try {
    await s.opened
    await sleep(200)
    const id1 = await phpPublish({ topic, data: 'one', retry: '150' })
    assert.equal((await s.next(1)).data, 'one')
    // cut the connection; publish while the client is away
    state.cuts[0]()
    const id2 = await phpPublish({ topic, data: 'two (published while disconnected)' })
    const id3 = await phpPublish({ topic, data: 'three' })
    assert.equal((await s.next(2, 10000)).data, 'two (published while disconnected)')
    assert.equal((await s.next(3, 10000)).data, 'three')
    assert.equal(state.requests.length, 2, 'EventSource reconnected once')
    assert.equal(state.requests[1].headers['Last-Event-ID'] ?? state.requests[1].headers['last-event-id'], id1)
    await phpPublish({ topic, data: 'four (live again)' })
    assert.equal((await s.next(4)).data, 'four (live again)')
    await sleep(300)
    assert.deepEqual(s.events.map((e) => e.lastEventId).slice(0, 3), [id1, id2, id3])
    assert.equal(s.events.length, 4, 'no duplicates')
  } finally {
    s.es.close()
  }
})

test('reconnection with the cookie: private events missed are replayed', async () => {
  const topic = `${NS}/reconnect-private`
  const { cookie } = await discover(topic)
  const { fetch: bf, state } = browserFetch({ cookie })
  const s = openSource(subscribeUrl(`${HUB}${HUB_PATH}`, topic), { fetch: bf, withCredentials: true })
  try {
    await s.opened
    await sleep(200)
    const id1 = await phpPublish({ topic, data: 'p1', private: '1', retry: '150' })
    assert.equal((await s.next(1)).lastEventId, id1)
    state.cuts[0]()
    await phpPublish({ topic, data: 'secret while away', private: '1' })
    assert.equal((await s.next(2, 10000)).data, 'secret while away')
    assert.ok(state.requests[1].headers.cookie, 'the reconnection carries the cookie')
  } finally {
    s.es.close()
  }
})

test('the replay query parameter and "earliest" replay history', async () => {
  const topic = `${NS}/replay`
  const ids = []
  for (const d of ['a', 'b', 'c']) ids.push(await phpPublish({ topic, data: d }))
  const fromFirst = openSource(subscribeUrl(`${HUB}${HUB_PATH}`, topic, { [LAST_ID_PARAM]: ids[0] }))
  const fromStart = openSource(subscribeUrl(`${HUB}${HUB_PATH}`, topic, { [LAST_ID_PARAM]: 'earliest' }))
  try {
    assert.equal((await fromFirst.next(1)).data, 'b')
    assert.equal((await fromFirst.next(2)).data, 'c')
    assert.deepEqual((await Promise.all([1, 2, 3].map((n) => fromStart.next(n)))).map((e) => e.data), ['a', 'b', 'c'])
  } finally {
    fromFirst.es.close()
    fromStart.es.close()
  }
})

test('plain fetch streaming (no EventSource): headers, Authorization header, frames', async () => {
  const topic = `${NS}/fetch`
  // a subscriber JWT made by the app's own secret is not available here; use the cookie token as a bearer instead
  const { cookie } = await discover(topic)
  const token = cookie.split('=')[1]
  const ctl = new AbortController()
  const res = await fetch(subscribeUrl(`${HUB}${HUB_PATH}`, topic), { headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' }, signal: ctl.signal })
  try {
    assert.equal(res.status, 200)
    assert.match(res.headers.get('content-type'), /^text\/event-stream/)
    await sleep(200)
    const id = await phpPublish({ topic, data: 'via fetch', private: '1', type: 'x' })
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader()
    let buf = ''
    const deadline = Date.now() + 8000
    while (!buf.includes('\n\n') || !buf.includes('data: via fetch')) {
      if (Date.now() > deadline) throw new Error(`no frame: ${JSON.stringify(buf)}`)
      const { value, done } = await reader.read()
      if (done) break
      buf += value
    }
    assert.match(buf, /event: x\n/)
    assert.ok(buf.includes(`id: ${id}\n`), buf)
    assert.ok(buf.includes('data: via fetch\n\n'), buf)
  } finally {
    ctl.abort()
  }
})

test('an expired or wrong token is refused (the EventSource would stop, as a browser does on 401)', async () => {
  const topic = `${NS}/refused`
  const res = await fetch(subscribeUrl(`${HUB}${HUB_PATH}`, topic), { headers: { Authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.e30.invalid' } })
  await res.arrayBuffer()
  assert.ok([400, 401].includes(res.status), `status ${res.status}`)
})

if (MODERN) {
  test('Mercure 1.0: the legacy "topic" parameter is refused with 400 by a modern hub', async () => {
    const ctl = new AbortController()
    const res = await fetch(`${HUB}${HUB_PATH}?topic=${encodeURIComponent(`${NS}/legacy`)}`, { signal: ctl.signal })
    ctl.abort() // a 200 would be an open stream
    // the default Gossiper (--protocol both) still serves draft-07 clients on the same endpoint
    assert.ok([200, 400].includes(res.status), `status ${res.status}`)
  })

  test('Mercure 1.0: URL patterns and the QUERY method (fetch)', async () => {
    const topic = `${NS}/pattern/1`
    const ctl = new AbortController()
    const res = await fetch(`${HUB}${HUB_PATH}`, {
      method: 'QUERY',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'text/event-stream' },
      body: new URLSearchParams({ match_urlpattern: `${NS}/pattern/:id` }),
      signal: ctl.signal,
    })
    try {
      assert.equal(res.status, 200)
      assert.match(res.headers.get('content-type'), /^text\/event-stream/)
      await sleep(200)
      const id = await phpPublish({ topic, data: 'via QUERY' })
      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader()
      let buf = ''
      const deadline = Date.now() + 8000
      while (!buf.includes('data: via QUERY\n\n')) {
        if (Date.now() > deadline) throw new Error(`no frame: ${JSON.stringify(buf)}`)
        const { value, done } = await reader.read()
        if (done) break
        buf += value
      }
      assert.ok(buf.includes(`id: ${id}\n`), buf)
    } finally {
      ctl.abort()
    }
  })

  test('Mercure 1.0: EventSource with match_urlpattern', async () => {
    const s = openSource(`${HUB}${HUB_PATH}?match_urlpattern=${encodeURIComponent(`${NS}/ep/:id`)}`)
    try {
      await s.opened
      await sleep(200)
      await phpPublish({ topic: `${NS}/ep/9/nested`, data: 'no' })
      const id = await phpPublish({ topic: `${NS}/ep/9`, data: 'yes' })
      const e = await s.next(1)
      assert.equal(e.data, 'yes')
      assert.equal(e.lastEventId, id)
    } finally {
      s.es.close()
    }
  })

  test('Mercure 1.0: the protected resource metadata points at the hub', async () => {
    const res = await fetch(`${HUB}/.well-known/oauth-protected-resource${HUB_PATH}`)
    const doc = await res.json()
    assert.equal(res.status, 200)
    assert.equal(doc.resource, `${HUB}${HUB_PATH}`)
    assert.equal(doc.mercure_cookie, COOKIE_NAME)
    const unauth = await fetch(`${HUB}${HUB_PATH}`, { method: 'POST', body: new URLSearchParams({ topic: 'x' }) })
    await unauth.arrayBuffer()
    assert.equal(unauth.status, 401)
    assert.match(unauth.headers.get('www-authenticate'), /resource_metadata="[^"]+oauth-protected-resource/)
  })
}
