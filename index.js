import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import path from 'path'
import { fileURLToPath } from 'url'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { v4 as uuidv4 } from 'uuid'
import { MongoClient } from 'mongodb'
import cookieParser from 'cookie-parser'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
dotenv.config({ path: path.join(__dirname, '.env') })
dotenv.config()
dotenv.config({ path: path.join(__dirname, '.env.example') })
const app = express()
app.use(express.json())
app.use(cookieParser())
const ALLOW_ORIGINS = (process.env.ALLOW_ORIGINS || '').split(',').filter(Boolean)
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true)
    if (ALLOW_ORIGINS.length && ALLOW_ORIGINS.includes(origin)) return callback(null, true)
    if (/^http:\/\/localhost:\d+$/.test(origin)) return callback(null, true)
    return callback(null, false)
  },
  credentials: true
}))

// Config
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me'
const MONGODB_URI = process.env.MONGODB_URI
const MONGODB_DB_NAME = process.env.MONGODB_DB_NAME || 'testify'
const USERS_COL = process.env.USERS_COL || 'users'
const OTPS_COL = process.env.OTPS_COL || 'otps'
const ORDERS_COL = process.env.ORDERS_COL || 'orders'
const PORT = process.env.PORT || 8082
const DEF_CODE = process.env.DEFAULT_COUNTRY_CODE || '91'

let db = null

// In-memory fallback for local dev
const mem = {
  users: new Map(),
  byEmail: new Map(),
  byEmailRole: new Map(),
  otps: new Map(),
  orders: new Map(),
  otpRate: new Map()
}

// Helper: persist user
async function saveUser(user) {
  if (db) {
    await db.collection(USERS_COL).updateOne({ id: user.id }, { $set: user }, { upsert: true })
    return
  }
  mem.users.set(user.id, user)
  mem.byEmail.set(user.email, user)
  mem.byEmailRole.set(`${user.email}:${user.role}`, user)
}

async function findUserByEmail(email) {
  if (db) {
    const u = await db.collection(USERS_COL).findOne({ email })
    return u || null
  }
  return mem.byEmail.get(email) || null
}

async function findUserByEmailRole(email, role) {
  if (db) {
    const u = await db.collection(USERS_COL).findOne({ email, role })
    return u || null
  }
  return mem.byEmailRole.get(`${email}:${role}`) || null
}

async function findPendingProviders() {
  if (db) {
    const list = await db.collection(USERS_COL).find({ role: 'provider', status: 'pending' }).toArray()
    return list
  }
  return [...mem.users.values()].filter(u => u.role === 'provider' && u.status === 'pending')
}

async function listAllUsers() {
  if (db) {
    const list = await db.collection(USERS_COL).find({}).toArray()
    return list
  }
  return [...mem.users.values()]
}

async function listAllProviders() {
  if (db) {
    const list = await db.collection(USERS_COL).find({ role: 'provider' }).toArray()
    return list
  }
  return [...mem.users.values()].filter(u=>u.role==='provider')
}

async function listAllOrders() {
  if (db) {
    const list = await db.collection(ORDERS_COL).find({}).toArray()
    return list
  }
  return [...mem.orders.values()]
}

async function findUserById(id) {
  if (db) {
    const u = await db.collection(USERS_COL).findOne({ id })
    return u || null
  }
  return mem.users.get(id) || null
}

async function approveProvider(id) {
  if (db) {
    await db.collection(USERS_COL).updateOne({ id }, { $set: { status: 'active' } })
  } else {
    const u = mem.users.get(id); if (u) u.status = 'active'
  }
}

// OTP helpers
function randomOtp() { return String(Math.floor(100000 + Math.random()*900000)) }
function normalizeDigits(p){ return String(p).replace(/\D/g, '') }
function storagePhone(d){
  const digits = normalizeDigits(d)
  if (digits.length === 10) return `${DEF_CODE}${digits}`
  return digits
}
async function saveOtp(phone, code, context) {
  const key = storagePhone(phone)
  const expiresAt = Date.now() + 10*60*1000
  if (db) {
    await db.collection(OTPS_COL).updateOne({ phone: key }, { $set: { code, context, expiresAt } }, { upsert: true })
  } else {
    mem.otps.set(key, { code, expiresAt, context })
  }
}

async function verifyOtp(phone, code, context) {
  const key = storagePhone(phone)
  if (db) {
    const item = await db.collection(OTPS_COL).findOne({ phone: key })
    if (!item) return false
    return item.code === code && item.context === context && Number(item.expiresAt) > Date.now()
  }
  const o = mem.otps.get(key)
  return !!(o && o.code === code && o.context === context && o.expiresAt > Date.now())
}

async function sendSmsOtp(phone, code) {
  const apiKey = (process.env.FAST2SMS_API_KEY || '').trim()
  const sender = process.env.FAST2SMS_SENDER_ID || 'TXTIND'
  const templateId = (process.env.FAST2SMS_TEMPLATE_ID || '').trim()
  const url = 'https://www.fast2sms.com/dev/bulkV2'
  if (!apiKey) {
    return { ok:false, message:'Missing Fast2SMS API key' }
  }
  let digits = String(phone).replace(/\D/g, '')
  const defCode = process.env.DEFAULT_COUNTRY_CODE
  if (defCode && digits.length === 10) digits = `${defCode}${digits}`
  const local = digits.length > 10 ? digits.slice(-10) : digits
  const payload = templateId ?
    { route:'otp', variables_values: code, numbers: local, template_id: templateId } :
    { route:'q', sender_id: sender, message: `Your Testify OTP is ${code}`, language:'english', numbers: local }
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), 10000)
  try {
    const res = await fetch(url, { method:'POST', headers: { authorization: apiKey, 'Content-Type':'application/json' }, body: JSON.stringify(payload), signal: ctrl.signal })
    const text = await res.text()
    if (!res.ok) return { ok:false, message: text }
    let data = {}
    try { data = JSON.parse(text) } catch {}
    if (data && data.return === false) return { ok:false, message: 'Fast2SMS send failed' }
    return { ok:true }
  } catch (err) {
    return { ok:false, message: err.message }
  } finally { clearTimeout(t) }
}

// Auth middleware
function requireRole(role) {
  return (req, res, next) => {
    const h = req.headers.authorization || ''
    let token = h.startsWith('Bearer ') ? h.slice(7) : ''
    if (!token && req.cookies && req.cookies.auth) token = req.cookies.auth
    try {
      const payload = jwt.verify(token, JWT_SECRET)
      if (role && payload.role !== role) return res.status(403).json({ message:'Forbidden' })
      req.user = payload; next()
    } catch (err) { return res.status(401).json({ message:'Unauthorized' }) }
  }
}

function requireAuth(req, res, next) {
  const h = req.headers.authorization || ''
  let token = h.startsWith('Bearer ') ? h.slice(7) : ''
  if (!token && req.cookies && req.cookies.auth) token = req.cookies.auth
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    req.user = payload; next()
  } catch (err) { return res.status(401).json({ message:'Unauthorized' }) }
}

// Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { role, name, email, phone, password } = req.body
    if (!role || !name || !email || !phone || !password) return res.status(400).json({ message:'Missing fields' })
    const existingRole = await findUserByEmailRole(email, role)
    if (existingRole) return res.status(409).json({ message:'Email already registered for this role' })
    const id = uuidv4()
    const passwordHash = bcrypt.hashSync(password, 10)
    const status = role === 'provider' ? 'pending' : 'active'
    const normalizedPhone = storagePhone(phone)
    await saveUser({ id, role, name, email, phone: normalizedPhone, passwordHash, status })
    return res.json({ ok:true, id })
  } catch (err) {
    console.error('Register error:', err?.message || err)
    return res.status(500).json({ message:'Registration failed' })
  }
})

app.post('/api/auth/login', async (req, res) => {
  const { email, password, role } = req.body
  let u = null
  if (role) {
    u = await findUserByEmailRole(email, role)
  }
  if (!u) {
    u = await findUserByEmail(email)
  }
  if (!u) return res.status(401).json({ message:'Invalid credentials' })
  if (role && u.role !== role) return res.status(403).json({ message:'Role mismatch' })
  const ok = bcrypt.compareSync(password, u.passwordHash)
  if (!ok) return res.status(401).json({ message:'Invalid credentials' })
  if (u.role === 'provider' && u.status !== 'active') return res.status(403).json({ message:'Awaiting admin approval' })
  const token = jwt.sign({ sub: u.id, role: u.role, email: u.email }, JWT_SECRET, { expiresIn: '7d' })
  const isProd = !!process.env.VERCEL || process.env.NODE_ENV === 'production'
  res.cookie('auth', token, { httpOnly: true, sameSite: isProd ? 'none' : 'lax', secure: isProd, maxAge: 7*24*60*60*1000 })
  res.json({ ok:true, role: u.role })
})

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('auth', { httpOnly: true, sameSite: 'lax', secure: false })
  res.json({ ok:true })
})

app.post('/api/auth/send-otp', async (req, res) => {
  const { phone, context } = req.body
  if (!phone || !context) return res.status(400).json({ message:'Missing phone/context' })
  const digits = normalizeDigits(phone)
  if (digits.length < 10) return res.status(400).json({ message:'Invalid phone number' })
  const key = storagePhone(digits)
  const rateKey = `${key}:${context}`
  const now = Date.now()
  const last = mem.otpRate.get(rateKey) || 0
  if (now - last < 30000) return res.status(429).json({ message:'Please wait before requesting another OTP' })
  const code = randomOtp()
  await saveOtp(key, code, context)
  let r = await sendSmsOtp(key, code)
  if (!r.ok) {
    await new Promise(resolve => setTimeout(resolve, 800))
    r = await sendSmsOtp(key, code)
  }
  if (!r.ok) return res.status(502).json({ message: r.message || 'Failed to send OTP' })
  mem.otpRate.set(rateKey, now)
  const dev = process.env.DEV_SHOW_OTP === 'true'
  res.json(dev ? { ok:true, code } : { ok:true })
})

app.post('/api/auth/verify-otp', async (req, res) => {
  const { phone, otp, context } = req.body
  if (!phone || !otp || !context) return res.status(400).json({ message:'Missing fields' })
  const ok = await verifyOtp(phone, otp, context)
  if (!ok) return res.status(400).json({ message:'Invalid OTP' })
  res.json({ ok:true })
})

app.post('/api/auth/reset', async (req, res) => {
  const { phone, otp, password } = req.body
  if (!phone || !otp || !password) return res.status(400).json({ message:'Missing fields' })
  const ok = await verifyOtp(phone, otp, 'forgot')
  if (!ok) return res.status(400).json({ message:'Invalid OTP' })
  const key = storagePhone(phone)
  // find by phone
  let user = null
  if (db) {
    user = await db.collection(USERS_COL).findOne({ phone: key })
  } else {
    user = [...mem.users.values()].find(u=>u.phone===key)
  }
  if (!user) return res.status(404).json({ message:'User not found' })
  const newHash = bcrypt.hashSync(password, 10)
  if (db) {
    await db.collection(USERS_COL).updateOne({ id: user.id }, { $set: { passwordHash: newHash } })
  } else { user.passwordHash = newHash }
  res.json({ ok:true })
})

// Admin endpoints
app.get('/api/admin/providers', requireRole('admin'), async (req, res) => {
  const pending = await findPendingProviders()
  res.json({ pending })
})
app.get('/api/admin/users', requireRole('admin'), async (req, res) => {
  const users = await listAllUsers()
  res.json({ users })
})
app.get('/api/admin/providers/all', requireRole('admin'), async (req, res) => {
  const providers = await listAllProviders()
  res.json({ providers })
})
app.get('/api/admin/orders', requireRole('admin'), async (req, res) => {
  const orders = await listAllOrders()
  res.json({ orders })
})
app.post('/api/admin/providers/:id/approve', requireRole('admin'), async (req, res) => {
  await approveProvider(req.params.id)
  res.json({ ok:true })
})

// Services
app.get('/api/services', async (req, res) => {
  res.json({ services: [
    { id:'sugar', title:'Sugar Check', price: 149 },
    { id:'blood', title:'Blood Test', price: 299 },
    { id:'bp', title:'Blood Pressure', price: 99 },
    { id:'ecg', title:'ECG', price: 499 }
  ] })
})

app.get('/api/me', requireAuth, async (req, res) => {
  const u = await findUserById(req.user.sub)
  if (!u) return res.status(404).json({ message:'User not found' })
  res.json({ id: u.id, role: u.role, name: u.name, email: u.email, phone: u.phone, status: u.status })
})

app.get('/api/account/address', requireAuth, async (req, res) => {
  const u = await findUserById(req.user.sub)
  if (!u) return res.status(404).json({ message:'User not found' })
  const list = Array.isArray(u.addresses) ? u.addresses : []
  res.json({ addresses: list })
})

app.post('/api/account/address', requireAuth, async (req, res) => {
  const { id, address, city, state, pincode, landmark } = req.body
  if (!address || !city || !state || !pincode) return res.status(400).json({ message:'Missing fields' })
  const u = await findUserById(req.user.sub)
  if (!u) return res.status(404).json({ message:'User not found' })
  const list = Array.isArray(u.addresses) ? [...u.addresses] : []
  let item = { id: id || uuidv4(), address, city, state, pincode, landmark: landmark || '' }
  const idx = list.findIndex(x => x.id === item.id)
  if (idx >= 0) list[idx] = item; else list.push(item)
  if (db) {
    await db.collection(USERS_COL).updateOne({ id: u.id }, { $set: { addresses: list } })
  } else {
    u.addresses = list
    await saveUser(u)
  }
  res.json({ ok:true, id: item.id })
})

app.post('/api/orders', requireAuth, async (req, res) => {
  const { serviceId, address, pincode, landmark, city, state, phone } = req.body
  if (!serviceId || !address || !pincode || !city || !state || !phone) return res.status(400).json({ message:'Missing fields' })
  const id = uuidv4()
  const order = { id, userId: req.user.sub, serviceId, address, pincode, landmark: landmark || '', city, state, phone, status: 'requested', createdAt: Date.now() }
  if (db) {
    await db.collection(ORDERS_COL).insertOne(order)
  } else {
    mem.orders.set(id, order)
  }
  res.json({ ok:true, id })
})

app.get('/api/orders', requireAuth, async (req, res) => {
  if (db) {
    const list = await db.collection(ORDERS_COL).find({ userId: req.user.sub }).toArray()
    return res.json({ orders: list })
  }
  const list = [...mem.orders.values()].filter(o=>o.userId===req.user.sub)
  res.json({ orders: list })
})

app.post('/api/orders/reserve', requireAuth, async (req, res) => {
  const { serviceId, scheduledAt } = req.body
  if (!serviceId || !scheduledAt) return res.status(400).json({ message:'Missing fields' })
  const id = uuidv4()
  const order = { id, userId: req.user.sub, serviceId, address:'', pincode:'', landmark:'', city:'', state:'', phone:'', status: 'reserved', scheduledAt: String(scheduledAt), createdAt: Date.now() }
  if (db) {
    await db.collection(ORDERS_COL).insertOne(order)
  } else {
    mem.orders.set(id, order)
  }
  res.json({ ok:true, id })
})

// Health
app.get('/api/health', (req, res) => res.json({ ok:true }))
// Root health for platform checks
app.get('/', (req, res) => res.status(200).send('OK'))

// Dev helper: get last OTP for a phone
app.get('/api/debug/otp', (req, res) => {
  if (process.env.DEV_SHOW_OTP !== 'true') return res.status(404).json({ message:'Not available' })
  const phone = req.query.phone
  if (!phone) return res.status(400).json({ message:'Missing phone' })
  const o = mem.otps.get(String(phone))
  if (!o) return res.status(404).json({ message:'No OTP found' })
  res.json({ code: o.code, expiresAt: o.expiresAt, context: o.context })
})

async function init() {
  if (MONGODB_URI) {
    const client = new MongoClient(MONGODB_URI)
    await client.connect()
    db = client.db(MONGODB_DB_NAME)
  }
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@testify.local'
  const adminPass = process.env.ADMIN_PASSWORD || 'admin123'
  let admin = await findUserByEmail(adminEmail)
  if (!admin) {
    const id = uuidv4()
    const passwordHash = bcrypt.hashSync(adminPass, 10)
    await saveUser({ id, role:'admin', name:'Admin', email:adminEmail, phone:'', passwordHash, status:'active' })
    admin = await findUserByEmail(adminEmail)
  }
  const demoEmail = process.env.DEMO_USER_EMAIL || 'user@testify.local'
  const demoPass = process.env.DEMO_USER_PASSWORD || 'user123'
  let demo = await findUserByEmail(demoEmail)
  if (!demo) {
    const id = uuidv4()
    const passwordHash = bcrypt.hashSync(demoPass, 10)
    await saveUser({ id, role:'user', name:'Demo User', email:demoEmail, phone:'', passwordHash, status:'active' })
  }
}

let initialized = false
async function ensureInit(req, res, next) {
  if (!initialized) {
    try { await init(); initialized = true } catch (err) { /* ignore */ }
  }
  next()
}
app.use(ensureInit)

export default app

if (!process.env.VERCEL) {
  init().then(()=>{
    app.listen(PORT, () => {
      console.log(`API server listening on http://localhost:${PORT}`)
    })
  })
}
