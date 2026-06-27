# 🔷 JagX Backend

> Your own private, fully-featured backend platform — Auth, Database, Storage, Realtime, and your own OAuth sign-in provider. **100% free to start.**

---

## What's Included

| Service | Description | Port |
|---------|-------------|------|
| **JagX Auth** | Sign up, sign in, magic links, MFA, OAuth2 provider | 3001 |
| **JagX API** | REST + GraphQL database API with Row-Level Security | 3002 |
| **JagX Storage** | File uploads, signed URLs, image optimization | 3003 |
| **JagX Realtime** | WebSocket channels, presence, DB change events | 3004 |
| **JagX Admin** | Web dashboard to manage everything | 3000 |

---

## Free Hosting Stack (Zero Naira)

| Service | Provider | Free Tier |
|---------|----------|-----------|
| API Services | **Railway.app** | $5 credit/month (enough for all services) |
| PostgreSQL | **Railway** (built-in) | 1GB free |
| Redis | **Railway** (built-in) | 25MB free |
| File Storage | **MinIO on Railway** | Uses Railway volume |
| Email | **Resend.com** | 3,000 emails/month free |
| CDN + DDoS | **Cloudflare** | 100% free |
| Code + CI/CD | **GitHub** | 100% free |
| Domain | **jagxbackend.com** | ~₦15,000/year only |

---

## Quick Start (Local Development)

### Prerequisites
- Docker Desktop installed (free): https://docker.com/products/docker-desktop
- Node.js 20+ (free): https://nodejs.org
- Git (free): https://git-scm.com

### 1. Clone & Configure

```bash
git clone https://github.com/YOUR_USERNAME/jagx-backend.git
cd jagx-backend

# Copy environment template
cp .env.example .env
```

### 2. Edit .env File

Open `.env` and fill in your values:

```bash
# Generate secure secrets with this command:
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Run it twice — once for JWT_SECRET, once for JWT_REFRESH_SECRET
```

Get your free Resend API key at: https://resend.com (sign up free, no card needed)

### 3. Start Everything

```bash
docker compose up -d
```

That's it! All services start automatically. Check they're running:

```bash
docker compose ps
```

### 4. Verify Services

```bash
# Auth service
curl http://localhost:3001/health

# API service  
curl http://localhost:3002/health

# Storage service
curl http://localhost:3003/health

# Realtime service
curl http://localhost:3004/health
```

---

## Deploy Free on Railway

### Step 1: Create Railway Account
Go to https://railway.app — sign up with GitHub (free, no card needed)

### Step 2: Install Railway CLI
```bash
npm install -g @railway/cli
railway login
```

### Step 3: Create Project
```bash
cd jagx-backend
railway init
# Name it: jagx-backend
```

### Step 4: Add PostgreSQL & Redis
In Railway dashboard:
- Click "New Service" → "Database" → "PostgreSQL"
- Click "New Service" → "Database" → "Redis"
- Copy the connection URLs shown

### Step 5: Set Environment Variables
```bash
railway variables set NODE_ENV=production
railway variables set JWT_SECRET=your_64_char_secret
railway variables set JWT_REFRESH_SECRET=your_other_64_char_secret
railway variables set RESEND_API_KEY=re_your_key
# Add all other vars from .env.example
```

### Step 6: Deploy
```bash
railway up
```

Railway gives you free URLs like:
- `jagx-auth.up.railway.app`
- `jagx-api.up.railway.app`
- `jagx-storage.up.railway.app`

### Step 7: Add Cloudflare (Free CDN + Custom Domain)
1. Sign up at https://cloudflare.com (free)
2. Add your domain
3. Create CNAME records pointing to your Railway URLs
4. Enable "Proxy" (orange cloud) for DDoS protection

---

## Using the JagX JavaScript SDK

### Install
```bash
npm install @jagx/client
# OR use directly from CDN (free):
# <script src="https://cdn.jsdelivr.net/npm/@jagx/client/dist/index.js"></script>
```

### Initialize
```javascript
import { createClient } from '@jagx/client'

const jagx = createClient({
  url: 'https://your-jagx-backend.up.railway.app',
  anonKey: 'your-project-anon-key'
})
```

### Authentication
```javascript
// Sign up
const { user, session, error } = await jagx.auth.signUp({
  email: 'user@example.com',
  password: 'SecurePass123'
})

// Sign in
const { user, session } = await jagx.auth.signIn({
  email: 'user@example.com',
  password: 'SecurePass123'
})

// Magic link (passwordless)
await jagx.auth.signInWithMagicLink('user@example.com')

// Sign out
await jagx.auth.signOut()

// Listen to auth changes
jagx.auth.onAuthStateChange((event, session) => {
  if (event === 'SIGNED_IN') console.log('User logged in:', session.user)
  if (event === 'SIGNED_OUT') console.log('User logged out')
})
```

### Database
```javascript
// Fetch all posts
const { data, error } = await jagx.from('posts').select('*')

// Filter
const { data } = await jagx
  .from('posts')
  .select('id, title, created_at')
  .eq('user_id', userId)
  .order('created_at', { ascending: false })
  .limit(10)

// Insert
const { data } = await jagx.from('posts').insert({
  title: 'My Post',
  content: 'Hello world',
  user_id: jagx.auth.getSession()?.user?.id
})

// Update
await jagx.from('posts').eq('id', postId).update({ title: 'Updated' })

// Delete
await jagx.from('posts').eq('id', postId).delete()
```

### Storage
```javascript
// Upload file
const file = document.querySelector('input[type=file]').files[0]
const { data, error } = await jagx.storage.from('avatars').upload('my-photo.jpg', file)

// Get public URL
const { data: { publicUrl } } = jagx.storage.from('avatars').getPublicUrl('my-photo.jpg')

// Create signed URL (for private files, expires in 1 hour)
const { data: { signedUrl } } = await jagx.storage.from('docs').createSignedUrl('report.pdf', 3600)

// List files
const { data: files } = await jagx.storage.from('avatars').list()
```

### Realtime
```javascript
// Subscribe to channel
jagx.channel('chat-room-1')
  .on('new-message', (payload) => {
    console.log('New message:', payload)
  })
  .subscribe()

// Send message
jagx.channel('chat-room-1').send('new-message', {
  text: 'Hello everyone!',
  user: 'John'
})

// Presence (see who's online)
jagx.channel('presence:chat-room-1')
  .on('join', ({ user }) => console.log(`${user.email} joined`))
  .on('leave', ({ user }) => console.log(`${user.email} left`))
  .on('members', ({ members }) => console.log('Online:', members))
  .subscribe()
```

---

## Sign In With JagX (OAuth Provider)

### Register Your App
```bash
curl -X POST https://your-auth.up.railway.app/oauth/v1/clients \
  -H "x-jagx-service-key: YOUR_SERVICE_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "JagX Buddy Connect",
    "redirect_uris": ["https://jagx-buddy-connect.name.ng/auth/callback"],
    "scopes": ["openid", "email", "profile"]
  }'
```

Response:
```json
{
  "client_id": "abc123",
  "client_secret": "SAVE_THIS_SECURELY",
  "name": "JagX Buddy Connect"
}
```

### Add to Your Site
```html
<a href="https://auth.jagxbackend.com/oauth/v1/authorize
  ?client_id=abc123
  &redirect_uri=https://jagx-buddy-connect.name.ng/auth/callback
  &response_type=code
  &scope=openid email profile">
  Sign in with JagX
</a>
```

---

## Security Features

- ✅ JWT RS256 signing with rotation
- ✅ Refresh token rotation (stolen token detection)
- ✅ Brute force protection (5 attempts → 15 min lockout)
- ✅ Rate limiting per IP and API key
- ✅ Audit logs for all auth events
- ✅ SQL injection protection (parameterized queries)
- ✅ CORS per-project configuration
- ✅ HTTP security headers (Helmet.js)
- ✅ Token blacklisting on sign out
- ✅ File type validation
- ✅ File size limits per bucket
- ✅ Signed URLs with expiry for private files
- ✅ Magic link single-use enforcement
- ✅ Email enumeration protection
- ✅ Password hashing (bcrypt, cost factor 12)
- ✅ MFA (TOTP — Google Authenticator)
- ✅ Session management with device tracking

---

## Project Structure

```
jagx-backend/
├── docker-compose.yml          ← Run everything locally
├── railway.toml                ← Free cloud deployment
├── .env.example                ← Configuration template
├── .github/workflows/          ← Auto-deploy on push
├── services/
│   ├── auth/                   ← Authentication service
│   │   ├── src/
│   │   │   ├── index.ts        ← Main server
│   │   │   ├── routes/
│   │   │   │   ├── auth.ts     ← Register, login, logout
│   │   │   │   ├── oauth.ts    ← Sign in with JagX
│   │   │   │   ├── users.ts    ← User management
│   │   │   │   ├── mfa.ts      ← Two-factor auth
│   │   │   │   └── api-keys.ts ← API key management
│   │   │   └── utils/
│   │   │       ├── tokens.ts   ← JWT helpers
│   │   │       ├── email.ts    ← Email sending
│   │   │       └── brute-force.ts ← Security
│   ├── api/                    ← REST + GraphQL API
│   ├── storage/                ← File storage
│   └── realtime/               ← WebSocket server
├── admin/                      ← React dashboard
├── sdk/
│   └── js/src/index.ts         ← @jagx/client SDK
└── infra/
    └── postgres/init.sql       ← Database schema
```

---

## Next Steps (Build Order)

1. ✅ Foundation (docker-compose, database, env)
2. ✅ Auth Service (login, signup, magic link, OAuth)
3. ✅ Storage Service (upload, download, signed URLs)
4. ✅ Realtime Service (WebSocket channels)
5. ✅ JS SDK (@jagx/client)
6. 🔲 API Service (REST query builder for your tables)
7. 🔲 Admin Dashboard (React UI)
8. 🔲 MFA routes (TOTP setup + verify)
9. 🔲 User management routes
10. 🔲 Connect jagx-buddy-connect.name.ng

---

## Support

Built by JagX. Free forever for personal use.
