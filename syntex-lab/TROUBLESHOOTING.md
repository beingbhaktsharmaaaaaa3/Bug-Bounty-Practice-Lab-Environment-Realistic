# Troubleshooting — Syntex Lab

Common setup issues and their exact fixes.

---

## Docker Issues

### ❌ `npm ci` — requires package-lock.json

```
npm error The `npm ci` command can only install with an existing package-lock.json
```

**Fix:** Edit `backend/Dockerfile`, change line 7:
```dockerfile
# Remove this:
RUN npm ci --only=production

# Replace with:
RUN npm install --omit=dev
```

---

### ❌ `unknown flag: --build`

```
unknown flag: --build
```

Your system has Docker Compose v1 (hyphenated). Use:
```bash
docker-compose up --build    # v1 — hyphen, same binary
```

If neither works:
```bash
sudo apt update && sudo apt install -y docker-compose-plugin
docker compose version   # should print v2.x
```

---

### ❌ `version` obsolete warning

```
WARN: the attribute `version` is obsolete, it will be ignored
```

Not an error — just a warning. Remove the `version: '3.8'` line from `docker-compose.yml`. The lab works fine either way.

---

### ❌ Port already in use

```
Error: listen tcp 127.0.0.1:80: bind: address already in use
```

Something else is using port 80 or 3000. Find and stop it:
```bash
sudo ss -tlnp | grep ':80\|:3000\|:5432'
sudo kill $(sudo lsof -ti:80)
sudo kill $(sudo lsof -ti:3000)
```

Or change the ports in `docker-compose.yml`:
```yaml
ports:
  - "127.0.0.1:8080:80"    # use port 8080 instead
  - "127.0.0.1:3001:3000"  # use port 3001 instead
```

---

### ❌ Database container not ready

```
Error: connect ECONNREFUSED 127.0.0.1:5432
[SEED] Database connection failed
```

The app started before PostgreSQL was ready. This usually self-resolves on second run:
```bash
docker-compose down
docker-compose up --build
```

Or increase the sleep in `backend/Dockerfile`:
```dockerfile
CMD ["sh", "-c", "sleep 15 && node database/seed.js && node server.js"]
#                         ^^^ increase from 8 to 15
```

---

### ❌ Seed fails — relation does not exist

```
error: relation "users" does not exist
```

The schema hasn't been initialised. Force a full rebuild with volume wipe:
```bash
docker-compose down -v    # -v removes the postgres_data volume
docker-compose up --build
```

---

### ❌ Container keeps restarting

```
syntex_app    | Error: Cannot find module './routes/dashboard'
```

A required file is missing from the repo. Check which file is missing and ensure your GitHub repo has all route files. Common missing files:
- `backend/routes/dashboard.js`
- `backend/routes/misc.js`
- `backend/middleware/cors.js`
- `backend/database/db.js`

---

### ❌ GraphQL / WebSocket not available

If `npm install` failed for `graphql` or `ws`:
```bash
docker exec -it syntex_app sh
npm install graphql ws fast-xml-parser
exit
docker-compose restart app
```

---

## Website Issues

### ❌ syntex.local — ERR_NAME_NOT_RESOLVED

Your `/etc/hosts` hasn't been updated. Add:
```bash
sudo bash -c 'cat >> /etc/hosts << "EOF"
127.0.0.1 syntex.local www.syntex.local api.syntex.local
127.0.0.1 admin.syntex.local dev.syntex.local staging.syntex.local
127.0.0.1 cdn.syntex.local program.syntex.local
EOF'
```

Verify it works:
```bash
ping -c 1 syntex.local      # should resolve to 127.0.0.1
curl -I http://syntex.local  # should return HTTP/1.1 200 or 302
```

---

### ❌ File Manager shows 404

The upload route is mounted at `/upload`. Make sure `backend/server.js` has:
```javascript
app.use('/upload', require('./routes/upload'));  // correct
// NOT:
app.use('/',       require('./routes/upload'));  // wrong
```

---

### ❌ /program page shows 404

The program platform is accessible via:
- `http://localhost:3000/program`
- `http://program.syntex.local` (after /etc/hosts setup)

If the route isn't found, check that `backend/routes/program.js` exists and is mounted in `server.js`:
```javascript
app.use('/program', require('./routes/program'));
```

---

### ❌ Admin panel shows "Access Denied" even as admin

The admin check reads from cookies AND session. Try:
1. Log out completely
2. Log back in with `admin / admin123`
3. Or set cookie manually: DevTools → Application → Cookies → add `role=admin`

---

### ❌ Seed data missing — users table empty

Trigger the seed manually:
```bash
docker exec syntex_app node database/seed.js
```

If it errors, check logs:
```bash
docker logs syntex_app --tail 50
```

---

### ❌ Flag not appearing after exploitation

Flags are planted at specific proof points. Checklist:
1. Are you in **beginner mode**? (`LAB_MODE=beginner` in docker-compose.yml)
2. Did you exploit the right endpoint? Check `/program/hints/:slug`
3. For SSRF flags — fetch `http://localhost:3000/debug` via the SSRF endpoint
4. For IDOR flags — read the `secret_note` or `notes` field, not just the main response
5. For XSS flags — open the browser console after the payload fires

---

## Subdomain Discovery Issues

### ❌ subfinder shows no results

`subfinder` uses certificate transparency logs. `.local` domains are **never** in CT logs. Use ffuf instead:

```bash
# Vhost fuzzing — no DNS needed
ffuf -u http://127.0.0.1 -H "Host: FUZZ.syntex.local" \
     -w wordlist.txt -mc 200,301,302,403,503 -t 40

# gobuster with lab DNS server
docker-compose up -d dns   # start DNS container first
gobuster dns -d syntex.local --resolver 127.0.0.1:5353 \
             -w wordlist.txt -t 30
```

---

### ❌ DNS server container fails to start

```
Error: andyshinn/dnsmasq: image not found
```

Pull the image manually:
```bash
docker pull andyshinn/dnsmasq
```

Or use the ffuf vhost method instead — it doesn't require the DNS container.

---

## Reset & Cleanup

### Reset lab data (keep containers running)
```bash
docker exec syntex_app node database/reset.js
```

### Full restart (keep data)
```bash
docker-compose restart
```

### Full wipe and rebuild
```bash
docker-compose down -v     # removes volumes
docker-compose up --build  # rebuilds from scratch
```

### Remove everything including images
```bash
docker-compose down -v --rmi all
```

---

## Performance Issues

### Lab feels slow

```bash
# Check container resource usage
docker stats

# Check app logs for errors
docker logs syntex_app -f

# Check DB logs
docker logs syntex_db --tail 20
```

If the app container is using excessive CPU, a regex DoS or infinite loop may have been triggered. Reset:
```bash
docker-compose restart app
```

---

## Still stuck?

1. Check `docker logs syntex_app --tail 100` for the exact error
2. Check `docker logs syntex_db --tail 20` for database errors
3. Open an issue on GitHub with the full error output

---

*Remember: this lab is intentionally vulnerable. Some "errors" are actually features.*
