# End-to-End VPS Deployment Guide for Shomei Auth

This is your comprehensive master guide to deploying Shomei Auth to your VPS (`46.225.87.125`) from absolute scratch. Follow these steps in order, and you will have a fully automated, containerized, and secure OIDC provider.

---

## Phase 1: Hostinger Domain Configuration (DNS)
Before setting up the server, you need to point your domains to your VPS so Nginx can recognize the traffic.

1. Log into your **Hostinger Account**.
2. Navigate to **Domains** -> Select `parikar.in` -> click **DNS / Nameservers**.
3. In the DNS Records section, add two **A Records**:

| Type | Name | Points to (IPv4) | TTL |
|------|------|------------------|-----|
| A | `auth` | `46.225.87.125` | 3600 (Default) |
| A | `api.auth` | `46.225.87.125` | 3600 (Default) |

> [!NOTE]
> DNS propagation can take anywhere from a few minutes to an hour. You can use a tool like `dnschecker.org` to check if `auth.parikar.in` resolves to your VPS IP.

---

## Phase 2: VPS Initial Setup & `.env`

1. **SSH into your VPS:**
```bash
ssh deployer@46.225.87.125
```

2. **Clone your repository:**
```bash
git clone https://github.com/your-username/Shomei-auth.git
cd Shomei-auth
```

3. **Create the Environment File:**
This file handles the dynamic configuration of your containers. It should **never** be pushed to GitHub. Create it by running `nano .env` and pasting the following:

```env
# Database Credentials
POSTGRES_USER=myuser
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=oidc_db
DATABASE_URL=postgresql://myuser:your_secure_password@shomei_postgres:5432/oidc_db

# Redis
REDIS_URL=redis://shomei_redis:6379

# OIDC URLs (Critical for Production)
JWT_ISSUER=https://api.auth.parikar.in
FRONTEND_URL=https://auth.parikar.in
VITE_API_URL=https://api.auth.parikar.in

# Application Secrets (Generate random strings for these)
SESSION_SECRET=super_secret_session_string
JWT_SECRET=super_secret_jwt_string

# Email Service (Nodemailer config for OTPs)
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password

# Drizzle Studio (Optional)
PORT=3371
```
*Press `Ctrl+O` -> `Enter` to save, and `Ctrl+X` to exit nano.*

---

## Phase 3: Nginx & SSL Configuration

We need to tell Nginx to proxy incoming traffic to the Docker containers.

1. **Create the Nginx config file:**
```bash
sudo nano /etc/nginx/sites-available/shomei-auth
```

2. **Paste the routing rules:**
```nginx
# Proxy for the Frontend Dashboard (Port 3000)
server {
    listen 80;
    server_name auth.parikar.in;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;
    }
}

# Proxy for the Backend API (Port 3371)
server {
    listen 80;
    server_name api.auth.parikar.in;

    location / {
        proxy_pass http://127.0.0.1:3371;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;
    }
}
```

3. **Enable the site and restart Nginx:**
```bash
sudo ln -s /etc/nginx/sites-available/shomei-auth /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

4. **Secure it with SSL (Certbot):**
OIDC flows require strict HTTPS. Run Certbot to auto-configure SSL certificates for both domains:
```bash
sudo certbot --nginx -d auth.parikar.in -d api.auth.parikar.in
```

---

## Phase 4: CI/CD Automation (GitHub Actions)

You never want to manually SSH into the server to deploy again! Let's wire up GitHub Actions.

1. Go to your **GitHub Repository** -> **Settings** -> **Secrets and variables** -> **Actions**.
2. Click **New repository secret** and add the following three secrets:
   - `VPS_HOST`: `46.225.87.125`
   - `VPS_USERNAME`: `deployer`
   - `VPS_PASSWORD`: `your_ssh_password`

*(Note: If you use an SSH key instead of a password, you can change `VPS_PASSWORD` to `VPS_SSH_KEY` in the secrets and the `.github/workflows/deploy.yml` file).*

---

## Phase 5: First Deployment!

With everything configured, you are ready to fire it up.

1. On your local machine, commit and push your code to `main`.
```bash
git add .
git commit -m "Initial production deployment"
git push origin main
```

2. Open the **Actions** tab in your GitHub repository. You will see the `Deploy to VPS` workflow running. It is logging into your server, pulling the code, and running `./maintenance.sh` to build and launch all 4 Docker containers.

3. Wait a minute for the build to finish, and navigate to `https://auth.parikar.in` in your browser. Your completely independent, self-hosted Shomei Auth provider is now live!

Deployment done