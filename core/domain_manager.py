import os
import subprocess
import shutil
import re
from typing import Dict, Tuple, Optional
from core.storage import load_data, atomic_update

NGINX_CONF_PATH = "/etc/nginx/conf.d/ldbp_dashboard.conf"
SSL_DIR = "/etc/nginx/ssl"
SELFSIGNED_CERT = os.path.join(SSL_DIR, "ldbp_selfsigned.crt")
SELFSIGNED_KEY = os.path.join(SSL_DIR, "ldbp_selfsigned.key")

# Cloudflare Supported Ports
CF_HTTP_PORTS = [2052, 2082, 2086, 8880]
CF_HTTPS_PORTS = [8443, 2095]

def get_dashboard_domain_config() -> dict:
    data = load_data()
    return data.get("dashboard_domain", {
        "domain": "",
        "ssl_mode": "cloudflare",  # "cloudflare" (Origin/Flexible on 8443) or "letsencrypt" (Certbot on 8443)
        "configured": False,
        "ssl_active": False,
        "last_error": ""
    })

def ensure_selfsigned_cert() -> Tuple[bool, str]:
    """Ensures self-signed cert exists for Cloudflare Full SSL / TLS handshake."""
    try:
        os.makedirs(SSL_DIR, exist_ok=True)
        if not (os.path.exists(SELFSIGNED_CERT) and os.path.exists(SELFSIGNED_KEY)):
            cmd = [
                "openssl", "req", "-x509", "-nodes", "-days", "3650",
                "-newkey", "rsa:2048",
                "-keyout", SELFSIGNED_KEY,
                "-out", SELFSIGNED_CERT,
                "-subj", "/CN=ldbp-dashboard"
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            if res.returncode != 0:
                return False, f"OpenSSL error: {res.stderr}"
        return True, "Cert ready"
    except Exception as e:
        return False, str(e)

def apply_nginx_config(domain: str = "", ssl_mode: str = "cloudflare") -> Tuple[bool, str]:
    """
    Configures Nginx reverse proxy for LD-BP dashboard.
    Supports Cloudflare CDN ports (HTTP: 2052, 2082, 2086, 8880 / HTTPS: 8443, 2095).
    """
    ok, msg = ensure_selfsigned_cert()
    if not ok:
        return False, msg

    cert_path = SELFSIGNED_CERT
    key_path = SELFSIGNED_KEY

    # Check if Let's Encrypt cert exists for domain
    domain_clean = domain.strip().lower()
    if ssl_mode == "letsencrypt" and domain_clean:
        le_cert = f"/etc/letsencrypt/live/{domain_clean}/fullchain.pem"
        le_key = f"/etc/letsencrypt/live/{domain_clean}/privkey.pem"
        if os.path.exists(le_cert) and os.path.exists(le_key):
            cert_path = le_cert
            key_path = le_key

    server_names = "_" if not domain_clean else f"{domain_clean} _"

    nginx_conf = f"""# LD-BP Dashboard CDN & Direct Ports
server {{
    listen 2052 default_server;
    listen 2082 default_server;
    listen 2086 default_server;
    listen 8880 default_server;
    listen 8443 ssl default_server;
    listen 2095 ssl default_server;
    server_name {server_names};

    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {{
        proxy_pass http://127.0.0.1:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }}
}}
"""
    try:
        with open(NGINX_CONF_PATH, "w", encoding="utf-8") as f:
            f.write(nginx_conf)

        # Test nginx
        test_res = subprocess.run(["nginx", "-t"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if test_res.returncode != 0:
            return False, f"Nginx test failed: {test_res.stderr}"

        # Reload nginx
        reload_res = subprocess.run(["systemctl", "reload", "nginx"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if reload_res.returncode != 0:
            return False, f"Nginx reload failed: {reload_res.stderr}"

        return True, "Nginx configured and reloaded"
    except Exception as e:
        return False, str(e)

def issue_letsencrypt_cert(domain: str, email: Optional[str] = None) -> Tuple[bool, str]:
    """Issues Let's Encrypt certificate via webroot using /var/www/html (acme-challenge)."""
    domain_clean = domain.strip().lower()
    if not domain_clean or "." not in domain_clean or not re.match(r"^[a-z0-9.-]+$", domain_clean):
        return False, "نام دامنه معتبر نیست"

    if not shutil.which("certbot"):
        return False, "ابزار certbot روی سرور نصب نیست"

    os.makedirs("/var/www/html", exist_ok=True)
    cmd = [
        "certbot", "certonly", "--webroot",
        "-w", "/var/www/html",
        "-d", domain_clean,
        "--non-interactive", "--agree-tos"
    ]
    if email:
        cmd.extend(["-m", email.strip()])
    else:
        cmd.append("--register-unsafely-without-email")

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        if res.returncode == 0:
            return True, "گواهینامه SSL با موفقیت دریافت شد"
        else:
            raw_err = (res.stderr or res.stdout or "").strip()
            if "DNS problem" in raw_err or "NXDOMAIN" in raw_err:
                msg = f"رکورد DNS دامنه {domain_clean} یافت نشد یا به آی‌پی این سرور متصل نیست. ابتدا رکورد A را در DNS ست کنید."
            elif "Connection refused" in raw_err or "Failed to connect" in raw_err or "Timeout" in raw_err:
                msg = "سرورهای Let's Encrypt نتوانستند به پورت 80 سرور وصل شوند. اگر پروکسی کلودفلر (ابر نارنجی) روشن است، از حالت Cloudflare Full SSL استفاده کنید یا ابر را موقتاً خاکستری کنید."
            elif "challenges have failed" in raw_err:
                msg = "تأیید مالکیت دامنه توسط Let's Encrypt ناموفق بود. مطمئن شوید رکورد A به آی‌پی این سرور اشاره دارد و پورت 80 باز است."
            else:
                msg = f"خطا در صدور SSL: {raw_err[:120]}"
            return False, msg
    except subprocess.TimeoutExpired:
        return False, "زمان درخواست گواهینامه به پایان رسید (Timeout)"
    except Exception as e:
        return False, str(e)
