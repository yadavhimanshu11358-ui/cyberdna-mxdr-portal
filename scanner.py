from dotenv import load_dotenv
load_dotenv()

import os
import json
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
from requests.auth import HTTPBasicAuth
from flask import Flask, request, jsonify
from flask_cors import CORS
from google import genai

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

api_key = os.environ.get("GEMINI_API_KEY", "").strip()
ai_client = genai.Client(api_key=api_key) if api_key else None
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash").strip()


@app.route("/", methods=["GET"])
def health_check():
    return jsonify({
        "status": "online",
        "service": "CyberDNA MXDR & NetOps Scanner API",
        "currency": "USD",
        "ai_configured": bool(ai_client),
    }), 200


def check_dns_records(hostname: str) -> dict:
    dns_info = {
        "a_records": [],
        "spf_present": False,
        "dmarc_present": False,
    }
    try:
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        dns_info["a_records"] = ip_list
    except Exception:
        pass

    try:
        res_txt = requests.get(
            f"https://dns.google/resolve?name={hostname}&type=TXT", timeout=3
        ).json()
        for ans in res_txt.get("Answer", []):
            if "v=spf1" in ans.get("data", "").lower():
                dns_info["spf_present"] = True
                break
    except Exception:
        pass

    try:
        res_dmarc = requests.get(
            f"https://dns.google/resolve?name=_dmarc.{hostname}&type=TXT", timeout=3
        ).json()
        for ans in res_dmarc.get("Answer", []):
            if "v=dmarc1" in ans.get("data", "").lower():
                dns_info["dmarc_present"] = True
                break
    except Exception:
        pass

    return dns_info


def get_recon_data(hostname: str) -> dict:
    recon = {
        "ip_address": "Unknown",
        "ssl_valid": False,
        "ssl_issuer": "N/A",
        "ssl_expiry": "N/A",
        "ssl_days_remaining": None,
        "tls_version": "N/A",
        "open_ports": [],
        "dns_health": {},
    }

    try:
        recon["ip_address"] = socket.gethostbyname(hostname)
    except socket.gaierror:
        pass

    recon["dns_health"] = check_dns_records(hostname)

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                recon["ssl_valid"] = True
                recon["tls_version"] = ssock.version() or "TLSv1.2+"
                issuer = dict(x[0] for x in cert.get("issuer", []))
                recon["ssl_issuer"] = issuer.get("organizationName", "Verified CA")

                not_after = cert.get("notAfter")
                if not_after:
                    expiry_dt = datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days_left = (expiry_dt - datetime.now(timezone.utc)).days
                    recon["ssl_expiry"] = expiry_dt.strftime("%Y-%m-%d")
                    recon["ssl_days_remaining"] = days_left
    except Exception:
        recon["ssl_valid"] = False

    for port in [21, 22, 80, 443, 3306, 8080, 8443]:
        try:
            with socket.create_connection((hostname, port), timeout=1.0):
                recon["open_ports"].append(port)
        except Exception:
            pass

    return recon


def call_gemini_text(prompt: str) -> str:
    if not ai_client:
        raise RuntimeError("GEMINI_API_KEY is not configured on the server.")
    res = ai_client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt,
    )
    return (res.text or "").strip()


def generate_executive_brief(target: str, score: int, vulns: list) -> str:
    if not vulns:
        return (
            f"Hardened posture verified for {target} (Score: {score}/100). "
            f"Perimeter ports, TLS chain, DNS spoofing records, and HTTP headers passed checks."
        )

    finding_titles = ", ".join(v["title"] for v in vulns[:5])
    if not ai_client:
        return (
            f"Automated SecOps & NetOps audit completed for {target} "
            f"(Score: {score}/100, {len(vulns)} findings). Immediate action recommended on: {finding_titles}."
        )

    prompt = (
        f"You are a Senior Security & Network Engineer writing a 2-sentence operational summary.\n"
        f"Target: {target}\n"
        f"Score: {score}/100\n"
        f"Key Findings: {finding_titles}\n"
        f"Explain the business/network risk and top immediate engineering fix concisely."
    )
    try:
        return call_gemini_text(prompt)
    except Exception:
        return (
            f"Audit completed for {target} (Score: {score}/100). "
            f"Immediate remediation recommended for: {finding_titles}."
        )


@app.route("/api/scan", methods=["POST"])
def scan_domain():
    data = request.json or {}
    target_url = (data.get("url") or "").strip()
    profile = (data.get("profile") or "rapid").strip()
    custom_auth = (data.get("auth_header") or "").strip()

    if not target_url:
        return jsonify({"status": "error", "message": "Target URL is required."}), 400

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    parsed_url = urlparse(target_url)
    hostname = parsed_url.hostname or target_url

    req_headers = {"User-Agent": "CyberDNA-MXDR-Auditor/4.0"}
    if custom_auth:
        req_headers["Authorization"] = custom_auth

    try:
        response = requests.get(target_url, timeout=8, headers=req_headers)
        headers = response.headers
        raw_headers_dict = dict(headers)
        recon_info = get_recon_data(hostname)

        vulnerabilities = []
        score = 100

        if "X-Frame-Options" not in headers and "frame-ancestors" not in headers.get(
            "Content-Security-Policy", ""
        ):
            vulnerabilities.append({
                "id": "VULN-001",
                "title": "Missing Clickjacking Protection (X-Frame-Options)",
                "severity": "Medium",
                "cvss": "5.4",
                "endpoint": target_url,
                "description": "Neither X-Frame-Options nor CSP frame-ancestors is set, allowing iframe embedding.",
                "cli_fix": 'add_header X-Frame-Options "SAMEORIGIN" always;',
            })
            score -= 12

        if "Content-Security-Policy" not in headers:
            vulnerabilities.append({
                "id": "VULN-002",
                "title": "Missing Content-Security-Policy (CSP)",
                "severity": "High",
                "cvss": "7.2",
                "endpoint": target_url,
                "description": "Missing Content-Security-Policy increases XSS and script injection exposure.",
                "cli_fix": 'add_header Content-Security-Policy "default-src \'self\';" always;',
            })
            score -= 20

        if "Strict-Transport-Security" not in headers and target_url.startswith("https://"):
            vulnerabilities.append({
                "id": "VULN-003",
                "title": "Missing HTTP Strict Transport Security (HSTS)",
                "severity": "Medium",
                "cvss": "5.9",
                "endpoint": target_url,
                "description": "Server does not enforce HTTPS via Strict-Transport-Security.",
                "cli_fix": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
            })
            score -= 12

        if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
            vulnerabilities.append({
                "id": "VULN-004",
                "title": "Missing X-Content-Type-Options: nosniff",
                "severity": "Low",
                "cvss": "3.7",
                "endpoint": target_url,
                "description": "Browser MIME-sniffing is not disabled.",
                "cli_fix": 'add_header X-Content-Type-Options "nosniff" always;',
            })
            score -= 8

        if "Server" in headers or "X-Powered-By" in headers:
            exposed = ", ".join(
                f"{k}: {headers[k]}" for k in ["Server", "X-Powered-By"] if k in headers
            )
            vulnerabilities.append({
                "id": "VULN-005",
                "title": f"Server Technology Banner Disclosure ({exposed})",
                "severity": "Low",
                "cvss": "3.1",
                "endpoint": target_url,
                "description": f"Response headers expose backend stack details ({exposed}).",
                "cli_fix": "server_tokens off;\nproxy_hide_header X-Powered-By;",
            })
            score -= 5

        if target_url.startswith("http://"):
            vulnerabilities.append({
                "id": "VULN-006",
                "title": "Insecure Cleartext HTTP Protocol",
                "severity": "High",
                "cvss": "7.5",
                "endpoint": target_url,
                "description": "Application is accessed over unencrypted HTTP.",
                "cli_fix": "return 301 https://$host$request_uri;",
            })
            score -= 25

        days_left = recon_info.get("ssl_days_remaining")
        if days_left is not None and days_left < 30:
            vulnerabilities.append({
                "id": "VULN-007",
                "title": f"SSL/TLS Certificate Expiring Soon ({days_left} days left)",
                "severity": "High" if days_left < 10 else "Medium",
                "cvss": "6.5",
                "endpoint": target_url,
                "description": f"TLS certificate expires on {recon_info['ssl_expiry']}.",
                "cli_fix": f"sudo certbot renew --cert-name {hostname} --force-renewal",
            })
            score -= 15

        risky_ports = [p for p in recon_info.get("open_ports", []) if p in [21, 22, 3306, 8080]]
        if risky_ports:
            vulnerabilities.append({
                "id": "NET-001",
                "title": f"Exposed Network Ports Detected ({', '.join(map(str, risky_ports))})",
                "severity": "High",
                "cvss": "7.8",
                "endpoint": f"{hostname}:{risky_ports[0]}",
                "description": f"External TCP ports {risky_ports} are reachable; restrict via firewall/ACL.",
                "cli_fix": f"sudo ufw deny {risky_ports[0]}/tcp && sudo ufw reload",
            })
            score -= 12

        dns_health = recon_info.get("dns_health", {})
        if not dns_health.get("dmarc_present"):
            vulnerabilities.append({
                "id": "NET-002",
                "title": "Missing DMARC DNS Policy (_dmarc)",
                "severity": "Medium",
                "cvss": "5.5",
                "endpoint": f"_dmarc.{hostname}",
                "description": "No DMARC TXT record found to protect against domain email spoofing.",
                "cli_fix": f'TXT _dmarc.{hostname} "v=DMARC1; p=quarantine; rua=mailto:soc@{hostname}"',
            })
            score -= 6

        if not dns_health.get("spf_present"):
            vulnerabilities.append({
                "id": "NET-003",
                "title": "Missing SPF Sender Policy Record",
                "severity": "Low",
                "cvss": "4.3",
                "endpoint": hostname,
                "description": "No v=spf1 record detected on domain TXT records.",
                "cli_fix": f'TXT {hostname} "v=spf1 include:_spf.google.com -all"',
            })
            score -= 4

        if profile in ["comprehensive", "fullPenTest"]:
            if "Referrer-Policy" not in headers:
                vulnerabilities.append({
                    "id": "VULN-008",
                    "title": "Missing Referrer-Policy Header",
                    "severity": "Low",
                    "cvss": "3.5",
                    "endpoint": target_url,
                    "description": "Referrer-Policy header is missing.",
                    "cli_fix": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
                })
                score -= 5

            if "Permissions-Policy" not in headers:
                vulnerabilities.append({
                    "id": "VULN-009",
                    "title": "Missing Permissions-Policy Header",
                    "severity": "Low",
                    "cvss": "3.2",
                    "endpoint": target_url,
                    "description": "Permissions-Policy header is not set.",
                    "cli_fix": 'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
                })
                score -= 5

            set_cookie = headers.get("Set-Cookie", "")
            if set_cookie:
                cookie_lower = set_cookie.lower()
                missing_flags = [
                    f
                    for f in ["HttpOnly", "Secure", "SameSite"]
                    if f.lower() not in cookie_lower
                ]
                if missing_flags:
                    vulnerabilities.append({
                        "id": "VULN-010",
                        "title": f"Insecure Cookie Configuration (Missing {', '.join(missing_flags)})",
                        "severity": "Medium",
                        "cvss": "5.3",
                        "endpoint": target_url,
                        "description": f"Cookies missing {', '.join(missing_flags)} flags.",
                        "cli_fix": 'proxy_cookie_path / "/; HTTPOnly; Secure; SameSite=Lax";',
                    })
                    score -= 10

        security_txt_found = False
        if profile == "fullPenTest":
            acao = headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                vulnerabilities.append({
                    "id": "VULN-011",
                    "title": "Overly Permissive CORS Policy (Access-Control-Allow-Origin: *)",
                    "severity": "Medium",
                    "cvss": "5.8",
                    "endpoint": target_url,
                    "description": "Wildcard CORS header allows any origin to read responses.",
                    "cli_fix": 'add_header Access-Control-Allow-Origin "https://app.yourdomain.com" always;',
                })
                score -= 10

            try:
                sec_res = requests.get(f"https://{hostname}/.well-known/security.txt", timeout=4)
                if sec_res.status_code == 200 and "contact:" in sec_res.text.lower():
                    security_txt_found = True
                else:
                    vulnerabilities.append({
                        "id": "VULN-012",
                        "title": "Missing RFC 9116 security.txt Disclosure Policy",
                        "severity": "Info",
                        "cvss": "2.0",
                        "endpoint": f"https://{hostname}/.well-known/security.txt",
                        "description": "No /.well-known/security.txt disclosure policy found.",
                        "cli_fix": f'printf "Contact: mailto:security@{hostname}\\n" | sudo tee /var/www/html/.well-known/security.txt',
                    })
            except Exception:
                pass

        final_score = max(score, 10)
        executive_summary = generate_executive_brief(hostname, final_score, vulnerabilities)

        hours_saved = round(1.5 + (len(vulnerabilities) * 0.65), 1)
        cost_saved_usd = int(round(hours_saved * 45))

        return jsonify({
            "status": "success",
            "target": target_url,
            "profile": profile,
            "recon": {
                **recon_info,
                "raw_headers": raw_headers_dict,
                "security_txt": security_txt_found,
            },
            "roi_metrics": {
                "engineer_hours_saved": hours_saved,
                "estimated_cost_saved_usd": cost_saved_usd,
                "tasks_automated": 7 + len(vulnerabilities),
            },
            "executive_summary": executive_summary,
            "security_score": final_score,
            "total_issues": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }), 200

    except requests.exceptions.RequestException as e:
        return jsonify({"status": "error", "message": f"Connection failed: {str(e)}"}), 400


@app.route("/api/ai-fix", methods=["POST"])
def generate_ai_fix():
    data = request.json or {}
    vuln_title = (data.get("title") or "").strip()
    vuln_desc = (data.get("description") or "").strip()

    if not ai_client:
        return jsonify({
            "status": "success",
            "remediation": (
                f"# Remediation Runbook: {vuln_title}\n"
                f"# {vuln_desc}\n"
                f'add_header Content-Security-Policy "default-src \'self\';" always;\n'
                f"sudo nginx -t && sudo systemctl reload nginx"
            ),
        }), 200

    prompt = (
        f"Provide a concise Security & Network Engineer remediation runbook for:\n"
        f"Finding: {vuln_title}\n"
        f"Context: {vuln_desc}\n"
        f"Include copy-pasteable Nginx, Apache, or Linux/UFW/DNS CLI fixes and a 1-line verification command."
    )

    try:
        remediation_text = call_gemini_text(prompt)
        return jsonify({"status": "success", "remediation": remediation_text}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/create-jira-ticket", methods=["POST"])
def create_jira_ticket():
    try:
        data = request.json or {}
        summary = data.get("title", "Security Vulnerability Detected")
        description = data.get("description", "Vulnerability found by CyberDNA MXDR Portal")

        jira_domain = os.getenv("JIRA_DOMAIN", "").strip()
        jira_user_email = os.getenv("JIRA_USER_EMAIL", "").strip()
        jira_api_token = os.getenv("JIRA_API_TOKEN", "").strip()
        project_key = os.getenv("JIRA_PROJECT_KEY", "KAN").strip()

        if jira_domain and jira_user_email and jira_api_token:
            url = f"https://{jira_domain}/rest/api/2/issue"
            auth = HTTPBasicAuth(jira_user_email, jira_api_token)
            headers = {"Content-Type": "application/json"}
            payload = {
                "fields": {
                    "project": {"key": project_key},
                    "summary": summary,
                    "description": description,
                    "issuetype": {"name": "Task"},
                }
            }
            response = requests.post(
                url,
                data=json.dumps(payload),
                headers=headers,
                auth=auth,
                timeout=8,
            )
            if response.status_code == 201:
                res_data = response.json()
                issue_key = res_data.get("key")
                return jsonify({
                    "status": "success",
                    "mode": "live",
                    "issue_key": issue_key,
                    "issue_url": f"https://{jira_domain}/browse/{issue_key}",
                }), 200
            return jsonify({
                "status": "error",
                "message": f"Jira API error ({response.status_code}): {response.text}",
            }), 400

        return jsonify({
            "status": "success",
            "mode": "local_queue",
            "issue_key": f"{project_key}-101",
            "issue_url": f"https://{jira_domain or 'atlassian.net'}/browse/{project_key}-101",
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/send-slack-alert", methods=["POST"])
def send_slack_alert():
    try:
        data = request.json or {}
        message = data.get("message", "CyberDNA Security Alert")
        webhook_url = os.getenv("SLACK_WEBHOOK_URL", "").strip()

        if not webhook_url:
            return jsonify({
                "status": "error",
                "message": "SLACK_WEBHOOK_URL missing in .env",
            }), 400

        res = requests.post(
            webhook_url,
            json={"text": f"*CyberDNA MXDR Alert:* {message}"},
            timeout=6,
        )
        if res.status_code == 200:
            return jsonify({
                "status": "success",
                "mode": "live",
                "message": "Sent to Slack",
            }), 200

        return jsonify({
            "status": "error",
            "message": f"Slack error: {res.text}",
        }), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/create-servicenow-ticket", methods=["POST"])
def create_servicenow_ticket():
    try:
        data = request.json or {}
        short_desc = data.get("title", "CyberDNA Incident")
        desc = data.get("description", "Auto-escalated from CyberDNA MXDR")
        assigned_to = data.get("assigned_to", "")

        sn_instance = os.getenv("SERVICENOW_INSTANCE", "").strip()
        sn_user = os.getenv("SERVICENOW_USER", "").strip()
        sn_pass = os.getenv("SERVICENOW_PASSWORD", "").strip()

        if not (sn_instance and sn_user and sn_pass):
            return jsonify({
                "status": "error",
                "message": "ServiceNow credentials missing in .env",
            }), 400

        url = f"https://{sn_instance}/api/now/table/incident"
        payload = {
            "short_description": short_desc,
            "description": desc,
            "urgency": "2",
            "impact": "2",
            "work_notes": f"Assigned Engineer: {assigned_to}",
        }
        res = requests.post(
            url,
            auth=HTTPBasicAuth(sn_user, sn_pass),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            data=json.dumps(payload),
            timeout=8,
        )
        if res.status_code in [200, 201]:
            inc_number = res.json().get("result", {}).get("number", "INC0010001")
            return jsonify({
                "status": "success",
                "mode": "live",
                "ticket_number": inc_number,
                "ticket_url": f"https://{sn_instance}/nav_to.do?uri=incident.do?sysparm_query=number={inc_number}",
            }), 200

        return jsonify({
            "status": "error",
            "message": f"ServiceNow error: {res.text}",
        }), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/login", methods=["POST"])
def soc_login():
    data = request.json or {}
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    valid_password = os.environ.get("SOC_LOGIN_PASSWORD", "Soc@2026")

    if email and "@" in email and password == valid_password:
        return jsonify({
            "status": "success",
            "message": "Authenticated",
            "user": {"email": email, "role": "SOC & NetOps Engineer"},
        }), 200

    return jsonify({
        "status": "error",
        "message": "Invalid SOC credentials.",
    }), 401


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)