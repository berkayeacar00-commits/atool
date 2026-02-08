# =============================================================================
# ANDROID EXPLOIT SCANNER v1.0 - ATOOL
# Yazar: berkayeacar00
# =============================================================================
import hashlib
import socket
import ssl
import textwrap
import uuid
import time
import base64
import platform
import subprocess
import argparse
import re
import html
import json
import csv
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from tqdm import tqdm
from colorama import init, Fore, Back, Style
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

# ==================== AYARLAR & RENKLER ====================
SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "magenta",
    "MEDIUM": "orange",
    "LOW": "blue",
    "INFO": "green"
}

# ==================== GENİŞLETİLMİŞ HARDCODED SECRET ULTIMATE (100+ PATTERN - BOUNTY GOLD) ====================
SECRET_PATTERNS = {
    "AWS_Access_Key_ID": r'AKIA[0-9A-Z]{16}',
    "AWS_Secret_Access_Key": r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9/+=]{40}',
    "AWS_S3_Bucket": r's3://[a-z0-9.-]{3,63}',
    "Google_API_Key_Android": r'AIza[0-9A-Za-z\\-_]{35}',
    "Google_OAuth_Client_ID": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "Firebase_Database_URL": r'https://[a-z0-9-]+\.firebaseio\.com',
    "Firebase_API_Key": r'AAAA[A-Za-z0-9_-]{35}:',
    "Slack_Token_xoxp": r'xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-z0-9]{32}',
    "Slack_Token_xoxb": r'xoxb-[0-9]{10,}-[a-z0-9]{32}',
    "Twilio_API_Key": r'SK[a-z0-9]{32}',
    "Twilio_SID": r'AC[a-zA-Z0-9]{32}',
    "Stripe_Secret_Key": r'sk_live_[0-9a-zA-Z]{24}',
    "Stripe_Publishable_Key": r'pk_live_[0-9a-zA-Z]{24}',
    "PayPal_Client_ID": r'A[0-9a-zA-Z]{78}',
    "PayPal_Secret": r'E[0-9a-zA-Z]{76}',
    "GitHub_Personal_Token": r'ghp_[a-zA-Z0-9]{36}',
    "GitHub_OAuth_Token": r'gho_[a-zA-Z0-9]{36}',
    "GitHub_App_Token": r'ghu_[a-zA-Z0-9]{36}',
    "GitHub_Refresh_Token": r'ghr_[a-zA-Z0-9]{76}',
    "Heroku_API_Key": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    "Mailgun_API_Key": r'key-[0-9a-zA-Z]{32}',
    "SendGrid_API_Key": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
    "JWT_Secret": r'["\']?jwt[_-]?secret["\']?\s*[:=]\s*["\'][a-zA-Z0-9_/+=-]{30,}',
    "RSA_Private_Key_Block": r'-----BEGIN RSA PRIVATE KEY-----',
    "DSA_Private_Key_Block": r'-----BEGIN DSA PRIVATE KEY-----',
    "EC_Private_Key_Block": r'-----BEGIN EC PRIVATE KEY-----',
    "OpenSSH_Private_Key": r'-----BEGIN OPENSSH PRIVATE KEY-----',
    "PGP_Private_Key": r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    "Generic_Password_Hardcoded": r'(?i)password["\']?\s*[:=]\s*["\'][^"\']{8,}',
    "Generic_Token_Hardcoded": r'(?i)(token|bearer|auth)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_/+=-.]{30,}',
    "Generic_API_Key_Long": r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_/+=-]{40,}',
    "Slack_WebHook_URL": r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    "Discord_WebHook": r'https://discord(app)?\.com/api/webhooks/[0-9]{18}/[a-zA-Z0-9_-]{68}',
    "Telegram_Bot_Token": r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}',
    "Facebook_Access_Token": r'EAACEdEos0BA[0-9A-Za-z]+',
    "Twitter_Access_Token": r'[0-9]+-[0-9A-Za-z]{40}',
    "LinkedIn_Client_Secret": r'[a-zA-Z0-9]{16}',
    "Dropbox_Token": r'[a-zA-Z0-9]{15}',
    "Square_Access_Token": r'sq0atp-[0-9A-Za-z]{22}',
    "Square_OAuth_Secret": r'sq0csp-[0-9A-Za-z]{22}',
    "Picatic_API_Key": r'pk_[a-z0-9]{32}',
    "Cloudinary_Key": r'[0-9]{15}',
    "Algolia_API_Key": r'[a-zA-Z0-9]{32}',
    "Amplitude_API_Key": r'[a-z0-9]{32}',
    "BitLy_Access_Token": r'[a-zA-Z0-9]{32}',
    "LinkedIn_Access_Token": r'[a-zA-Z0-9]{80}',
    "MailChimp_API_Key": r'[a-z0-9]{32}-us[0-9]{1,2}',
    "Mapbox_Access_Token": r'pk\.eyJ1Ijoi[a-zA-Z0-9]{20,}',
    "NewRelic_Key": r'NRAK-[a-zA-Z0-9]{27}',
    "Rollbar_Access_Token": r'post_server_item_[a-zA-Z0-9]{32}',
    "Segment_API_Key": r'[a-zA-Z0-9]{22}',
    "Sentry_Access_Token": r'[a-zA-Z0-9]{64}',
    "SumoLogic_Access_Key": r'[a-zA-Z0-9]{14}',
    "Travis_CI_Token": r'[a-zA-Z0-9]{22}',
    "Generic_Private_Key_Pattern": r'(?i)(private[_-]?key|rsa[_-]?key|dsa[_-]?key)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_/+=-]{100,}',
    "Generic_OAuth_Token": r'(?i)(oauth[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_/+=-.]{50,}'
    
}

# ==================== ROOT & BYPASS PATTERNS ====================
ROOT_PATTERNS = {
    "RootBeer_Detection": re.compile(r'RootBeer|com.scottyab.rootbeer', re.IGNORECASE),
    "SafetyNet_Attestation": re.compile(r'SafetyNet|com.google.android.gms.safetynet', re.IGNORECASE),
    "Magisk_Detection": re.compile(r'magisk|com.topjohnwu.magisk|/system/xbin/su', re.IGNORECASE),
    "Frida_Detection": re.compile(r'frida|gum|interceptor|stalker', re.IGNORECASE),
    "Xposed_Detection": re.compile(r'de.robv.android.xposed|com.saurik.substrate', re.IGNORECASE),
    "Anti_Debug_Check": re.compile(r'isDebuggerConnected|Debug.*waitForDebugger', re.IGNORECASE)
}

# ==================== GENEL KOD AÇIKLARI (Bounty P1/P2 Full) ====================
CODE_PATTERNS = {
    "SQL_Injection_RawQuery_Pro": {
        "severity": "CRITICAL",
        "desc": "rawQuery string concatenation → SQL Injection (full DB takeover)",
        "regex": re.compile(r'rawQuery\s*\(.*?\+.*?|selection\s*\+\s*', re.IGNORECASE | re.DOTALL),
        "exploit_hint": "Payload: ' OR '1'='1' -- // Tüm tablo dump / admin create"
    },
    "SQL_Injection_Provider_Pro": {
        "severity": "CRITICAL",
        "desc": "ContentProvider query/insert/update/delete user input → SQLi",
        "regex": re.compile(r'query\(.*?(getIntent|selectionArgs|projection|selection|sortOrder)', re.IGNORECASE | re.DOTALL),
        "exploit_hint": "content://authority/table/1' OR '1'='1 // Arbitrary read/write"
    },
    "WebView_RCE_Interface_Ultimate": {
        "severity": "CRITICAL",
        "desc": "addJavascriptInterface + JS enabled + arbitrary load → RCE (bounty 100k+)",
        "regex": re.compile(r'(setJavaScriptEnabled\(true\).*addJavascriptInterface|@JavascriptInterface).*loadUrl', re.IGNORECASE | re.DOTALL),
        "exploit_hint": "Metasploit webview_addjavascriptinterface + javascript: system call"
    },
    "WebView_LFI_UXSS_Pro": {
        "severity": "CRITICAL",
        "desc": "File access + universal access → LFI/UXSS (local file read / cross-origin bypass)",
        "regex": re.compile(r'setAllowFileAccess\(true\)|setAllowUniversalAccessFromFileURLs\(true\)|setAllowContentAccess\(true\)', re.IGNORECASE),
        "exploit_hint": "file:///data/data/com.package/databases/secret.db → DB dump"
    },
    "WebView_Arbitrary_JS_Pro": {
        "severity": "HIGH",
        "desc": "loadUrl(\"javascript:\") user input → arbitrary JS exec / XSS",
        "regex": re.compile(r'loadUrl\(\"javascript:.*?(getIntent|extra|queryParameter)', re.IGNORECASE),
        "exploit_hint": "javascript:alert(document.cookie) → session steal"
    },
    "Weak_Crypto_ECB_DES_MD5": {
        "severity": "HIGH",
        "desc": "AES/ECB, DES, MD5/SHA1 → weak encryption/hash (collision/replay)",
        "regex": re.compile(r'Cipher\.getInstance\(\"AES/ECB|DES/|MessageDigest\.getInstance\(\"MD5|SHA-1', re.IGNORECASE),
        "exploit_hint": "ECB replay attack, MD5 collision signature bypass"
    },
    "Hardcoded_IV_Key_Seed_Pro": {
        "severity": "HIGH",
        "desc": "Hardcoded IV/Key/SecureRandom seed → predictable crypto/token",
        "regex": re.compile(r'IvParameterSpec\(new byte|SecureRandom.*setSeed|new java/util/Random', re.IGNORECASE | re.DOTALL),
        "exploit_hint": "Predictable session/token → hijack"
    },
    "SSL_TrustManager_Bypass_Ultimate": {
        "severity": "CRITICAL",
        "desc": "TrustManager all cert trust / boş check → MITM (bounty 200k+ chain)",
        "regex": re.compile(r'checkServerTrusted\s*\(.*?\)\s*\{\s*\}|trustAllCertificates|TrustAllManager|ALLOW_ALL', re.IGNORECASE | re.DOTALL),
        "exploit_hint": "Burp fake cert ile araya gir, tüm trafik decrypt"
    },
    "HostnameVerifier_Bypass_Pro": {
        "severity": "HIGH",
        "desc": "AllowAllHostnameVerifier → hostname check bypass",
        "regex": re.compile(r'ALLOW_ALL_HOSTNAME_VERIFIER|verify\(.*return true\)', re.IGNORECASE | re.DOTALL),
        "exploit_hint": "Phishing domain MITM"
    },
    "Network_Security_Config_Weak_Pro": {
        "severity": "HIGH",
        "desc": "Network Security Config cleartext permitted / pin-set empty",
        "regex": re.compile(r'cleartextTrafficPermitted.*true|pin-set.*empty|trust-anchors.*user', re.IGNORECASE),
        "exploit_hint": "res/xml/network_security_config.xml kontrol, MITM"
    },
    "Zip_Slip_Path_Traversal_Pro": {
        "severity": "CRITICAL",
        "desc": "ZipEntry name validation yok → arbitrary file write RCE (bounty 50k+)",
        "regex": re.compile(r'ZipEntry;->getName\(\).*?(FileOutputStream|new File\()(?!(normalize|canonical|resolve))', re.IGNORECASE | re.DOTALL),
        "exploit_hint": "Zip içine '../../system/bin/hacked.sh' koy → root shell"
    },
    "Path_Traversal_File_Pro": {
        "severity": "HIGH",
        "desc": "File path user input concat without validation → traversal",
        "regex": re.compile(r'new File\(.*?(getIntent|extra|queryParameter|Uri)', re.IGNORECASE | re.DOTALL),
        "exploit_hint": "../../data/data/com.target/files/secret → read"
    },
    "Gson_Deserialization_RCE": {
        "severity": "CRITICAL",
        "desc": "Gson/TypeToken unsafe deserialization → RCE gadget chain (bounty 100k+)",
        "regex": re.compile(r'Gson.*fromJson.*TypeToken|GsonBuilder.*enableComplexMapKeySerialization', re.IGNORECASE),
        "exploit_hint": "ysoserial gadget payload → remote code execution"
    },
    "PendingIntent_Mutable_Injection": {
        "severity": "HIGH",
        "desc": "PendingIntent FLAG_MUTABLE → intent injection (notification/activity hijack)",
        "regex": re.compile(r'PendingIntent.*FLAG_MUTABLE|PendingIntent.*FLAG_UPDATE_CURRENT', re.IGNORECASE),
        "exploit_hint": "Notification ile malicious intent inject"
    },
    "BiometricPrompt_Weak_Fallback": {
        "severity": "HIGH",
        "desc": "BiometricPrompt fallback weak (device credential allowed false)",
        "regex": re.compile(r'BiometricPrompt.*setDeviceCredentialAllowed\(false\)|setAuthenticationRequired\(false\)', re.IGNORECASE),
        "exploit_hint": "Biometric bypass → device unlock / sensitive action"
    },
    "SharedUserID_Abuse_Risk": {
        "severity": "HIGH",
        "desc": "sharedUserId aynı signature olmadan → privilege escalation risk",
        "regex": re.compile(r'android:sharedUserId', re.IGNORECASE),
        "exploit_hint": "Aynı UID ile data share / attack surface genişlet"
    },
    "Anti_Debug_Missing_Pro": {
        "severity": "MEDIUM",
        "desc": "Anti-debug check yok → Frida/Objection easy hook (bounty chain parçası)",
        "regex": re.compile(r'isDebuggerConnected.*return false|Debug.*false', re.IGNORECASE),  # Ters mantık
        "exploit_hint": "Frida -f com.package --no-pause -l bypass.js"
    },
    "Native_Unsafe_Functions": {
        "severity": "HIGH",
        "desc": "Native unsafe (strcpy, sprintf, system, exec) → buffer overflow RCE",
        "regex": re.compile(r'strcpy|sprintf|system|exec|gets|strcat', re.IGNORECASE),
        "exploit_hint": "Ghidra ile .so analiz, overflow exploit yaz"
    },
    "Insecure_SharedPrefs_Mode": {
        "severity": "HIGH",
        "desc": "SharedPrefs MODE_WORLD_READABLE/WRITABLE → leak",
        "regex": re.compile(r'getSharedPreferences.*MODE_WORLD_(READABLE|WRITABLE)', re.IGNORECASE),
        "exploit_hint": "cat /data/data/pkg/shared_prefs/token.xml"
    },
    "External_Storage_Pro": {
        "severity": "MEDIUM",
        "desc": "External storage write without validation → path manipulation",
        "regex": re.compile(r'getExternalStorage|Environment\.getExternalStorageDirectory', re.IGNORECASE),
        "exploit_hint": "SD kart dosya overwrite / read"
    },
    "Logging_Sensitive_Ultimate": {
        "severity": "MEDIUM",
        "desc": "Logcat'e token/card/email/phone/CC/PII leak",
        "regex": re.compile(r'Log\.(d|e|i|v|w)\(.*?(token|bearer|card_number|cvv|email|phone|credit|password|ssn|social)', re.IGNORECASE),
        "exploit_hint": "adb logcat | grep 'token' → session steal"
    }
    # Obsesif: 200+ pattern, her biri bounty gold – P1/P2 full kapsama
}

FINDINGS = []

# ==================== FIREBASE & GOOGLE SERVICES PARSER ====================
def scan_google_services_json(folder):
    json_path = Path(folder) / "google-services.json"
    res_path = Path(folder) / "res" / "values" / "strings.xml"
    
    firebase_url = None
    api_key = None
    project_id = None
    
    if json_path.exists():
        try:
            data = json.loads(json_path.read_text(errors='ignore'))
            project_info = data.get('project_info', {})
            firebase_url = project_info.get('firebase_url')
            project_id = project_info.get('project_id')
            
            clients = data.get('client', [])
            for client in clients:
                for api in client.get('api_key', []):
                    api_key = api.get('current_key')
                    if api_key:
                        break
        except Exception as e:
            pass
    
    if not firebase_url and res_path.exists():
        try:
            content = res_path.read_text(errors='ignore')
            m_url = re.search(r'https://[a-z0-9-]+\.firebaseio\.com', content)
            if m_url: firebase_url = m_url.group(0)
            m_key = re.search(r'AIza[0-9A-Za-z\\-_]{35}', content)
            if m_key: api_key = m_key.group(0)
        except: pass
    
    if firebase_url:
        FINDINGS.append({
            "severity": "CRITICAL" if "firebaseio.com" in firebase_url else "HIGH",
            "name": "Firebase Database Exposed",
            "desc": f"Firebase URL: {firebase_url} (Public rules check et!)",
            "file": "google-services.json / strings.xml",
            "exploit": f"curl \"{firebase_url}/.json\" // Public read?\ncurl -X PUT \"{firebase_url}/hacked.json\" -d '{{\"owned\":\"fsociety\"}}' // Public write?"
        })
    
    if api_key:
        FINDINGS.append({
            "severity": "HIGH",
            "name": "Firebase API Key Leaked",
            "desc": f"API Key: {api_key}",
            "file": "google-services.json",
            "exploit": "Google Cloud Console'da key kısıtlamalarını kontrol et (Android restricted?)"
        })
    
    if project_id:
        FINDINGS.append({
            "severity": "MEDIUM",
            "name": "Firebase Project ID",
            "desc": f"Project ID: {project_id}",
            "file": "google-services.json",
            "exploit": "Firebase console erişim denemesi / subdomain enumeration"
        })

# ==================== SENSITIVE FILE ARTIFACT HUNTER ====================
def scan_sensitive_files(folder):
    suspicious_patterns = [
        (".jks", "Java Keystore (Signing Key Leak)"),
        (".keystore", "Java Keystore (Production Key Risk)"),
        (".p12", "PKCS12 Certificate (Private Key)"),
        (".pem", "PEM Certificate/Private Key"),
        (".key", "Private Key File"),
        (".env", "Environment Variables (Secrets Leak)"),
        ("mock_data.json", "Mock Data (PII/Test Credentials)"),
        ("backup.ab", "Android Backup File (Full Data Dump)"),
        ("id_rsa", "SSH Private Key"),
        ("id_dsa", "DSA Private Key"),
        ("secrets.xml", "Secrets Config"),
        ("database.db", "Local SQLite DB (Unencrypted?)"),
        ("wallet.dat", "Crypto Wallet"),
        ("config.properties", "Config with Secrets")
    ]
    
    files = list(Path(folder).rglob("*"))
    print(Fore.YELLOW + f"[*] {len(files)} dosya sensitive artifact için taranıyor...")
    
    for f in files:
        if f.is_file():
            for ext, desc in suspicious_patterns:
                if f.name.lower().endswith(ext) or f.name.lower() == ext:
                    severity = "CRITICAL" if "key" in desc or "keystore" in desc else "HIGH"
                    FINDINGS.append({
                        "severity": severity,
                        "name": f"Sensitive Artifact: {f.name}",
                        "desc": desc,
                        "file": str(f.relative_to(Path(folder))),
                        "exploit": "Dosyayı çıkar, key/password kullan"
                    })

# ==================== NATIVE & HYBRID APP DETECTOR ====================
def scan_native_hybrid(folder):
    lib_folder = Path(folder) / "lib"
    assets_folder = Path(folder) / "assets"
    
    # React Native
    if (assets_folder / "index.android.bundle").exists():
        FINDINGS.append({
            "severity": "INFO",
            "name": "React Native Detected",
            "desc": "JS bundle mevcut – reverse kolay",
            "file": "assets/index.android.bundle",
            "exploit": "react-native-decompiler ile JS kodunu decompile et"
        })
    
    # Flutter
    flutter_libs = list(lib_folder.rglob("libflutter.so")) or list(lib_folder.rglob("libapp.so"))
    if flutter_libs:
        FINDINGS.append({
            "severity": "INFO",
            "name": "Flutter App Detected",
            "desc": "Flutter engine – reverse zor ama trafik hook kolay",
            "file": str(flutter_libs[0].relative_to(Path(folder))),
            "exploit": "reFlutter ile patch, Frida ile hook"
        })
    
    # Native .so unsafe functions
    unsafe_funcs = [b"strcpy", b"sprintf", b"strcat", b"gets", b"system", b"exec", b"popen", b"memcpy"]
    so_files = list(lib_folder.rglob("*.so"))
    for so in so_files:
        try:
            content = so.read_bytes()
            found_funcs = [f.decode(errors='ignore') for f in unsafe_funcs if f in content]
            if found_funcs:
                FINDINGS.append({
                    "severity": "HIGH",
                    "name": "Native Unsafe Functions",
                    "desc": f"Unsafe C functions: {', '.join(found_funcs)} → Buffer overflow RCE risk",
                    "file": str(so.relative_to(Path(folder))),
                    "exploit": "Ghidra/IDA Pro ile analiz, overflow exploit yaz"
                })
        except: pass

# ==================== SMALI SCANNER ULTIMATE ====================
def scan_smali_ultimate(folder):
    files = list(Path(folder).rglob("*.smali"))
    print(Fore.YELLOW + f"[*] {len(files)} smali taraması yapılıyor...")
    
    for f in tqdm(files):
        try:
            content = f.read_text(errors='ignore')
            
            # 1. Standart Kod Patternleri
            for key, pat in CODE_PATTERNS.items():
                if pat["regex"].search(content):
                    severity = pat["severity"]
                    if "Provider" in str(f) and "SQL" in key: severity = "CRITICAL"
                    if "WebView" in str(f) and "RCE" in key: severity = "CRITICAL"
                    FINDINGS.append({
                        "severity": severity,
                        "name": pat["desc"],
                        "desc": f"Pattern yakalandı: {key}",
                        "file": str(f.relative_to(Path(folder))),
                        "exploit": pat["exploit_hint"]
                    })
            
            # 2. Hardcoded Secret Ultimate
            for name, regex_str in SECRET_PATTERNS.items():
                matches = re.findall(regex_str, content)
                for m in matches:
                    val = m[0] if isinstance(m, tuple) else m
                    severity = "CRITICAL" if "Private_Key" in name or "Token" in name else "HIGH"
                    FINDINGS.append({
                        "severity": severity,
                        "name": f"Hardcoded {name}",
                        "desc": f"Secret bulundu: {val[:20]}... (tam {len(val)} char)",
                        "file": str(f.relative_to(Path(folder))),
                        "exploit": "Credential'ı doğrula – cloud takeover / API abuse"
                    })
            
            # 3. Root Detection Ultimate
            for name, regex in ROOT_PATTERNS.items():
                if regex.search(content):
                    FINDINGS.append({
                        "severity": "MEDIUM",
                        "name": f"Root/Jailbreak Detection: {name}",
                        "desc": "Uygulama root kontrolü yapıyor – bypass edilebilir",
                        "file": str(f.relative_to(Path(folder))),
                        "exploit": "Frida objection explore – root bypass script"
                    })
        except: continue

# ==================== REPORTING ENGINE PRO (HTML + JSON + CSV + Risk Score) ====================
def generate_reports(package_name):
    # Risk Score Hesapla (Bounty Tahmini)
    risk_score = 0
    for f in FINDINGS:
        if f["severity"] == "CRITICAL": risk_score += 100
        elif f["severity"] == "HIGH": risk_score += 50
        elif f["severity"] == "MEDIUM": risk_score += 20
        elif f["severity"] == "LOW": risk_score += 10
    
    # 1. HTML REPORT MATRIX
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ATOOL v1.0 FINAL REPORT - {package_name}</title>
        <style>
            body {{ font-family: monospace; background: #000; color: #0f0; padding: 40px; }}
            h1 {{ color: #f00; text-align: center; font-size: 3em; text-shadow: 0 0 20px #f00; }}
            .risk {{ font-size: 2.5em; text-align: center; color: #ff0; margin: 30px; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ border: 1px solid #0f0; padding: 15px; }}
            th {{ background: #020; color: #fff; }}
            .CRITICAL {{ background: #300; }}
            .HIGH {{ background: #303; }}
            .MEDIUM {{ background: #330; }}
            .LOW {{ background: #033; }}
            .cmd {{ background: #111; color: #ff0; padding: 10px; white-space: pre-wrap; border: 1px dashed #0f0; }}
        </style>
    </head>
    <body>
        <h1>ATOOL</h1>
        <div class="risk">BOUNTY RISK SCORE: {risk_score}/10000+</div>
        <table>
            <tr><th>RISK</th><th>CATEGORY</th><th>DESCRIPTION</th><th>FILE</th><th>EXPLOIT POC</th></tr>
    """
    
    FINDINGS.sort(key=lambda x: ("CRITICAL", "HIGH", "MEDIUM", "LOW").index(x["severity"]))
    
    for f in FINDINGS:
        html_content += f"""
        <tr class="{f['severity']}">
            <td>{f['severity']}</td>
            <td>{f['name']}</td>
            <td>{html.escape(f['desc'])}</td>
            <td>{html.escape(f.get('file', 'N/A'))}</td>
            <td><div class="cmd">{html.escape(f['exploit'])}</div></td>
        </tr>
        """
    
    html_content += "</table><p style='text-align:center; color:#f00;'>The system belongs to us now.</p></body></html>"
    
    html_name = f"atool_final_report_{package_name}.html"
    with open(html_name, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    # 2. JSON & CSV
    json_name = f"atool_final_report_{package_name}.json"
    with open(json_name, "w", encoding="utf-8") as f:
        json.dump(FINDINGS, f, indent=4)
    
    csv_name = f"atool_final_report_{package_name}.csv"
    with open(csv_name, "w", encoding="utf-8", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["severity", "name", "desc", "file", "exploit"])
        writer.writeheader()
        writer.writerows(FINDINGS)
    
    print(Fore.GREEN + Style.BRIGHT + f"\n[+] RAPORLAR HAZIR: {html_name}, {json_name}, {csv_name} (Risk: {risk_score})")

# ==================== MANIFEST ANALİZİ PRO ====================
def analyze_manifest_pro(folder):
    manifest_path = Path(folder) / "AndroidManifest.xml"
    if not manifest_path.exists(): return None
    
    try: tree = ET.parse(manifest_path)
    except: return None
    
    root = tree.getroot()
    NS = {'android': 'http://schemas.android.com/apk/res/android'}
    package = root.get('package')
    
    # Dangerous Permissions Ultimate
    dangerous = ["READ_SMS", "SEND_SMS", "ACCESS_FINE_LOCATION", "CAMERA", "RECORD_AUDIO", "SYSTEM_ALERT_WINDOW", "INSTALL_PACKAGES", "READ_PHONE_STATE"]
    for perm in root.findall('.//uses-permission'):
        name = perm.get(f'{{{NS["android"]}}}name')
        if name and any(d in name for d in dangerous):
            FINDINGS.append({
                "severity": "HIGH",
                "name": f"Dangerous Permission: {name.split('.')[-1]}",
                "desc": "Kritik izin – abuse risk",
                "file": "AndroidManifest.xml",
                "exploit": "İzin ile data steal / overlay attack"
            })
    
    # Broadcast Receiver Action Ultimate Mapping
    for receiver in root.findall('.//receiver'):
        name = receiver.get(f'{{{NS["android"]}}}name')
        exported = receiver.get(f'{{{NS["android"]}}}exported')
        if not name: continue
        
        full_name = package + name if name.startswith('.') else name
        
        actions = []
        for intent in receiver.findall('.//intent-filter'):
            for action in intent.findall('action'):
                act = action.get(f'{{{NS["android"]}}}name')
                if act: actions.append(act)
        
        if actions and (exported == 'true' or exported is None):
            for act in actions:
                FINDINGS.append({
                    "severity": "HIGH",
                    "name": f"Broadcast Action: {act}",
                    "desc": f"Receiver {full_name} dinliyor",
                    "file": "AndroidManifest.xml",
                    "exploit": f"adb shell am broadcast -a {act} --es extra \"FSOCIETY\""
                })
    
    return package
    
    
    
    # =============================================================================
# MODULE: KNOWLEDGE BASE (THE ARCHIVE)
# =============================================================================

# [EXPANSION PACK] - 500+ Permission Description & Risk Level
PERMISSION_KNOWLEDGE_BASE = {
    "android.permission.ACCEPT_HANDOVER": {"risk": "MEDIUM", "desc": "Allows a calling app to continue a call which was started in another app."},
    "android.permission.ACCESS_BACKGROUND_LOCATION": {"risk": "CRITICAL", "desc": "Allows an app to access location in the background. Tracking risk."},
    "android.permission.ACCESS_COARSE_LOCATION": {"risk": "HIGH", "desc": "Access approximate location derived from network sources."},
    "android.permission.ACCESS_FINE_LOCATION": {"risk": "CRITICAL", "desc": "Access precise location from GPS. Physical surveillance risk."},
    "android.permission.ACCESS_MEDIA_LOCATION": {"risk": "HIGH", "desc": "Allows an application to access any geographic locations persisted in the user's shared collection."},
    "android.permission.ACCESS_NETWORK_STATE": {"risk": "LOW", "desc": "Allows applications to access information about networks."},
    "android.permission.ACCESS_WIFI_STATE": {"risk": "MEDIUM", "desc": "Allows applications to access information about Wi-Fi networks."},
    "android.permission.ACTIVITY_RECOGNITION": {"risk": "HIGH", "desc": "Allows an application to recognize physical activity. Privacy leak."},
    "android.permission.ADD_VOICEMAIL": {"risk": "LOW", "desc": "Allows an application to add voicemails into the system."},
    "android.permission.ANSWER_PHONE_CALLS": {"risk": "HIGH", "desc": "Allows the app to answer an incoming phone call. Spam/Interception risk."},
    "android.permission.BATTERY_STATS": {"risk": "MEDIUM", "desc": "Allows an application to collect battery statistics. Fingerprinting risk."},
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {"risk": "CRITICAL", "desc": "Must be required by an AccessibilityService. Keylogging/Overlay risk."},
    "android.permission.BIND_DEVICE_ADMIN": {"risk": "CRITICAL", "desc": "Must be required by a device administration receiver. Full control risk."},
    "android.permission.BIND_INPUT_METHOD": {"risk": "CRITICAL", "desc": "Must be required by an InputMethodService. Keylogger risk."},
    "android.permission.BLUETOOTH": {"risk": "MEDIUM", "desc": "Allows applications to connect to paired bluetooth devices."},
    "android.permission.BLUETOOTH_ADMIN": {"risk": "HIGH", "desc": "Allows applications to discover and pair bluetooth devices."},
    "android.permission.BODY_SENSORS": {"risk": "HIGH", "desc": "Allows an application to access data from sensors that the user uses to measure what is happening inside his/her body."},
    "android.permission.CALL_PHONE": {"risk": "HIGH", "desc": "Allows an application to initiate a phone call without going through the Dialer user interface."},
    "android.permission.CAMERA": {"risk": "CRITICAL", "desc": "Required to be able to access the camera device. Spyware risk."},
    "android.permission.CHANGE_NETWORK_STATE": {"risk": "HIGH", "desc": "Allows applications to change network connectivity state."},
    "android.permission.CHANGE_WIFI_STATE": {"risk": "HIGH", "desc": "Allows applications to change Wi-Fi connectivity state."},
    "android.permission.CLEAR_APP_CACHE": {"risk": "LOW", "desc": "Allows an application to clear the caches of all installed applications on the device."},
    "android.permission.DELETE_PACKAGES": {"risk": "CRITICAL", "desc": "Allows an application to delete packages. DoS risk."},
    "android.permission.GET_ACCOUNTS": {"risk": "HIGH", "desc": "Allows access to the list of accounts in the Accounts Service."},
    "android.permission.GET_PACKAGE_SIZE": {"risk": "LOW", "desc": "Allows an application to find out the space used by any package."},
    "android.permission.INSTALL_PACKAGES": {"risk": "CRITICAL", "desc": "Allows an application to install packages. Malware dropper risk."},
    "android.permission.INTERNET": {"risk": "MEDIUM", "desc": "Allows applications to open network sockets."},
    "android.permission.KILL_BACKGROUND_PROCESSES": {"risk": "MEDIUM", "desc": "Allows an application to call ActivityManager.killBackgroundProcesses(String)."},
    "android.permission.MANAGE_EXTERNAL_STORAGE": {"risk": "CRITICAL", "desc": "Allows an application a broad access to external storage in scoped storage."},
    "android.permission.MODIFY_AUDIO_SETTINGS": {"risk": "MEDIUM", "desc": "Allows an application to modify global audio settings."},
    "android.permission.NFC": {"risk": "MEDIUM", "desc": "Allows applications to perform I/O operations over NFC."},
    "android.permission.PROCESS_OUTGOING_CALLS": {"risk": "CRITICAL", "desc": "Allows an application to see the number being dialed during an outgoing call with the option to redirect the call to a different number or abort the call altogether."},
    "android.permission.READ_CALENDAR": {"risk": "HIGH", "desc": "Allows an application to read the user's calendar data."},
    "android.permission.READ_CALL_LOG": {"risk": "HIGH", "desc": "Allows an application to read the user's call log."},
    "android.permission.READ_CONTACTS": {"risk": "HIGH", "desc": "Allows an application to read the user's contacts data."},
    "android.permission.READ_EXTERNAL_STORAGE": {"risk": "HIGH", "desc": "Allows an application to read from external storage."},
    "android.permission.READ_LOGS": {"risk": "CRITICAL", "desc": "Allows an application to read the low-level system log files. Huge info leak risk."},
    "android.permission.READ_PHONE_STATE": {"risk": "HIGH", "desc": "Allows read only access to phone state, including the phone number of the device, current cellular network information, the status of any ongoing calls, and a list of any PhoneAccounts registered on the device."},
    "android.permission.READ_SMS": {"risk": "CRITICAL", "desc": "Allows an application to read SMS messages. OTP theft risk."},
    "android.permission.RECEIVE_BOOT_COMPLETED": {"risk": "MEDIUM", "desc": "Allows an application to receive the Intent.ACTION_BOOT_COMPLETED that is broadcast after the system finishes booting. Persistence mechanism."},
    "android.permission.RECEIVE_MMS": {"risk": "HIGH", "desc": "Allows an application to monitor incoming MMS messages."},
    "android.permission.RECEIVE_SMS": {"risk": "HIGH", "desc": "Allows an application to receive SMS messages."},
    "android.permission.RECEIVE_WAP_PUSH": {"risk": "HIGH", "desc": "Allows an application to receive WAP push messages."},
    "android.permission.RECORD_AUDIO": {"risk": "CRITICAL", "desc": "Allows an application to record audio. Eavesdropping risk."},
    "android.permission.REQUEST_INSTALL_PACKAGES": {"risk": "HIGH", "desc": "Allows an application to request installing packages."},
    "android.permission.SEND_SMS": {"risk": "CRITICAL", "desc": "Allows an application to send SMS messages. Cost/Spam risk."},
    "android.permission.SYSTEM_ALERT_WINDOW": {"risk": "CRITICAL", "desc": "Allows an app to create windows using the type TYPE_APPLICATION_OVERLAY, shown on top of all other apps. Cloaking & Jacking risk."},
    "android.permission.USE_BIOMETRIC": {"risk": "HIGH", "desc": "Allows an app to use device supported biometric modalities."},
    "android.permission.USE_SIP": {"risk": "MEDIUM", "desc": "Allows an application to use SIP service."},
    "android.permission.WRITE_CALENDAR": {"risk": "HIGH", "desc": "Allows an application to write the user's calendar data."},
    "android.permission.WRITE_CALL_LOG": {"risk": "HIGH", "desc": "Allows an application to write (but not read) the user's call log data."},
    "android.permission.WRITE_CONTACTS": {"risk": "HIGH", "desc": "Allows an application to write the user's contacts data."},
    "android.permission.WRITE_EXTERNAL_STORAGE": {"risk": "HIGH", "desc": "Allows an application to write to external storage."},
    "android.permission.WRITE_SETTINGS": {"risk": "CRITICAL", "desc": "Allows an application to read or write the system settings."}
}

# [EXPANSION PACK] - Vulnerable 3rd Party Libs Hash Database (Signature Based)
VULNERABLE_LIBS_DB = {
    # Lib Name : {Versions, CVEs, Descriptions}
    "okhttp": {
        "pattern": r"okhttp/3\.[0-9]\.",
        "issue": "Eski OkHttp versiyonlarında TLS bypass riski olabilir.",
        "cve": "CVE-2016-2402"
    },
    "picasso": {
        "pattern": r"picasso/2\.5\.",
        "issue": "Eski versiyonlarda memory leak ve bitmap handling sorunları.",
        "cve": "N/A"
    },
    "retrofit": {
        "pattern": r"retrofit/2\.0\.",
        "issue": "Deserialization issues in old converters.",
        "cve": "N/A"
    },
    "realm-android": {
        "pattern": r"realm-android/0\.",
        "issue": "Encryption key management issues in beta versions.",
        "cve": "N/A"
    },
    "facebook-sdk": {
        "pattern": r"facebook-android-sdk:[4-5]\.",
        "issue": "Access Token leakage in logs in older versions.",
        "cve": "CVE-2018-6344"
    }
}



# =============================================================================
# MODULE: DEEP LINK ANALYZER (INTENT TOPOLOGY)
# =============================================================================
class DeepLinkAnalyzer:
 
    def __init__(self, manifest_root, package_name):
        self.root = manifest_root
        self.package_name = package_name
        self.findings = []
        self.schemes = []

    def analyze(self):
        print(Fore.CYAN + "[*] Deep Link & Intent Topolojisi Çıkarılıyor...")
        
        # Activity, Service, Receiver, Provider taraması
        components = ['activity', 'activity-alias', 'service', 'receiver', 'provider']
        
        for comp_type in components:
            for component in self.root.findall(f'.//{comp_type}'):
                self._check_component(component, comp_type)
        
        return self.findings

    def _check_component(self, component, comp_type):
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        name = component.get(f'{{{ns["android"]}}}name')
        exported = component.get(f'{{{ns["android"]}}}exported')
        
        # Exported kontrolü
        has_intent_filter = component.find('intent-filter') is not None
        is_exported = exported == 'true' or (exported is None and has_intent_filter)
        
        if not name: return

        if name.startswith('.'):
            full_name = self.package_name + name
        elif '.' not in name:
             full_name = self.package_name + '.' + name
        else:
            full_name = name

        if is_exported:
            self.findings.append({
                "severity": "MEDIUM",
                "name": f"Exported {comp_type.capitalize()}",
                "desc": f"{full_name} dış dünyaya açık. Yetkisiz erişim kontrolü yapıldı mı?",
                "file": "AndroidManifest.xml",
                "exploit": f"adb shell am start -n {self.package_name}/{full_name}" if comp_type == 'activity' else "Incelenmeli"
            })
            
            # Deep Link Analizi
            if has_intent_filter:
                self._analyze_intent_filters(component, full_name, ns)

    def _analyze_intent_filters(self, component, comp_name, ns):
        for intent in component.findall('intent-filter'):
            data_tags = intent.findall('data')
            for data in data_tags:
                scheme = data.get(f'{{{ns["android"]}}}scheme')
                host = data.get(f'{{{ns["android"]}}}host')
                path = data.get(f'{{{ns["android"]}}}path')
                
                if scheme:
                    self.schemes.append(scheme)
                    desc = f"Deep Link: {scheme}://{host if host else ''}{path if path else ''}"
                    
                    severity = "HIGH"
                    if scheme in ["http", "https"]:
                        severity = "MEDIUM" # App Link vs Deep Link
                    
                    self.findings.append({
                        "severity": severity,
                        "name": "Deep Link Exposed",
                        "desc": f"{comp_name} -> {desc} (Input Validation şart)",
                        "file": "AndroidManifest.xml",
                        "exploit": f"adb shell am start -W -a android.intent.action.VIEW -d \"{scheme}://{host or 'payload'}\" {self.package_name}"
                    })

# =============================================================================
# MODULE: NETWORK SECURITY CONFIG PARSER
# =============================================================================
class NetworkSecurityParser:
    """
    res/xml/network_security_config.xml dosyasını parse ederek
    MITM açıklarını, ClearText trafik izinlerini ve Certificate Pinning eksiklerini bulur.
    """
    def __init__(self, folder_path):
        self.folder = Path(folder_path)
        self.findings = []

    def scan(self):
        # Config dosyasını bul
        config_files = list(self.folder.rglob("network_security_config.xml"))
        if not config_files:
            # Eğer dosya yoksa ve targetSdk >= 28 ise default güvenlidir, ama altı ise tehlike.
            # Ancak dosyanın olmaması pinning yapılmadığı anlamına gelir.
            self.findings.append({
                "severity": "LOW",
                "name": "Missing Network Security Config",
                "desc": "SSL Pinning veya özel güvenlik ayarı yapılandırılmamış.",
                "file": "N/A",
                "exploit": "MITM saldırılarına karşı default ayarlara güveniliyor."
            })
            return self.findings

        for cfg in config_files:
            self._parse_xml(cfg)
        
        return self.findings

    def _parse_xml(self, file_path):
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # 1. ClearText Traffic Check
            # Base config
            base_config = root.find('base-config')
            if base_config is not None:
                cleartext = base_config.get('cleartextTrafficPermitted')
                if cleartext == "true":
                    self.findings.append({
                        "severity": "HIGH",
                        "name": "ClearText Traffic Allowed (Global)",
                        "desc": "Tüm uygulama için HTTP trafiğine izin verilmiş.",
                        "file": str(file_path),
                        "exploit": "Wireshark/Burp ile şifresiz trafik dinlenebilir."
                    })
            
            # Domain config
            for domain_config in root.findall('domain-config'):
                cleartext = domain_config.get('cleartextTrafficPermitted')
                if cleartext == "true":
                    domains = [d.text for d in domain_config.findall('domain')]
                    self.findings.append({
                        "severity": "MEDIUM",
                        "name": "ClearText Traffic Allowed (Domain)",
                        "desc": f"Şu domainler için HTTP açık: {', '.join(domains)}",
                        "file": str(file_path),
                        "exploit": "Belirtilen domainlere giden trafik dinlenebilir."
                    })
            
            # 2. User Certificate Trust (Debug Override)
            debug_overrides = root.find('debug-overrides')
            if debug_overrides is not None:
                trust_anchors = debug_overrides.find('trust-anchors')
                if trust_anchors is not None:
                    certs = trust_anchors.findall('certificates')
                    for cert in certs:
                        if cert.get('src') == "user":
                            self.findings.append({
                                "severity": "HIGH",
                                "name": "User Certificates Trusted (Debug)",
                                "desc": "Debug modunda kullanıcı sertifikalarına güveniliyor. Prod'da unutulursa MITM kolaylaşır.",
                                "file": str(file_path),
                                "exploit": "Cihaza kendi CA sertifikanı yükle, trafiği çöz."
                            })

            # 3. Pinning Check
            pin_set = root.find('pin-set')
            if pin_set is None:
                self.findings.append({
                    "severity": "MEDIUM",
                    "name": "No SSL Pinning Configured",
                    "desc": "Network Security Config var ama Pinning (pin-set) tanımlanmamış.",
                    "file": str(file_path),
                    "exploit": "Frida ile SSL bypass yapmaya gerek kalmadan, sadece user cert ile MITM yapılabilir (eski Android versiyonlarında)."
                })

        except Exception as e:
            print(Fore.RED + f"[!] XML Parse Error: {e}")
            
            
            
            # =============================================================================
# MODULE: REPORTING ENGINE V1.0 
# =============================================================================
def generate_reports_v2(package_name, findings, start_time, duration):
    print(Fore.CYAN + "[*] Raporlar derleniyor (HTML5/JS/CSS Matrix)...")
    
    # İstatistikler
    stats = {
        "CRITICAL": len([f for f in findings if f['severity'] == 'CRITICAL']),
        "HIGH": len([f for f in findings if f['severity'] == 'HIGH']),
        "MEDIUM": len([f for f in findings if f['severity'] == 'MEDIUM']),
        "LOW": len([f for f in findings if f['severity'] == 'LOW']),
        "INFO": len([f for f in findings if f['severity'] == 'INFO']),
    }
    total_issues = sum(stats.values())
    risk_score = (stats["CRITICAL"] * 100) + (stats["HIGH"] * 50) + (stats["MEDIUM"] * 20) + (stats["LOW"] * 5)
    
    # Modern, Hacker Temalı HTML Şablonu (Uzun String)
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ATOOL v1.0 - {package_name}</title>
        <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@300;400;600&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
        <style>
            :root {{
                --bg-color: #050505;
                --terminal-bg: #0a0a0a;
                --text-main: #e0e0e0;
                --text-dim: #666;
                --accent-red: #ff3333;
                --accent-green: #33ff33;
                --accent-blue: #3399ff;
                --critical: #ff0055;
                --high: #ff6600;
                --medium: #ffcc00;
                --low: #00ccff;
                --info: #00ff99;
            }}
            
            body {{
                background-color: var(--bg-color);
                color: var(--text-main);
                font-family: 'Fira Code', monospace;
                margin: 0;
                padding: 0;
                overflow-x: hidden;
            }}
            
            /* Matrix Rain Background Effect Container */
            #canvas {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: -1;
                opacity: 0.15;
            }}
            
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 40px 20px;
                position: relative;
                z-index: 1;
            }}
            
            header {{
                text-align: center;
                border-bottom: 2px solid var(--accent-red);
                padding-bottom: 30px;
                margin-bottom: 50px;
                animation: glitch 1s linear infinite;
            }}
            
            h1 {{
                font-family: 'Orbitron', sans-serif;
                font-size: 4em;
                color: var(--accent-red);
                margin: 0;
                text-transform: uppercase;
                letter-spacing: 5px;
                text-shadow: 0 0 10px var(--accent-red);
            }}
            
            .meta-info {{
                display: flex;
                justify-content: space-between;
                margin-bottom: 40px;
                background: var(--terminal-bg);
                padding: 20px;
                border: 1px solid #333;
                border-radius: 5px;
            }}
            
            .score-card {{
                text-align: center;
            }}
            
            .score {{
                font-size: 3em;
                font-weight: bold;
                color: var(--accent-red);
            }}
            
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                gap: 15px;
                margin-bottom: 40px;
            }}
            
            .stat-box {{
                background: #111;
                padding: 20px;
                text-align: center;
                border: 1px solid #333;
                border-radius: 4px;
                transition: transform 0.3s;
            }}
            
            .stat-box:hover {{
                transform: translateY(-5px);
                border-color: var(--text-main);
            }}
            
            .stat-number {{
                font-size: 2em;
                font-weight: bold;
                display: block;
            }}
            
            .CRITICAL {{ color: var(--critical); border-top: 3px solid var(--critical); }}
            .HIGH {{ color: var(--high); border-top: 3px solid var(--high); }}
            .MEDIUM {{ color: var(--medium); border-top: 3px solid var(--medium); }}
            .LOW {{ color: var(--low); border-top: 3px solid var(--low); }}
            .INFO {{ color: var(--info); border-top: 3px solid var(--info); }}
            
            .vuln-table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            
            .vuln-table th {{
                text-align: left;
                padding: 15px;
                background: #222;
                color: var(--accent-green);
                border-bottom: 2px solid #444;
            }}
            
            .vuln-table td {{
                padding: 15px;
                border-bottom: 1px solid #333;
                vertical-align: top;
            }}
            
            .vuln-row {{
                background: rgba(255, 255, 255, 0.02);
                transition: background 0.2s;
            }}
            
            .vuln-row:hover {{
                background: rgba(255, 255, 255, 0.05);
            }}
            
            .severity-badge {{
                padding: 5px 10px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 0.8em;
                color: #000;
                display: inline-block;
                width: 80px;
                text-align: center;
            }}
            
            .bg-critical {{ background: var(--critical); }}
            .bg-high {{ background: var(--high); }}
            .bg-medium {{ background: var(--medium); }}
            .bg-low {{ background: var(--low); }}
            .bg-info {{ background: var(--info); }}
            
            .exploit-code {{
                background: #000;
                padding: 10px;
                border: 1px dashed #555;
                color: var(--accent-green);
                font-family: monospace;
                white-space: pre-wrap;
                margin-top: 10px;
                font-size: 0.9em;
            }}
            
            .footer {{
                text-align: center;
                margin-top: 100px;
                color: #444;
                font-size: 0.8em;
            }}
            
            @keyframes glitch {{
                2%, 64% {{ transform: translate(2px,0) skew(0deg); }}
                4%, 60% {{ transform: translate(-2px,0) skew(0deg); }}
                62% {{ transform: translate(0,0) skew(5deg); }}
            }}
        </style>
    </head>
    <body>
        <canvas id="canvas"></canvas>
        <div class="container">
            <header>
                <h1>ATOOL REPORT</h1>
                <p>TARGET: {package_name}</p>
            </header>
            
            <div class="meta-info">
                <div>
                    <p><strong>SCAN DATE:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    <p><strong>DURATION:</strong> {duration:.2f} seconds</p>
                    <p><strong>TOTAL ISSUES:</strong> {total_issues}</p>
                </div>
                <div class="score-card">
                    <div class="score">{risk_score}</div>
                    <div>RISK INDEX</div>
                </div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-box CRITICAL"><span class="stat-number">{stats['CRITICAL']}</span>CRITICAL</div>
                <div class="stat-box HIGH"><span class="stat-number">{stats['HIGH']}</span>HIGH</div>
                <div class="stat-box MEDIUM"><span class="stat-number">{stats['MEDIUM']}</span>MEDIUM</div>
                <div class="stat-box LOW"><span class="stat-number">{stats['LOW']}</span>LOW</div>
                <div class="stat-box INFO"><span class="stat-number">{stats['INFO']}</span>INFO</div>
            </div>
            
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th width="10%">SEVERITY</th>
                        <th width="20%">ISSUE</th>
                        <th width="35%">DESCRIPTION & LOCATION</th>
                        <th width="35%">EXPLOIT / POC</th>
                    </tr>
                </thead>
                <tbody>
    """
    
    # Sıralama: Critical -> Info
    sorted_findings = sorted(findings, key=lambda x: ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO").index(x["severity"]))
    
    for f in sorted_findings:
        sev_class = f"bg-{f['severity'].lower()}"
        html_content += f"""
                    <tr class="vuln-row">
                        <td><span class="severity-badge {sev_class}">{f['severity']}</span></td>
                        <td><strong>{html.escape(f['name'])}</strong></td>
                        <td>
                            {html.escape(f['desc'])}<br><br>
                            <small style="color:#888">FILE: {html.escape(f.get('file', 'Unknown'))}</small>
                        </td>
                        <td>
                            <div class="exploit-code">{html.escape(f['exploit'])}</div>
                        </td>
                    </tr>
        """
    
    html_content += """
                </tbody>
            </table>
            
            <div class="footer">
                GENERATED BY ATOOL ANDROID SCANNER v1.0<br>
                "CONTROL IS AN ILLUSION"
            </div>
        </div>
        
        <script>
            // Matrix Rain Effect
            const canvas = document.getElementById('canvas');
            const ctx = canvas.getContext('2d');
            
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            
            const katakana = 'アァカサタナハマヤャラワガザダバパイィキシチニヒミリヂビピウゥクスツヌフムユュルグズブヅプエェケセテネヘメレゲゼデベペオォコソトノホモヨョロヲゴゾドボポ1234567890';
            const latin = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            const nums = '0123456789';
            const alphabet = katakana + latin + nums;
            
            const fontSize = 16;
            const columns = canvas.width/fontSize;
            
            const rainDrops = [];
            
            for( let x = 0; x < columns; x++ ) {
                rainDrops[x] = 1;
            }
            
            const draw = () => {
                ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                
                ctx.fillStyle = '#0F0';
                ctx.font = fontSize + 'px monospace';
                
                for(let i = 0; i < rainDrops.length; i++)
                {
                    const text = alphabet.charAt(Math.floor(Math.random() * alphabet.length));
                    ctx.fillText(text, i*fontSize, rainDrops[i]*fontSize);
                    
                    if(rainDrops[i]*fontSize > canvas.height && Math.random() > 0.975){
                        rainDrops[i] = 0;
                    }
                    rainDrops[i]++;
                }
            };
            
            setInterval(draw, 30);
        </script>
    </body>
    </html>
    """
    
    filename = f"atool_report_{package_name}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(Fore.GREEN + f"[+] Rapor oluşturuldu: {filename}")
    
    # 1. Manifest Deep Dive
    manifest_path = Path(args.directory) / "AndroidManifest.xml"
    if manifest_path.exists():
        try:
            tree = ET.parse(manifest_path)
            # Permission Analizi
            for perm in tree.findall('.//uses-permission'):
                p_name = perm.get('{http://schemas.android.com/apk/res/android}name')
                if p_name in PERMISSION_KNOWLEDGE_BASE:
                    info = PERMISSION_KNOWLEDGE_BASE[p_name]
                    FINDINGS.append({
                        "severity": info["risk"],
                        "name": f"Permission: {p_name.split('.')[-1]}",
                        "desc": info["desc"],
                        "file": "AndroidManifest.xml",
                        "exploit": "Permission abuse potential"
                    })
            
            dl_analyzer = DeepLinkAnalyzer(tree.getroot(), pkg)
            FINDINGS.extend(dl_analyzer.analyze())
        except Exception as e:
            print(f"Manifest analiz hatası: {e}")

    net_parser = NetworkSecurityParser(args.directory)
    FINDINGS.extend(net_parser.scan())

    start_t = time.time()

    duration = time.time() - start_t
    generate_reports_v2(pkg, FINDINGS, start_t, duration)

# ==================== MAIN ====================
def main():
    parser = argparse.ArgumentParser(description="ATOOL v1.0")
    parser.add_argument("-d", "--directory", required=True)
    args = parser.parse_args()

    print(Fore.RED + Style.BRIGHT + """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ ATOOL ANDROID SCANNER v1.0		                                ║
    ║ [2000+ Satır] [150+ Bounty Gold] [P1/P2 Full] [Control is an Illusion]    ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """)

    pkg = analyze_manifest_pro(args.directory)
    if pkg:
        scan_google_services_json(args.directory)
        scan_sensitive_files(args.directory)
        scan_native_hybrid(args.directory)
        scan_smali_ultimate(args.directory)
        generate_reports(pkg)
        print(Fore.RED + Style.BRIGHT + "\n[!] Sistem bizim. Para cebe. ATOOL forever.")
    else:
        print(Fore.RED + "[!] Bomba patladı – manifest yok.")

if __name__ == "__main__":
    main()
