#!/usr/bin/env python3
"""
APK Secret Scanner — Post-Decompilation Secret Discovery
Run after FullAPKDecompiler to find secrets in decompiled output.

Usage: python secret_scanner.py <decompiled_dir> [--output report.md]

Scans:
  - Java source (jadx output)
  - Smali (apktool output)
  - Resources (strings.xml, configs)
  - Assets (JS bundles, configs, certs)
  - AndroidManifest.xml
"""

import argparse
import json
import os
import re
import sys
import base64
from collections import defaultdict
from pathlib import Path

# ============================================================
# SECRET PATTERNS — Add new patterns here
# ============================================================

# Format: (name, regex_pattern, severity, description)
# Severity: CRITICAL, HIGH, MEDIUM, LOW, INFO

SECRET_PATTERNS = [
    # === CLOUD PROVIDER KEYS ===
    ("AWS Access Key ID", r'AKIA[0-9A-Z]{16}', "CRITICAL", "AWS IAM access key"),
    ("AWS Secret Access Key", r'(?:aws_secret_access_key|secret_key|aws_secret)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']', "CRITICAL", "AWS secret key"),
    ("AWS Session Token", r'ASIA[0-9A-Z]{16}', "HIGH", "AWS temporary session key"),
    ("AWS ARN", r'arn:aws:[a-zA-Z0-9\-]+:[a-zA-Z0-9\-]*:\d{12}:[a-zA-Z0-9\-_/:.]+', "MEDIUM", "AWS resource identifier"),
    ("AWS S3 Bucket URL", r'https?://[a-zA-Z0-9._-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*', "MEDIUM", "S3 bucket URL"),
    ("AWS S3 Bucket (path style)", r'https?://s3[a-zA-Z0-9.-]*\.amazonaws\.com/[a-zA-Z0-9._-]+', "MEDIUM", "S3 bucket path-style URL"),
    ("Google Cloud API Key", r'AIza[0-9A-Za-z_-]{35}', "MEDIUM", "Google API key"),
    ("Google OAuth Client ID", r'\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com', "LOW", "Google OAuth client"),
    ("Google Cloud Service Account", r'[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.iam\.gserviceaccount\.com', "HIGH", "GCP service account"),
    ("Azure Storage Key", r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};', "CRITICAL", "Azure storage connection string"),
    ("Azure SAS Token", r'[?&]sig=[A-Za-z0-9%+/=]{40,}', "HIGH", "Azure shared access signature"),

    # === API KEYS & TOKENS ===
    ("Generic API Key (long)", r'(?:api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "HIGH", "Generic API key"),
    ("Generic Secret Key", r'(?:secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-/+=]{16,})["\']', "HIGH", "Generic secret key"),
    ("Generic Access Token", r'(?:access[_-]?token|auth[_-]?token|bearer[_-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-/.+=]{20,})["\']', "HIGH", "Generic access token"),
    ("Generic Password", r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^\s"\']{8,})["\']', "HIGH", "Hardcoded password"),
    ("Bearer Token", r'[Bb]earer\s+[a-zA-Z0-9_\-/.+=]{20,}', "HIGH", "Bearer auth token"),
    ("Basic Auth Header", r'Basic\s+[A-Za-z0-9+/=]{20,}', "HIGH", "Basic auth credentials (base64)"),
    ("Authorization Header", r'["\']Authorization["\']\s*[:=]\s*["\']([^"\']{10,})["\']', "HIGH", "Hardcoded auth header"),

    # === PAYMENT / FINANCIAL ===
    ("Stripe Secret Key", r'sk_live_[a-zA-Z0-9]{20,}', "CRITICAL", "Stripe secret key (LIVE)"),
    ("Stripe Test Secret", r'sk_test_[a-zA-Z0-9]{20,}', "HIGH", "Stripe secret key (TEST)"),
    ("Stripe Publishable (Live)", r'pk_live_[a-zA-Z0-9]{20,}', "LOW", "Stripe publishable key"),
    ("Stripe Webhook Secret", r'whsec_[a-zA-Z0-9]{20,}', "CRITICAL", "Stripe webhook signing secret"),
    ("Stripe Restricted Key", r'rk_live_[a-zA-Z0-9]{20,}', "HIGH", "Stripe restricted key"),
    ("Square Access Token", r'sq0[a-z]{3}-[a-zA-Z0-9_-]{22,}', "HIGH", "Square API token"),
    ("PayPal Braintree Token", r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}', "CRITICAL", "Braintree production token"),

    # === SOCIAL / COMMUNICATION ===
    ("Slack Webhook", r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{20,}', "HIGH", "Slack incoming webhook URL"),
    ("Slack Bot Token", r'xoxb-[0-9]{10,13}-[a-zA-Z0-9-]+', "CRITICAL", "Slack bot token"),
    ("Slack User Token", r'xoxp-[0-9]{10,13}-[a-zA-Z0-9-]+', "CRITICAL", "Slack user token"),
    ("Slack App Token", r'xapp-[0-9]-[A-Z0-9]{10,}-[a-zA-Z0-9-]+', "HIGH", "Slack app-level token"),
    ("Discord Webhook", r'https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+', "HIGH", "Discord webhook URL"),
    ("Discord Bot Token", r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}', "HIGH", "Discord bot token"),
    ("Telegram Bot Token", r'\d{8,10}:[A-Za-z0-9_-]{35}', "HIGH", "Telegram bot API token"),
    ("Twilio Account SID", r'AC[a-f0-9]{32}', "MEDIUM", "Twilio account SID"),
    ("Twilio Auth Token", r'(?:twilio[_-]?auth[_-]?token|TWILIO_AUTH)\s*[:=]\s*["\']([a-f0-9]{32})["\']', "HIGH", "Twilio auth token"),

    # === SCM / CI-CD ===
    ("GitHub Personal Access Token", r'ghp_[a-zA-Z0-9]{36}', "CRITICAL", "GitHub PAT"),
    ("GitHub OAuth Token", r'gho_[a-zA-Z0-9]{36}', "CRITICAL", "GitHub OAuth token"),
    ("GitHub App Token", r'ghu_[a-zA-Z0-9]{36}', "HIGH", "GitHub user-to-server token"),
    ("GitHub Fine-grained PAT", r'github_pat_[a-zA-Z0-9_]{22,}', "CRITICAL", "GitHub fine-grained PAT"),
    ("GitLab Token", r'glpat-[a-zA-Z0-9_-]{20,}', "CRITICAL", "GitLab personal access token"),
    ("Bitbucket App Password", r'(?:bitbucket[_-]?password|BB_AUTH)\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']', "HIGH", "Bitbucket app password"),
    ("CircleCI Token", r'circle-token\s*[:=]\s*["\']([a-f0-9]{40})["\']', "HIGH", "CircleCI API token"),

    # === EMAIL / MESSAGING ===
    ("SendGrid API Key", r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', "CRITICAL", "SendGrid API key"),
    ("Mailgun API Key", r'key-[a-f0-9]{32}', "HIGH", "Mailgun API key"),
    ("Mailchimp API Key", r'[a-f0-9]{32}-us\d{1,2}', "HIGH", "Mailchimp API key"),

    # === AI / ML ===
    ("OpenAI API Key", r'sk-[a-zA-Z0-9]{20,}', "CRITICAL", "OpenAI secret key"),
    ("OpenAI Project Key", r'sk-proj-[a-zA-Z0-9_-]{20,}', "CRITICAL", "OpenAI project key"),
    ("Anthropic API Key", r'sk-ant-[a-zA-Z0-9_-]{20,}', "CRITICAL", "Anthropic API key"),
    ("HuggingFace Token", r'hf_[a-zA-Z0-9]{34}', "HIGH", "HuggingFace API token"),

    # === MONITORING / ANALYTICS ===
    ("Sentry DSN", r'https://[a-f0-9]{32}@[a-z0-9.]+sentry[a-z.]*/\d+', "MEDIUM", "Sentry error tracking DSN"),
    ("Datadog API Key", r'(?:datadog[_-]?api[_-]?key|DD_API_KEY)\s*[:=]\s*["\']([a-f0-9]{32})["\']', "HIGH", "Datadog API key"),
    ("New Relic License Key", r'[a-f0-9]{40}NRAL', "HIGH", "New Relic license key"),
    ("Amplitude API Key", r'(?:amplitude[_-]?api[_-]?key|AMPLITUDE_KEY)\s*[:=]\s*["\']([a-f0-9]{32})["\']', "LOW", "Amplitude analytics key"),
    ("Mixpanel Token", r'(?:mixpanel[_-]?token|MIXPANEL)\s*[:=]\s*["\']([a-f0-9]{32})["\']', "LOW", "Mixpanel project token"),
    ("Segment Write Key", r'(?:segment[_-]?write[_-]?key|SEGMENT_KEY)\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']', "MEDIUM", "Segment analytics key"),

    # === CRYPTO / BLOCKCHAIN ===
    ("Ethereum Private Key", r'(?:0x)?[a-fA-F0-9]{64}', "INFO", "Possible ETH private key (verify context)"),
    ("Mnemonic Seed Phrase", r'(?:mnemonic|seed[_-]?phrase|recovery[_-]?phrase)\s*[:=]\s*["\']([a-z\s]{20,})["\']', "CRITICAL", "Wallet seed phrase"),
    ("Alchemy API Key (in URL)", r'https://[a-z0-9-]+\.g\.alchemy\.com/v2/[a-zA-Z0-9_-]{20,}', "LOW", "Alchemy RPC endpoint with key"),
    ("Infura Project ID (in URL)", r'https://[a-z]+\.infura\.io/v3/[a-f0-9]{32}', "LOW", "Infura RPC endpoint with project ID"),
    ("QuikNode Endpoint", r'https://[a-z0-9-]+\.quiknode\.pro/[a-f0-9]{40,}', "LOW", "QuikNode RPC with auth token"),

    # === CERTIFICATES & PRIVATE KEYS ===
    ("RSA Private Key", r'-----BEGIN RSA PRIVATE KEY-----', "CRITICAL", "RSA private key"),
    ("EC Private Key", r'-----BEGIN EC PRIVATE KEY-----', "CRITICAL", "EC private key"),
    ("DSA Private Key", r'-----BEGIN DSA PRIVATE KEY-----', "CRITICAL", "DSA private key"),
    ("OpenSSH Private Key", r'-----BEGIN OPENSSH PRIVATE KEY-----', "CRITICAL", "OpenSSH private key"),
    ("PGP Private Key", r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "CRITICAL", "PGP private key"),
    ("PKCS8 Private Key", r'-----BEGIN PRIVATE KEY-----', "CRITICAL", "PKCS8 private key"),
    ("Certificate", r'-----BEGIN CERTIFICATE-----', "INFO", "X.509 certificate (check if CA or server cert)"),

    # === JWT ===
    ("JSON Web Token", r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+', "HIGH", "JWT token (decode to check contents)"),

    # === FIREBASE ===
    ("Firebase Database URL", r'https://[a-zA-Z0-9_-]+\.firebaseio\.com', "MEDIUM", "Firebase Realtime DB (test for open rules)"),
    ("Firebase Storage Bucket", r'[a-zA-Z0-9_-]+\.appspot\.com', "LOW", "Firebase/GCS storage bucket"),
    ("Firebase Cloud Messaging Key", r'(?:server_key|FCM_KEY|fcm_server_key)\s*[:=]\s*["\']([A-Za-z0-9_:=-]{100,})["\']', "HIGH", "FCM server key (can send push to any device)"),

    # === INTERNAL INFRASTRUCTURE ===
    ("Internal URL (staging/dev/test)", r'https?://[a-zA-Z0-9._-]*(?:staging|internal|\.dev\.|sandbox|\.qa\.|\.uat\.|preprod|nonprod|\.beta\.|\.alpha\.|\.debug\.)[a-zA-Z0-9._-]*\.[a-zA-Z]{2,}[^\s"\'<>]*', "MEDIUM", "Internal/staging URL"),
    ("Localhost URL", r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?[^\s"\'<>]*', "LOW", "Localhost reference in production"),
    ("IP Address (private)", r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', "LOW", "Private IP address"),
    ("Mock API URL", r'https?://[a-zA-Z0-9._-]*(?:mockapi|beeceptor|requestbin|webhook\.site|ngrok|localtunnel|pipedream)[a-zA-Z0-9._-]*\.[a-zA-Z]+[^\s"\'<>]*', "MEDIUM", "Mock/debug API endpoint in production"),

    # === DATABASE ===
    ("Database Connection String", r'(?:mongodb|postgres|mysql|redis|amqp|mssql)(?:\+[a-z]+)?://[^\s"\'<>]{10,}', "CRITICAL", "Database connection string with credentials"),
    ("JDBC Connection", r'jdbc:[a-z]+://[^\s"\'<>]{10,}', "HIGH", "JDBC connection string"),

    # === MOBILE SPECIFIC ===
    ("Android Keystore Password", r'(?:keystore[_-]?password|storePassword|KEYSTORE_PASS)\s*[:=]\s*["\']([^\s"\']{4,})["\']', "HIGH", "Android keystore password"),
    ("Signing Config", r'(?:signingConfigs|key\.alias|key\.password)\s*[:=]\s*["\']([^\s"\']{4,})["\']', "HIGH", "Android signing configuration"),
    ("UAT/Test Token", r'(?:UAT[_-]?TOKEN|TEST[_-]?TOKEN|STAGING[_-]?TOKEN|DEV[_-]?TOKEN)\s*[:=]\s*["\']([^\s"\']{8,})["\']', "HIGH", "UAT/test token in production build"),

    # === OAUTH / SSO ===
    ("OAuth Client Secret", r'(?:client[_-]?secret|consumer[_-]?secret|oauth[_-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "HIGH", "OAuth client secret"),
    ("SAML Certificate", r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\n\r]+-----END CERTIFICATE-----', "MEDIUM", "SAML/SSO certificate"),

    # === ENCRYPTION ===
    ("Hardcoded AES Key", r'(?:aes[_-]?key|encryption[_-]?key|cipher[_-]?key|SECRET_KEY|ENCRYPTION_KEY)\s*[:=]\s*["\']([a-zA-Z0-9+/=_-]{16,})["\']', "HIGH", "Hardcoded encryption key"),
    ("Hardcoded IV", r'(?:iv|initialization[_-]?vector|INIT_VECTOR)\s*[:=]\s*["\']([a-fA-F0-9]{16,})["\']', "MEDIUM", "Hardcoded initialization vector"),
    ("HMAC Secret", r'(?:hmac[_-]?secret|HMAC_KEY|signing[_-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9+/=_-]{16,})["\']', "HIGH", "HMAC signing secret"),
]

# ============================================================
# FILE PATTERNS — Interesting files to flag
# ============================================================

INTERESTING_FILES = [
    (r'\.pem$', "MEDIUM", "PEM certificate/key file"),
    (r'\.p12$|\.pfx$', "HIGH", "PKCS12 keystore"),
    (r'\.jks$|\.bks$', "HIGH", "Java/Bouncy Castle keystore"),
    (r'\.key$', "HIGH", "Private key file"),
    (r'\.env$|\.env\.\w+$', "CRITICAL", ".env config file"),
    (r'google-services\.json$', "MEDIUM", "Firebase config"),
    (r'GoogleService-Info\.plist$', "MEDIUM", "iOS Firebase config in Android app"),
    (r'\.sql$|\.sqlite$|\.db$', "MEDIUM", "Database file"),
    (r'\.secret$|secrets?\.\w+$', "HIGH", "Secrets file"),
    (r'config\.json$|config\.ya?ml$|config\.xml$', "MEDIUM", "Configuration file"),
    (r'credentials\.\w+$', "HIGH", "Credentials file"),
    (r'\.cer$|\.crt$|\.der$', "LOW", "Certificate file"),
    (r'backup_rules\.xml$|network_security_config\.xml$', "INFO", "Android security config"),
]

# ============================================================
# MANIFEST CHECKS
# ============================================================

MANIFEST_CHECKS = [
    ("debuggable", r'android:debuggable="true"', "HIGH", "App is debuggable"),
    ("allowBackup", r'android:allowBackup="true"', "MEDIUM", "Backup enabled"),
    ("usesCleartextTraffic", r'android:usesCleartextTraffic="true"', "MEDIUM", "Cleartext HTTP allowed"),
    ("exported_activity", r'android:exported="true"', "INFO", "Exported component (count)"),
    ("custom_scheme", r'android:scheme="(?!https?|content|file|android)([^"]+)"', "INFO", "Custom URL scheme"),
    ("network_security_config", r'android:networkSecurityConfig', "INFO", "Has network security config"),
]


class SecretScanner:
    def __init__(self, decompiled_dir, verbose=False):
        self.root = Path(decompiled_dir)
        self.verbose = verbose
        self.findings = []
        self.file_findings = []
        self.manifest_findings = []
        self.stats = defaultdict(int)

    def scan(self):
        """Run all scans."""
        print(f"[*] Scanning: {self.root}")
        print(f"[*] Finding source files...")

        # Find all scannable files
        source_files = []
        for ext in ['*.java', '*.smali', '*.xml', '*.json', '*.properties',
                     '*.yml', '*.yaml', '*.cfg', '*.ini', '*.conf', '*.txt',
                     '*.js', '*.jsx', '*.ts', '*.bundle', '*.html', '*.htm']:
            source_files.extend(self.root.rglob(ext))

        print(f"[*] Found {len(source_files)} files to scan")

        # Scan for secrets in source
        for i, fpath in enumerate(source_files):
            if i > 0 and i % 500 == 0:
                print(f"  Progress: {i}/{len(source_files)} files...")
            self._scan_file(fpath)

        # Scan for interesting files
        self._scan_interesting_files()

        # Scan manifest
        self._scan_manifest()

        # Scan strings.xml
        self._scan_strings_xml()

        # Scan BuildConfig
        self._scan_buildconfig()

        # Scan assets for configs
        self._scan_assets()

        # Decode and scan Base64 in strings.xml
        self._scan_base64_strings()

        print(f"\n[*] Scan complete!")
        print(f"  Secrets found: {len(self.findings)}")
        print(f"  Interesting files: {len(self.file_findings)}")
        print(f"  Manifest issues: {len(self.manifest_findings)}")

        by_severity = defaultdict(int)
        for f in self.findings:
            by_severity[f['severity']] += 1
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if by_severity[sev]:
                print(f"  {sev}: {by_severity[sev]}")

    def _scan_file(self, fpath):
        """Scan a single file for secret patterns."""
        try:
            # Skip very large files (>5MB) and binary files
            if fpath.stat().st_size > 5_000_000:
                # For large files (JS bundles), scan in chunks
                self._scan_large_file(fpath)
                return

            content = fpath.read_text(encoding='utf-8', errors='ignore')

            for name, pattern, severity, desc in SECRET_PATTERNS:
                matches = re.finditer(pattern, content)
                for match in matches:
                    value = match.group(0)[:200]  # Truncate long matches
                    line_num = content[:match.start()].count('\n') + 1

                    # Skip false positives
                    if self._is_false_positive(name, value, content, match.start()):
                        continue

                    self.findings.append({
                        'name': name,
                        'severity': severity,
                        'description': desc,
                        'value': value,
                        'file': str(fpath.relative_to(self.root)),
                        'line': line_num,
                    })
                    self.stats[name] += 1

        except Exception as e:
            if self.verbose:
                print(f"  Error scanning {fpath}: {e}")

    def _scan_large_file(self, fpath):
        """Scan large files in chunks."""
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                chunk_size = 1_000_000
                overlap = 1000
                chunk_num = 0
                prev_tail = ""

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    search_text = prev_tail + chunk
                    chunk_num += 1

                    for name, pattern, severity, desc in SECRET_PATTERNS:
                        # Only check high-value patterns in large files
                        if severity in ('CRITICAL', 'HIGH'):
                            for match in re.finditer(pattern, search_text):
                                value = match.group(0)[:200]
                                if not self._is_false_positive(name, value, search_text, match.start()):
                                    self.findings.append({
                                        'name': name,
                                        'severity': severity,
                                        'description': desc,
                                        'value': value,
                                        'file': str(fpath.relative_to(self.root)),
                                        'line': f"chunk_{chunk_num}",
                                    })
                                    self.stats[name] += 1

                    prev_tail = chunk[-overlap:] if len(chunk) >= overlap else chunk

        except Exception as e:
            if self.verbose:
                print(f"  Error scanning large file {fpath}: {e}")

    def _is_false_positive(self, name, value, content, pos):
        """Filter out common false positives."""
        val_lower = value.lower()

        # Skip placeholder/example values
        placeholders = ['example', 'placeholder', 'your_', 'xxx', 'todo', 'fixme',
                       'insert_', 'replace_', 'change_me', 'dummy', 'sample',
                       'test1234', 'password123', '${', 'process.env']
        if any(p in val_lower for p in placeholders):
            return True

        # Skip values that are just code constructs
        if name == "Generic Password":
            code_patterns = ['getPassword', 'setPassword', 'password()', 'passwordField',
                           'password_hint', 'password_toggle', 'forgot_password',
                           'reset_password', 'change_password', 'confirm_password',
                           'new_password', 'old_password', 'PASSWORD_',
                           'password":', 'passwordError', 'invalidPassword']
            if any(p in content[max(0, pos-100):pos+100] for p in code_patterns):
                return True

        # Skip Ethereum addresses (not private keys) — they start with 0x and are 42 chars
        if name == "Ethereum Private Key":
            if value.startswith('0x') and len(value) == 42:
                return True
            # Must be in a context suggesting it's a key, not a hash or address
            context = content[max(0, pos-200):pos+200].lower()
            if not any(kw in context for kw in ['private', 'secret', 'key', 'sign', 'wallet']):
                return True

        # Skip known library hashes
        if name == "Generic API Key (long)" or name == "Generic Secret Key":
            # Verify it's actually an assignment, not just a string
            context = content[max(0, pos-50):pos].lower()
            if not any(kw in context for kw in ['key', 'secret', 'token', 'api', 'auth', 'password', 'credential']):
                return True

        # Skip Sentry DSNs that are just public keys (client-side by design)
        # Still report but context matters

        # Skip Google API keys in standard Firebase config (client-side)
        # Still report but at appropriate severity

        return False

    def _scan_interesting_files(self):
        """Find interesting files by extension/name."""
        for fpath in self.root.rglob('*'):
            if fpath.is_file():
                fname = fpath.name
                for pattern, severity, desc in INTERESTING_FILES:
                    if re.search(pattern, fname, re.IGNORECASE):
                        self.file_findings.append({
                            'severity': severity,
                            'description': desc,
                            'file': str(fpath.relative_to(self.root)),
                            'size': fpath.stat().st_size,
                        })

    def _scan_manifest(self):
        """Scan AndroidManifest.xml for security issues."""
        manifest = self.root / 'apktool' / 'main' / 'AndroidManifest.xml'
        if not manifest.exists():
            # Try alternate paths
            for p in self.root.rglob('AndroidManifest.xml'):
                manifest = p
                break

        if not manifest.exists():
            return

        content = manifest.read_text(encoding='utf-8', errors='ignore')

        for name, pattern, severity, desc in MANIFEST_CHECKS:
            matches = re.findall(pattern, content)
            if matches:
                if name == "exported_activity":
                    count = len(matches)
                    self.manifest_findings.append({
                        'name': name,
                        'severity': severity,
                        'description': f"{desc}: {count} exported components",
                        'file': str(manifest.relative_to(self.root)),
                    })
                elif name == "custom_scheme":
                    for m in matches:
                        self.manifest_findings.append({
                            'name': name,
                            'severity': severity,
                            'description': f"Custom URL scheme: {m}",
                            'file': str(manifest.relative_to(self.root)),
                        })
                elif name == "network_security_config":
                    self.manifest_findings.append({
                        'name': name,
                        'severity': 'INFO',
                        'description': "Has network security config (good)",
                        'file': str(manifest.relative_to(self.root)),
                    })
                else:
                    self.manifest_findings.append({
                        'name': name,
                        'severity': severity,
                        'description': desc,
                        'file': str(manifest.relative_to(self.root)),
                    })

        # Check for missing network_security_config
        if 'networkSecurityConfig' not in content:
            self.manifest_findings.append({
                'name': 'missing_network_security_config',
                'severity': 'MEDIUM',
                'description': 'No network_security_config.xml — no certificate pinning at manifest level',
                'file': str(manifest.relative_to(self.root)),
            })

    def _scan_strings_xml(self):
        """Scan res/values/strings.xml for secrets."""
        for strings_xml in self.root.rglob('strings.xml'):
            if 'res' in str(strings_xml) and 'values' in str(strings_xml):
                try:
                    content = strings_xml.read_text(encoding='utf-8', errors='ignore')
                    # Extract key-value pairs
                    for match in re.finditer(r'<string name="([^"]+)"[^>]*>([^<]+)</string>', content):
                        key, value = match.group(1), match.group(2)
                        key_lower = key.lower()

                        # Flag interesting keys — require exact key patterns, not substrings
                        sensitive_exact = ['api_key', 'api_secret', 'secret_key', 'client_secret',
                                         'client_id', 'access_token', 'auth_token', 'bearer_token',
                                         'database_url', 'storage_bucket', 'sender_id',
                                         'app_id', 'project_id', 'web_client_id', 'server_key',
                                         'firebase_database_url', 'google_api_key', 'google_app_id',
                                         'google_crash_reporting_api_key', 'default_web_client_id',
                                         'gcm_defaultsenderid']
                        # Skip UI text strings
                        skip_values = ['Authenticate', 'Connect wallet', 'Continue', 'Sign message',
                                      'Authentication failed', 'Authentication was successful',
                                      'Show password', 'Token ID', 'Token standard', 'Unknown',
                                      'Zetetic']
                        if any(sv.lower() in value.lower() for sv in skip_values):
                            continue
                        # Skip SVG path data
                        if value.startswith('M') and ('L' in value or 'Z' in value) and ',' in value:
                            continue
                        for sk in sensitive_exact:
                            if sk == key_lower and len(value) > 5 and value not in ('true', 'false'):
                                self.findings.append({
                                    'name': f"strings.xml: {key}",
                                    'severity': 'MEDIUM',
                                    'description': f"Sensitive value in strings.xml",
                                    'value': value[:200],
                                    'file': str(strings_xml.relative_to(self.root)),
                                    'line': content[:match.start()].count('\n') + 1,
                                })
                                break
                except Exception:
                    pass

    def _scan_buildconfig(self):
        """Scan BuildConfig.java for hardcoded values."""
        for bc in self.root.rglob('BuildConfig.java'):
            try:
                content = bc.read_text(encoding='utf-8', errors='ignore')
                for match in re.finditer(r'(?:public\s+)?static\s+final\s+String\s+(\w+)\s*=\s*"([^"]+)"', content):
                    key, value = match.group(1), match.group(2)
                    key_lower = key.lower()
                    skip = ['application_id', 'build_type', 'flavor', 'version_name',
                           'version_code', 'library_package_name']
                    if any(s in key_lower for s in skip):
                        continue
                    if len(value) > 5:
                        severity = 'MEDIUM'
                        if any(s in key_lower for s in ['secret', 'token', 'password', 'key', 'auth']):
                            severity = 'HIGH'
                        if 'uat' in key_lower or 'test' in key_lower or 'staging' in key_lower:
                            severity = 'HIGH'
                        self.findings.append({
                            'name': f"BuildConfig: {key}",
                            'severity': severity,
                            'description': f"Hardcoded value in BuildConfig.java",
                            'value': value[:200],
                            'file': str(bc.relative_to(self.root)),
                            'line': content[:match.start()].count('\n') + 1,
                        })
            except Exception:
                pass

    def _scan_assets(self):
        """Scan assets directory for config files."""
        assets_dir = self.root / 'apktool' / 'main' / 'assets'
        if not assets_dir.exists():
            return

        for fpath in assets_dir.rglob('*'):
            if fpath.is_file():
                # Flag JSON config files
                if fpath.suffix in ('.json', '.cfg', '.ini', '.conf', '.properties', '.yaml', '.yml'):
                    try:
                        content = fpath.read_text(encoding='utf-8', errors='ignore')
                        if len(content) < 50000:  # Don't parse huge files
                            for name, pattern, severity, desc in SECRET_PATTERNS:
                                if severity in ('CRITICAL', 'HIGH', 'MEDIUM'):
                                    for match in re.finditer(pattern, content):
                                        value = match.group(0)[:200]
                                        if not self._is_false_positive(name, value, content, match.start()):
                                            self.findings.append({
                                                'name': f"Asset: {name}",
                                                'severity': severity,
                                                'description': f"{desc} (in asset file)",
                                                'value': value,
                                                'file': str(fpath.relative_to(self.root)),
                                                'line': content[:match.start()].count('\n') + 1,
                                            })
                    except Exception:
                        pass

    def _scan_base64_strings(self):
        """Look for Base64-encoded secrets in strings.xml."""
        for strings_xml in self.root.rglob('strings.xml'):
            if 'res' in str(strings_xml) and 'values' in str(strings_xml):
                try:
                    content = strings_xml.read_text(encoding='utf-8', errors='ignore')
                    for match in re.finditer(r'<string name="([^"]+)"[^>]*>([A-Za-z0-9+/=]{40,})</string>', content):
                        key, b64_value = match.group(1), match.group(2)
                        try:
                            decoded = base64.b64decode(b64_value).decode('utf-8', errors='ignore')
                            # Check if decoded value contains secrets
                            if any(kw in decoded.lower() for kw in ['http', 'api', 'key', 'secret', 'token', 'password', 'auth']):
                                self.findings.append({
                                    'name': f"Base64 Decoded ({key})",
                                    'severity': 'MEDIUM',
                                    'description': f"Base64-encoded value decoded to: {decoded[:100]}",
                                    'value': decoded[:200],
                                    'file': str(strings_xml.relative_to(self.root)),
                                    'line': content[:match.start()].count('\n') + 1,
                                })
                        except Exception:
                            pass
                except Exception:
                    pass

    def generate_report(self, output_path=None):
        """Generate markdown report."""
        lines = []
        lines.append("# APK Secret Scanner Report")
        lines.append(f"**Scanned:** `{self.root}`")
        lines.append(f"**Secrets Found:** {len(self.findings)}")
        lines.append(f"**Interesting Files:** {len(self.file_findings)}")
        lines.append(f"**Manifest Issues:** {len(self.manifest_findings)}")
        lines.append("")

        # Summary by severity
        by_sev = defaultdict(list)
        for f in self.findings:
            by_sev[f['severity']].append(f)

        lines.append("## Summary")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if by_sev[sev]:
                lines.append(f"| **{sev}** | {len(by_sev[sev])} |")
        lines.append("")

        # Findings by severity
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if by_sev[sev]:
                lines.append(f"## {sev} Findings")
                lines.append("")
                seen = set()
                for f in by_sev[sev]:
                    # Deduplicate by name+value
                    dedup_key = f"{f['name']}:{f['value'][:50]}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    lines.append(f"### {f['name']}")
                    lines.append(f"- **Description:** {f['description']}")
                    lines.append(f"- **File:** `{f['file']}` (line {f.get('line', '?')})")
                    lines.append(f"- **Value:** `{f['value']}`")
                    lines.append("")

        # Interesting files
        if self.file_findings:
            lines.append("## Interesting Files")
            lines.append("| Severity | Description | File | Size |")
            lines.append("|----------|-------------|------|------|")
            for f in sorted(self.file_findings, key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].index(x['severity'])):
                size_str = f"{f['size']:,}" if f['size'] < 1024 else f"{f['size']/1024:.1f}KB"
                lines.append(f"| {f['severity']} | {f['description']} | `{f['file']}` | {size_str} |")
            lines.append("")

        # Manifest findings
        if self.manifest_findings:
            lines.append("## Manifest Security")
            lines.append("| Severity | Finding | File |")
            lines.append("|----------|---------|------|")
            for f in self.manifest_findings:
                lines.append(f"| {f['severity']} | {f['description']} | `{f['file']}` |")
            lines.append("")

        report = "\n".join(lines)

        if output_path:
            Path(output_path).write_text(report, encoding='utf-8')
            print(f"[*] Report saved to: {output_path}")
        else:
            print(report)

        return report


def main():
    parser = argparse.ArgumentParser(description='APK Secret Scanner — Post-decompilation secret discovery')
    parser.add_argument('decompiled_dir', help='Path to decompiled APK directory')
    parser.add_argument('--output', '-o', help='Output report path (markdown)', default=None)
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if not os.path.isdir(args.decompiled_dir):
        print(f"Error: {args.decompiled_dir} is not a directory")
        sys.exit(1)

    scanner = SecretScanner(args.decompiled_dir, verbose=args.verbose)
    scanner.scan()

    # Auto-generate output path if not specified
    output = args.output
    if not output:
        output = os.path.join(args.decompiled_dir, 'secret_scan_report.md')

    scanner.generate_report(output)


if __name__ == '__main__':
    main()
