"""
Extract secrets, API keys, tokens, and internal endpoints from JavaScript/config files.
Findings are HIGH if secrets are found, MEDIUM for internal endpoints, INFO for config-only.
"""
import re
import httpx
from ai_recon.core.models import Finding, Technique, IntrusivenessLevel

SECRET_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9_-]{20,}"),  # OpenAI keys
    re.compile(r"mcp-tok-[a-zA-Z0-9_-]{10,}"),
    re.compile(r"api[_-]?key\s*[:=]\s*['\"]([a-zA-Z0-9-_=*]+)['\"]", re.I),
    re.compile(r"authToken\s*[:=]\s*['\"]([a-zA-Z0-9-_=*]+)['\"]", re.I),
    re.compile(r"bearer\s+[a-zA-Z0-9-_.=]+", re.I),
    re.compile(r"secret\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.I),
]

ENDPOINT_PATTERNS = [
    re.compile(r"endpoint\s*[:=]\s*['\"](/api/[a-zA-Z0-9_/-]+)['\"]"),
    re.compile(r"fetch\(['\"](/api/[a-zA-Z0-9_/-]+)['\"]"),
]

class JSSecretsExtract(Technique):
    id = "passive.js_secrets_extract"
    intrusiveness = IntrusivenessLevel.PASSIVE
    description = "Extract secrets, API keys, tokens, and internal endpoints from JavaScript/config files."
    references = [
        "https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/api-keys.txt",
        "https://github.com/projectdiscovery/nuclei-templates/blob/main/helpers/regexes.yaml"
    ]

    async def run(self, target, session, **kwargs):
        findings = []
        js_paths = [
            "/static/js/app.js",
            "/static/js/chat.js",
            "/config.json",
            "/api/config",
        ]
        for path in js_paths:
            url = target.url_for(path)
            try:
                resp = await session.get(url, timeout=8)
                if resp.status_code != 200 or not resp.text:
                    continue
                text = resp.text
                secrets = set()
                endpoints = set()
                for pat in SECRET_PATTERNS:
                    for m in pat.findall(text):
                        secrets.add(m if isinstance(m, str) else m[0])
                for pat in ENDPOINT_PATTERNS:
                    for m in pat.findall(text):
                        endpoints.add(m)
                if secrets:
                    findings.append(Finding(
                        technique=self.id,
                        severity="high",
                        confidence=0.95,
                        title=f"Secrets/API keys found in {path}",
                        evidence={"secrets": list(secrets), "path": path},
                        references=self.references,
                    ))
                if endpoints:
                    findings.append(Finding(
                        technique=self.id,
                        severity="medium",
                        confidence=0.8,
                        title=f"Internal endpoints found in {path}",
                        evidence={"endpoints": list(endpoints), "path": path},
                        references=self.references,
                    ))
                if not secrets and not endpoints:
                    findings.append(Finding(
                        technique=self.id,
                        severity="info",
                        confidence=0.5,
                        title=f"No secrets or endpoints found in {path}",
                        evidence={"path": path},
                        references=self.references,
                    ))
            except Exception as e:
                continue
        return findings
