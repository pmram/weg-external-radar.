#!/usr/bin/env python3
"""Passive discovery of potential WEG lookalike domains using free CT logs.

No target-site crawling, login, authentication attempts or malware execution.
Candidates are NOT confirmed phishing websites.
"""
from __future__ import annotations
import html
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "results.json"
QUERIES = [
    'inurl:weg "WEG" "official" -site:weg.net',
    'inurl:weg "WEG" "site oficial" -site:weg.net',
    'inurl:weg "WEG" "login" -site:weg.net',
    'inurl:weg "WEG" "portal" -site:weg.net',
    'inurl:weg "WEG" "customer" -site:weg.net',
    'inurl:weg "WEG" "distributor" -site:weg.net',
    '"WEG" "account" "sign in" -site:weg.net',
    '"WEG" "purchase order" "supplier" -site:weg.net',
    '"WEG" "recrutamento" "cadastro" -site:weg.net',
    '"WEG" "support" "password" -site:weg.net',
    '"WEG" "motores" "loja oficial" -site:weg.net',
]
EXCLUDED_DOMAINS = (
    "weg.net", "google.com", "googleusercontent.com", "youtube.com",
    "facebook.com", "instagram.com", "linkedin.com", "x.com",
    "twitter.com", "tiktok.com", "wikipedia.org", "reddit.com",
    "github.com", "amazon.com", "ebay.com", "aliexpress.com",
)
# Domains of news, journals, forums, product catalogues and recruitment platforms.
EXCLUDED_HOST_PARTS = (
    "news", "noticias", "noticias", "journal", "jornal", "magazine",
    "press", "media", "review", "blog", "wiki", "forum", "jobs",
    "careers", "indeed", "glassdoor", "marketplace", "shopping",
)
BRAND_TERM = re.compile(r"(?<![a-z])weg(?![a-z])", re.IGNORECASE)
OFFICIAL = re.compile(r"\b(official|site oficial|loja oficial|p[aá]gina oficial|empresa weg|weg corporate)\b", re.I)
AUTH = re.compile(r"\b(login|log[ -]?in|sign[ -]?in|senha|password|conta|account|portal|cadastro|verify|verification)\b", re.I)
PAYMENT = re.compile(r"\b(payment|pagamento|pagar|invoice|fatura|boleto|bank|banco|supplier portal)\b", re.I)
TRUSTED_EXTRA = [
    x.strip().lower().strip(".")
    for x in os.getenv("TRUSTED_DOMAINS", "").split(",") if x.strip()
]

def clean(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", value or ""))).strip()

def suffix(host: str, suffix_name: str) -> bool:
    return host == suffix_name or host.endswith("." + suffix_name)

def excluded(host: str) -> bool:
    if any(suffix(host, d) for d in EXCLUDED_DOMAINS + tuple(TRUSTED_EXTRA)):
        return True
    # Match whole labels / components, not "new" inside unrelated words.
    labels = re.split(r"[.\-_]", host)
    return any(p in labels or any(p in label for label in labels if p in (
        "noticias", "marketplace", "glassdoor", "indeed"
    )) for p in EXCLUDED_HOST_PARTS)

def hostname(url: str) -> str:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("https", "http") or parsed.username or parsed.password:
            return ""
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or len(host) > 253 or not re.fullmatch(r"[a-z0-9.-]+", host):
            return ""
        return host
    except ValueError:
        return ""

def domain_evidence(host: str) -> tuple[int, list[str]]:
    """Prefer WEG as an initial brand token; avoid German 'Weg' meaning 'way'."""
    labels = host.split(".")
    score = 0
    evidence = []
    for label in labels:
        if label == "weg":
            candidate_score, reason = 55, "A marca WEG aparece como componente autónoma do domínio"
        elif re.match(r"^weg[-_](motor|motors|motores|electric|energy|portal|support|service|official|oficial|shop|store|group|brasil)", label):
            candidate_score, reason = 55, "O endereço combina WEG com um termo relacionado com a marca"
        elif re.match(r"^weg(motor|motors|motores|electric|energy|portal|support|service|official|oficial|shop|store|group|brasil)", label):
            candidate_score, reason = 55, "O endereço começa por WEG e um termo comercial"
        elif re.fullmatch(r"weg[-a-z0-9]{0,15}", label):
            # Allow short weg-something, but reject common unrelated German phrases.
            forbidden = ("weg-zur", "weg-zu", "weg-von", "weg-fuer",
                         "weg-gesetze", "weg-in", "weg-track")
            if label.startswith(forbidden):
                continue
            candidate_score, reason = 38, "O nome do domínio começa por WEG"
        elif label in ("wge", "weq", "vveg", "wegg"):
            candidate_score, reason = 40, "O nome apresenta grafia semelhante a WEG"
        else:
            continue
        if candidate_score > score:
            score, evidence = candidate_score, [reason]
    return score, evidence

def assess(item: dict) -> dict | None:
    host = hostname(item.get("url", ""))
    if not host or excluded(host):
        return None
    score, evidence = domain_evidence(host)
    if not score:
        # Mentioning WEG in a product/news article is not an impersonation signal.
        return None
    title, desc = clean(item.get("title", "")), clean(item.get("description", ""))
    context = title + " " + desc
    if OFFICIAL.search(context):
        score += 25
        evidence.append("O título ou resumo apresenta linguagem de canal oficial")
    if AUTH.search(context):
        score += 15
        evidence.append("O resumo menciona autenticação, conta ou portal")
    if PAYMENT.search(context):
        score += 15
        evidence.append("O resumo menciona pagamentos ou dados financeiros")
    if BRAND_TERM.search(context):
        score += 5
        evidence.append("A marca WEG aparece no título ou resumo")
    score = min(100, score)
    if score < 38:
        return None
    return {
        "domain": host,
        "url": item["url"],
        "title": title or host,
        "description": desc,
        "source": "Brave Search",
        "query": item.get("query", ""),
        "score": score,
        "priority": "Alta" if score >= 75 else "Média" if score >= 50 else "Baixa",
        "signals": evidence,
        "status": "Requer validação humana",
    }

def ct_candidates():
    """Public crt.sh certificate-transparency search; no API key or target probing."""
    patterns = ["%.weg.%", "%weg-%", "wegmotor%", "wegenergy%"]
    for pattern in patterns:
        endpoint = "https://crt.sh/?q=" + quote(pattern, safe="") + "&output=json"
        headers = {"User-Agent": "WEG-Brand-Monitor/3.0 (passive CT discovery)", "Accept": "application/json"}
        try:
            with urlopen(Request(endpoint, headers=headers), timeout=50) as response:
                # Bound memory; crt.sh can return very large data sets.
                raw = response.read(12_000_001)
                if len(raw) > 12_000_000:
                    raise ValueError("crt.sh response exceeded 12 MB")
                records = json.loads(raw)
            for row in records:
                for name in (row.get("name_value") or "").splitlines():
                    host = name.strip().lower().rstrip(".")
                    if host.startswith("*."):
                        host = host[2:]
                    if not re.fullmatch(r"[a-z0-9.-]{4,253}", host):
                        continue
                    yield {"url": "https://" + host + "/", "title": host,
                           "description": "", "query": "Certificate Transparency",
                           "source": "crt.sh"}
        except Exception as exc:
            yield {"error": f"crt.sh ({pattern}): {type(exc).__name__}: {exc}"}

def main() -> None:
    candidates: dict[str, dict] = {}
    errors = []
    found = 0
    for raw in ct_candidates():
        if "error" in raw:
            errors.append(raw["error"])
            continue
        found += 1
        item = assess(raw)
        if item:
            # CT logs prove only that a certificate was logged for the name:
            # they do not prove that the website exists or is malicious.
            item["source"] = "crt.sh · Certificate Transparency"
            item["status"] = "Domínio potencial — validar existência, propriedade e conteúdo"
            item["signals"].append("Nome encontrado em registos públicos de certificados TLS; website não verificado")
            item["score"] = min(item["score"], 65)
            item["priority"] = "Média" if item["score"] >= 50 else "Baixa"
            previous = candidates.get(item["domain"])
            if previous is None or item["score"] > previous["score"]:
                candidates[item["domain"]] = item

    notice = (
        "Pesquisa gratuita de certificados TLS: os candidatos não são sites confirmados, "
        "podem estar inativos ou pertencer a parceiros legítimos. "
        "Nenhum website candidato foi visitado."
    )
    if errors:
        notice += " Algumas consultas falharam; os resultados podem estar incompletos."
    result = {
        "version": 2,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "provider": "crt.sh (Certificate Transparency) · gratuito",
        "notice": notice,
        "checked_queries": 4,
        "results": sorted(candidates.values(), key=lambda x: (-x["score"], x["domain"]))[:300],
        "errors": errors,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"CT names processed: {found}; candidates: {len(candidates)}; errors: {len(errors)}")
    # Preserve previous successful scan if ALL lookups fail, rather than clearing it.
    if errors and found == 0:
        raise SystemExit("No Certificate Transparency queries succeeded")

if __name__ == "__main__":
    main()
