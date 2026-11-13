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
from check_sites import check_all

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
    patterns = ["%.weg.%", "%weg-%", "wegmotor%", "wegenergy%", "weg-connect%", "%weg-connect%", "wegportal%", "wegservice%"]
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

def seed_candidates():
    """Operator-supplied names are discovery hints, never automatically marked active."""
    path = ROOT / "data" / "known_domains.txt"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        host = line.split("#", 1)[0].strip().lower()
        if not re.fullmatch(r"[a-z0-9.-]{4,253}", host):
            continue
        yield {"url": "https://" + host + "/", "title": host,
               "description": "", "query": "Domínio conhecido",
               "source": "Semente de descoberta"}

def main() -> None:
    candidates = {}
    errors = []
    names_processed = 0

    # In addition to certificate patterns, operator-supplied examples and
    # previous candidates are rechecked on every run. No API key required.
    sources = list(seed_candidates())
    if OUTPUT.exists():
        try:
            old = json.loads(OUTPUT.read_text(encoding="utf-8"))
            for row in old.get("results", []) + old.get("unreachable", []):
                domain = row.get("domain", "")
                if re.fullmatch(r"[a-z0-9.-]{4,253}", domain):
                    sources.append({"url": "https://" + domain + "/",
                                    "title": domain, "description": "",
                                    "source": "Histórico", "query": "Histórico"})
        except (ValueError, OSError):
            pass

    for raw in sources:
        item = assess(raw)
        if item:
            item["source"] = raw["source"]
            candidates[item["domain"]] = item

    for raw in ct_candidates():
        if "error" in raw:
            errors.append(raw["error"])
            continue
        names_processed += 1
        item = assess(raw)
        if item:
            item["source"] = "crt.sh (Certificate Transparency)"
            prior = candidates.get(item["domain"])
            if not prior or item["score"] > prior["score"]:
                candidates[item["domain"]] = item

    # Keep scan bounded and prioritize known seeds + highest hostname confidence.
    seeds = set(x["url"].split("/")[2] for x in sources if x.get("query") == "Domínio conhecido")
    ordered = sorted(candidates, key=lambda h: (h not in seeds, -candidates[h]["score"], h))[:100]
    candidates = {host: candidates[host] for host in ordered}
    check_all(candidates)

    active, inactive = [], []
    for item in candidates.values():
        item["status"] = "Requer validação humana"
        item["signals"].append("Disponibilidade avaliada via DNS público e resposta HTTP sem descarregar o conteúdo")
        item["priority"] = "Média" if item["score"] >= 50 else "Baixa"
        item["score"] = min(item["score"], 65)
        if item["site_status"] == "Ativo":
            item["url"] = item["checked_url"]
            active.append(item)
        else:
            inactive.append(item)

    active.sort(key=lambda x: (-x["score"], x["domain"]))
    inactive.sort(key=lambda x: (x["site_status"], x["domain"]))
    notice = (
        "A lista principal apresenta apenas endereços com resposta HTTP 2xx no momento da consulta. "
        "Isso não confirma que tenham aparência oficial nem que sejam fraudulentos. "
        "Redirecionamentos e sites inacessíveis ficam separados."
    )
    if errors:
        notice += " Algumas pesquisas de certificados falharam."
    result = {
        "version": 3,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "provider": "crt.sh + DNS/HTTP (gratuito)",
        "notice": notice,
        "checked_queries": 8,
        "results": active,
        "unreachable": inactive,
        "errors": errors,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Processed names: {names_processed}; checked: {len(candidates)}; active: {len(active)}; others: {len(inactive)}")
    if errors and names_processed == 0 and not sources:
        raise SystemExit("All discovery sources failed")

if __name__ == "__main__":
    main()
