#!/usr/bin/env python3
"""Passive discovery of WEG lookalike domains in search engine results.

No target-site crawling, login, authentication attempts or malware execution.
Candidates are NOT confirmed phishing websites.
"""
from __future__ import annotations
import html
import json
import os
import re
import time
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
    labels = host.split(".")
    # Only hostname/domain identity may establish a candidate.
    score = 0
    evidence = []
    for label in labels:
        if label == "weg":
            score = max(score, 55)
            evidence = ["A marca WEG aparece como componente autónoma do domínio"]
        elif re.search(r"(^weg[-0-9]|[-0-9]weg($|[-0-9])|weg(motor|energy|electric|group|brasil|global|portal|support|service|oficial|official|shop|store)|^(motor|energy|electric|portal|support|service|official|oficial|shop|store)weg)", label):
            if score < 50:
                score = 50
                evidence = ["O endereço combina WEG com termos de marca/serviço"]
        elif label.startswith("weg") or label.endswith("weg"):
            if score < 38:
                score = 38
                evidence = ["O endereço incorpora a sequência WEG"]
        elif label in ("wge", "weq", "vveg", "wegg", "w-eg"):
            if score < 45:
                score = 45
                evidence = ["O endereço é semelhante à grafia WEG"]
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

def brave_search(query: str, api_key: str):
    url = (
        "https://api.search.brave.com/res/v1/web/search?q="
        + quote(query) + "&count=20"
    )
    headers = {
        "Accept": "application/json",
        "X-Subscription-Token": api_key,
        "User-Agent": "WEG-Brand-Monitor/2.0",
    }
    with urlopen(Request(url, headers=headers), timeout=30) as response:
        payload = json.load(response)
    for hit in payload.get("web", {}).get("results", []):
        yield {
            "url": hit.get("url", ""),
            "title": hit.get("title", ""),
            "description": hit.get("description", ""),
            "query": query,
        }

def main() -> None:
    api_key = os.getenv("BRAVE_SEARCH_API_KEY", "").strip()
    candidates: dict[str, dict] = {}
    errors = []
    notice = None
    if not api_key:
        notice = "Configura BRAVE_SEARCH_API_KEY em GitHub Actions Secrets para ativar a pesquisa. Não são usadas notícias como alternativa."
    else:
        for query in QUERIES:
            try:
                for raw in brave_search(query, api_key):
                    item = assess(raw)
                    if item:
                        previous = candidates.get(item["domain"])
                        if previous is None or item["score"] > previous["score"]:
                            candidates[item["domain"]] = item
                time.sleep(0.15)
            except Exception as exc:
                errors.append(f"{query}: {type(exc).__name__}: {exc}")
    result = {
        "version": 2,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "provider": "Brave Search" if api_key else "Não configurado",
        "notice": notice,
        "checked_queries": len(QUERIES) if api_key else 0,
        "results": sorted(
            candidates.values(),
            key=lambda x: (-x["score"], x["domain"]),
        ),
        "errors": errors,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Domains: {len(candidates)}; Errors: {len(errors)}; {notice or 'scan complete'}")

if __name__ == "__main__":
    main()
