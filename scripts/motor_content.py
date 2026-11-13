"""Bounded, safe HTML-only checks for electric-motor references.

This is a relevance filter, NOT a phishing verdict. Never execute JS, fetch
images/subresources or follow redirects. Network pinning and public-IP checks
are inherited from check_sites.
"""
import http.client
import re
import ssl
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from check_sites import public_addresses, PinnedHTTP, PinnedHTTPS, TIMEOUT

MAX_BYTES = 128 * 1024
# Electric motors in commonly used WEG markets. Avoid broad standalone 'motor'
# (it also means engine) and 'weg' (German: way).
MOTOR_TERMS = [
    ("electric motors", r"\belectric\s+motors?\b"),
    ("industrial motors", r"\bindustrial\s+motors?\b"),
    ("three-phase motor", r"\b(?:three[- ]phase|3[- ]phase)\s+motors?\b"),
    ("induction motor", r"\binduction\s+motors?\b"),
    ("motor elétrico", r"\bmotores?\s+el[eé]tricos?\b"),
    ("motor eléctrico", r"\bmotores?\s+el[eé]ctricos?\b"),
    ("moteur électrique", r"\bmoteurs?\s+[ée]lectriques?\b"),
    ("elektromotor", r"\belektromotor(?:en|s)?\b"),
    ("elektromotor (ru)", r"\bэлектродвигател[ьиa-я]*\b"),
    ("электромотор", r"\bэлектромотор[а-я]*\b"),
    ("电动机", r"电动机|电机产品"),
    ("電動機", r"電動機"),
    ("electric motor (es)", r"\bmotores?\s+el[eé]ctricos?\b"),
    ("elektrik motoru", r"\belektrik\s+motor(?:u|lar[ıi])?\b"),
    ("електродвигун", r"\bелектродвигун[а-яіїєґ]*\b"),
    ("silniki elektryczne", r"\bsilnik(?:i|ów)?\s+elektryczn[a-z]*\b"),
    ("motori elettrici", r"\bmotori?\s+elettric[io]\b"),
    ("elektrische motoren", r"\belektrische\s+motor(?:en)?\b"),
    ("электр қозғалтқыш", r"электр(?:лік)?\s+қозғалтқыш[а-яәғқңөұүһі]*"),
]
PATTERNS = [(label, re.compile(pattern, re.I)) for label, pattern in MOTOR_TERMS]
CONTEXT = re.compile(
    r"\b(weg|w22|w21|w50|w60|ac\s+motors?|drives?|inverters?|"
    r"industri(?:al|a)|kw|hp|rpm|trif[aá]sic[oa]s?|three.phase|"
    r"electric|el[eé]tric[oa]s?|elektro|motores?|motors?)\b",
    re.I
)
GENERIC = re.compile(r"\bmotor(?:es|s)?\b", re.I)

class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skip = 0
        self.parts = []
        self.title = []
        self.in_title = False
    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "svg", "noscript", "template"):
            self.skip += 1
        if tag == "title":
            self.in_title = True
    def handle_endtag(self, tag):
        if tag in ("script", "style", "svg", "noscript", "template") and self.skip:
            self.skip -= 1
        if tag == "title":
            self.in_title = False
    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)
            if self.in_title:
                self.title.append(data)

def classify_html(raw):
    parser = VisibleText()
    parser.feed(raw.decode("utf-8", errors="replace"))
    visible = re.sub(r"\s+", " ", " ".join(parser.parts))
    matches = [label for label, expression in PATTERNS if expression.search(visible)]
    if not matches and GENERIC.search(visible) and CONTEXT.search(visible):
        # Generic 'motor' alone is insufficient: preserve candidates for review.
        return "Indício fraco", ["motor (contexto não conclusivo)"], "Texto genérico sobre motores; confirmar se são elétricos"
    if matches:
        return "Referências a motores", matches[:8], "Referências a motores elétricos detetadas no HTML público"
    return "Sem referências", [], "Sem referências a motores no HTML inicial analisado"

def inspect(host, checked_url):
    ips = public_addresses(host)
    if not ips:
        return {"motor_status": "Não verificado", "motor_terms": [], "motor_detail": "DNS não resolvido"}
    secure = checked_url.startswith("https://")
    conn = None
    try:
        conn = (PinnedHTTPS if secure else PinnedHTTP)(host, ips[0], timeout=TIMEOUT)
        conn.request("GET", "/", headers={
            "Host": host, "User-Agent": "WEG-Radar-Relevance/1.0",
            "Accept": "text/html", "Accept-Encoding": "identity", "Connection": "close",
        })
        response = conn.getresponse()
        if response.status < 200 or response.status >= 300:
            return {"motor_status": "Não verificado", "motor_terms": [], "motor_detail": f"HTTP {response.status}"}
        media_type = response.getheader("Content-Type", "").split(";")[0].lower().strip()
        if media_type not in ("text/html", "application/xhtml+xml"):
            return {"motor_status": "Não verificado", "motor_terms": [], "motor_detail": "Conteúdo não HTML"}
        content_length = response.getheader("Content-Length")
        if content_length and content_length.isdigit() and int(content_length) > MAX_BYTES:
            return {"motor_status": "Não verificado", "motor_terms": [], "motor_detail": "HTML excede 128 KB"}
        data = response.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            return {"motor_status": "Não verificado", "motor_terms": [], "motor_detail": "HTML excede 128 KB"}
        status, terms, detail = classify_html(data)
        return {"motor_status": status, "motor_terms": terms, "motor_detail": detail}
    except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError, UnicodeError) as exc:
        return {"motor_status": "Não verificado", "motor_terms": [],
                "motor_detail": f"Erro de inspeção: {type(exc).__name__}"}
    finally:
        if conn:
            conn.close()

def check_motor_content(candidates, max_workers=6):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        tasks = {executor.submit(inspect, host, row["checked_url"]): row
                 for host, row in candidates.items()
                 if row.get("site_status") == "Ativo" and row.get("checked_url")}
        for future in as_completed(tasks):
            row = tasks[future]
            try:
                row.update(future.result())
            except Exception:
                row.update(motor_status="Não verificado", motor_terms=[],
                           motor_detail="Erro interno ao verificar conteúdo")
    return candidates
