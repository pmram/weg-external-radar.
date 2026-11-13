"""Safely check whether an external web server serves an HTTP page.

Security: resolve names and connect ONLY to a public IPv4/IPv6 address,
never follow redirects, never fetch page content, and never connect to
internal, loopback, link-local, multicast or reserved targets.
"""
import http.client
import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 7

def public_addresses(host):
    addresses = []
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return []
    for record in records:
        ip = record[4][0]
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_global and ip not in addresses:
                addresses.append(ip)
        except ValueError:
            continue
    return addresses[:4]

class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, **kwargs):
        self.pinned_ip = ip
        super().__init__(host, **kwargs)
    def connect(self):
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)

class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, **kwargs):
        self.pinned_ip = ip
        super().__init__(host, **kwargs)
    def connect(self):
        sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise

def probe(host):
    ips = public_addresses(host)
    if not ips:
        return {"site_status": "Inacessível", "http_status": None,
                "checked_url": None, "check_detail": "DNS sem endereços públicos resolúveis"}
    errors = []
    # HTTPS first. HTTP fallback only if HTTPS fails to serve a page.
    for secure in (True, False):
        for ip in ips[:2]:
            conn = None
            protocol = "https" if secure else "http"
            try:
                klass = PinnedHTTPS if secure else PinnedHTTP
                conn = klass(host, ip, timeout=TIMEOUT)
                conn.request("GET", "/", headers={
                    "Host": host, "User-Agent": "WEG-Radar-Availability-Check/1.0",
                    "Range": "bytes=0-0", "Connection": "close"
                })
                response = conn.getresponse()
                status = response.status
                if 200 <= status < 300:
                    return {"site_status": "Ativo", "http_status": status,
                            "checked_url": f"{protocol}://{host}/",
                            "check_detail": "Resposta HTTP bem-sucedida; conteúdo e identidade não verificados"}
                if 300 <= status < 400:
                    # Do NOT follow potentially unsafe redirects; not proof of a usable site.
                    return {"site_status": "Redireciona", "http_status": status,
                            "checked_url": f"{protocol}://{host}/",
                            "check_detail": "HTTP redireciona; destino não verificado"}
                if status in (401, 403):
                    return {"site_status": "Acesso restrito", "http_status": status,
                            "checked_url": f"{protocol}://{host}/",
                            "check_detail": "Servidor responde, mas não permite acesso público"}
                errors.append(f"{protocol} HTTP {status}")
            except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
                errors.append(f"{protocol}: {type(exc).__name__}")
            finally:
                if conn:
                    conn.close()
    return {"site_status": "Inacessível", "http_status": None, "checked_url": None,
            "check_detail": "; ".join(errors[:4]) or "Sem resposta HTTP"}

def check_all(candidates, max_workers=8):
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        jobs = {pool.submit(probe, host): host for host in candidates}
        for future in as_completed(jobs):
            host = jobs[future]
            try:
                candidates[host].update(future.result())
            except Exception:
                candidates[host].update(site_status="Não verificado", http_status=None,
                                        checked_url=None, check_detail="Erro interno de verificação")
    return candidates
