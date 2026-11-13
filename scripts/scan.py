#!/usr/bin/env python3
"""Find public WEG references outside weg.net using Brave or Google News."""
import json, os, html, re, time
from pathlib import Path
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen
from xml.etree import ElementTree as ET
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parents[1]
QUERIES=['"WEG" electric motors','"WEG" motores elétricos','"WEG" industrial automation','"WEG" energia','"WEG" company']
def allowed(url):
    try:
        u=urlparse(url)
        host=(u.hostname or '').lower().rstrip('.')
        return u.scheme in ('https','http') and bool(host) and host!='weg.net' and not host.endswith('.weg.net')
    except ValueError:
        return False
def get(url,headers=None):
    h={'User-Agent':'WEG-External-Radar/1.0',**(headers or {})}
    with urlopen(Request(url,headers=h),timeout=25) as r: return r.read()
def clean(s):
    return re.sub(r'\s+',' ',html.unescape(re.sub(r'<[^>]+>',' ',s or ''))).strip()
def search_brave(q,key):
    url='https://api.search.brave.com/res/v1/web/search?q='+quote(q+' -site:weg.net')+'&count=20'
    payload=json.loads(get(url,{'Accept':'application/json','X-Subscription-Token':key}))
    for x in payload.get('web',{}).get('results',[]):
        yield {'title':clean(x.get('title')),'url':x.get('url',''),'description':clean(x.get('description')),'source':'Brave Search','query':q}
def search_news(q):
    url='https://news.google.com/rss/search?q='+quote(q+' -site:weg.net')+'&hl=en-US&gl=US&ceid=US:en'
    for x in ET.fromstring(get(url)).findall('./channel/item'):
        yield {'title':clean(x.findtext('title')),'url':(x.findtext('link') or '').strip(),'description':clean(x.findtext('description')),'source':'Google News RSS','query':q}
def main():
    api=os.getenv('BRAVE_SEARCH_API_KEY','').strip()
    items={}; errors=[]
    for q in QUERIES:
        try:
            for x in (search_brave(q,api) if api else search_news(q)):
                if not allowed(x['url']) or not x['title']: continue
                host=(urlparse(x['url']).hostname or '').lower()
                x['domain']=host
                x['domain_verified']=not (host=='news.google.com' or host.endswith('.google.com') or host.endswith('.googleusercontent.com'))
                items.setdefault(x['url'].rstrip('/'),x)
            time.sleep(.2)
        except Exception as ex:
            errors.append(q+': '+str(ex))
    output={'updated_at':datetime.now(timezone.utc).isoformat(),'provider':'Brave Search' if api else 'Google News RSS (unverified links)','results':sorted(items.values(),key=lambda x:(not x['domain_verified'],x['domain']))[:250],'errors':errors}
    target=ROOT/'data/results.json'
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Found:',len(output['results']),'Errors:',len(errors))
    if errors and not items: raise SystemExit('All searches failed')
if __name__=='__main__': main()
