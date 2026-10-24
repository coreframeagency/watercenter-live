#!/usr/bin/env python3
"""Password-lock the Water Center pages.
  lock:    python3 lock.py lock   <plain_dir> <out_dir> <password>
  unlock:  python3 lock.py unlock <locked_dir> <out_dir> <password>
AES-256-GCM, key from PBKDF2-SHA256 (310000 rounds). Pages in PAGES are encrypted; everything else is copied."""
import sys,os,re,json,base64,shutil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
PAGES=['index.html','site.html','tool.html']
IT=310000
def key(pw,salt):return PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=IT).derive(pw.encode())
b64=lambda b:base64.b64encode(b).decode()
GATE='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#0B6BA6">
%HEAD%
<style>
:root{--bg:#F2F8FC;--ink:#0B2A40;--ink2:#4A6678;--line:#CFE0EC;--blue:#0B6BA6}
@media(prefers-color-scheme:dark){:root{--bg:#061420;--ink:#E8F2F8;--ink2:#9DB5C6;--line:#1E3F57;--blue:#4FB0E6}}
*{box-sizing:border-box}html,body{height:100%}body{margin:0;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;padding:16px;padding-top:max(16px,env(safe-area-inset-top));padding-bottom:max(16px,env(safe-area-inset-bottom))}
#g{width:min(400px,100%);display:grid;gap:16px;text-align:center}
#g img{width:72px;height:72px;border-radius:16px;margin:0 auto}
h1{margin:0;font-size:24px;line-height:1.2}p{margin:0;color:var(--ink2)}
form{display:grid;gap:8px;margin-top:8px}
input{font:inherit;font-size:16px;padding:16px;border:1px solid var(--line);border-radius:12px;background:transparent;color:var(--ink);width:100%;min-height:48px}
input:focus{outline:2px solid var(--blue);outline-offset:1px}
button{font:inherit;font-weight:600;min-height:48px;border:0;border-radius:12px;background:var(--blue);color:#fff;cursor:pointer}
button:disabled{opacity:.6}
#e{color:#C0392B;min-height:24px;font-size:14px}
body.chk #g{visibility:hidden}
</style></head><body class="chk"><main id="g"><img src="/apple-touch-icon.png" alt="Water Center" width="72" height="72"><h1>Water Center</h1><p>Enter the password to continue.</p>
<form id="f"><input id="p" type="password" autocomplete="current-password" placeholder="Password" aria-label="Password" required><button id="b" type="submit">Enter</button><div id="e" role="alert"></div></form></main>
<noscript>This page needs JavaScript.</noscript>
<script>
(function(){
var D=%DATA%,K='wc_gate_v1',IT=%IT%;
function u(s){var b=atob(s),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a}
async function open(pw){
  var enc=new TextEncoder(),km=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveKey']);
  var k=await crypto.subtle.deriveKey({name:'PBKDF2',salt:u(D.s),iterations:IT,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['decrypt']);
  var pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:u(D.i)},k,u(D.c));
  return new TextDecoder().decode(pt)}
function show(html){document.open();document.write(html);document.close()}
function sget(){try{return localStorage.getItem(K)}catch(e){return null}}
function sset(v){try{if(v)localStorage.setItem(K,v);else localStorage.removeItem(K)}catch(e){}}
function ask(msg){document.body.classList.remove('chk');var e=document.getElementById('e');if(msg)e.textContent=msg;document.getElementById('p').focus()}
if(!window.crypto||!crypto.subtle){document.body.classList.remove('chk');document.getElementById('e').textContent='This browser cannot open the page over an insecure connection. Use https://watercenter.live.';return}
var f=document.getElementById('f'),b=document.getElementById('b');
f.addEventListener('submit',async function(ev){ev.preventDefault();var pw=document.getElementById('p').value;b.disabled=true;document.getElementById('e').textContent='';
  try{var h=await open(pw);sset(pw);show(h)}catch(e){b.disabled=false;document.getElementById('e').textContent='That password is not right.';document.getElementById('p').select()}});
var sp=sget();
if(sp){open(sp).then(show).catch(function(){sset(null);ask()})}else ask();
})();
</script></body></html>'''
def head_bits(h):
    m=re.search(r'<head>(.*?)</head>',h,re.S);hd=m.group(1) if m else h
    out=[]
    t=re.search(r'<title>.*?</title>',hd,re.S)
    if t:out.append(t.group(0))
    for x in re.findall(r'<meta\s[^>]*>',hd):
        if re.search(r'charset|viewport|name="robots"|theme-color',x):continue
        out.append(x)
    for x in re.findall(r'<link\s[^>]*>',hd):
        if re.search(r'rel="(canonical|icon|apple-touch-icon|alternate)"',x):out.append(x)
    return '\n'.join(out)
def lock(src,dst,pw):
    os.makedirs(dst,exist_ok=True)
    for n in os.listdir(src):
        p=os.path.join(src,n)
        if n in PAGES:
            h=open(p,encoding='utf-8').read();salt=os.urandom(16);iv=os.urandom(12)
            ct=AESGCM(key(pw,salt)).encrypt(iv,h.encode(),None)
            data=json.dumps({'s':b64(salt),'i':b64(iv),'c':b64(ct)},separators=(',',':'))
            open(os.path.join(dst,n),'w',encoding='utf-8').write(GATE.replace('%HEAD%',head_bits(h)).replace('%DATA%',data).replace('%IT%',str(IT)))
        elif os.path.isdir(p):
            shutil.copytree(p,os.path.join(dst,n),dirs_exist_ok=True)
        else:shutil.copy(p,os.path.join(dst,n))
def unlock(src,dst,pw):
    os.makedirs(dst,exist_ok=True)
    for n in os.listdir(src):
        p=os.path.join(src,n)
        if n in PAGES:
            h=open(p,encoding='utf-8').read();d=json.loads(re.search(r'var D=(\{.*?\}),K=',h,re.S).group(1))
            pt=AESGCM(key(pw,base64.b64decode(d['s']))).decrypt(base64.b64decode(d['i']),base64.b64decode(d['c']),None)
            open(os.path.join(dst,n),'w',encoding='utf-8').write(pt.decode())
        elif os.path.isdir(p):shutil.copytree(p,os.path.join(dst,n),dirs_exist_ok=True)
        else:shutil.copy(p,os.path.join(dst,n))
if __name__=='__main__':
    if len(sys.argv)!=5:print(__doc__);sys.exit(1)
    (lock if sys.argv[1]=='lock' else unlock)(sys.argv[2],sys.argv[3],sys.argv[4])
