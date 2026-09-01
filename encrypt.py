#!/usr/bin/env python3
"""Encrypt an HTML page for the Agent Radio share site.
AES-256-GCM, key from PBKDF2-HMAC-SHA256 (310k iters).
Writes a TINY gate page (renders instantly) + payload.bin (raw ciphertext,
fetched in the background with progress while the user types the password).
Usage: encrypt.py <password> <file> [<file>...]
"""
import sys, os, base64, secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER=310000
def derive(pw, salt):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode())

WRAP = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Agent Radio</title>
<style>
:root{--ink:#111110;--bone:#F5F4F0;--muted:rgba(245,244,240,.55);--accent:#E8420F;--live:#30D158}
*{margin:0;padding:0;box-sizing:border-box}html,body{height:100%}
body{background:#111110;color:var(--bone);font-family:-apple-system,BlinkMacSystemFont,"Helvetica Neue",Helvetica,Arial,sans-serif;display:flex;align-items:center;justify-content:center;padding:28px 22px}
.g{display:flex;flex-direction:column;align-items:center;gap:16px;text-align:center;width:100%;max-width:320px}
.lk{font-size:12px;font-weight:800;letter-spacing:.2em;text-transform:uppercase;color:var(--muted)}
input{width:100%;padding:15px 20px;border-radius:99px;border:1.5px solid rgba(245,244,240,.28);background:rgba(255,255,255,.06);color:var(--bone);font-size:16px;font-weight:700;text-align:center;outline:none}
input:focus{border-color:var(--accent)}
button{width:100%;padding:15px 20px;border-radius:99px;border:0;background:var(--bone);color:var(--ink);font-size:15px;font-weight:800;cursor:pointer}
.err{font-size:12px;color:var(--accent);font-weight:700;min-height:16px}
.dl{font-size:10.5px;color:var(--muted);font-weight:700;letter-spacing:.1em;text-transform:uppercase;min-height:14px}
.sp{font-size:12px;color:var(--muted);font-weight:700;letter-spacing:.12em;text-transform:uppercase;animation:pu 1.4s ease-in-out infinite}
@keyframes pu{50%{opacity:.35}}
.shake{animation:sh .4s ease}@keyframes sh{20%,60%{transform:translateX(-7px)}40%,80%{transform:translateX(7px)}}
</style></head><body>
<form class="g" id="g" autocomplete="off">
  <span class="lk">Agent Radio &middot; Private preview</span>
  <input id="pw" type="password" placeholder="Password" autofocus aria-label="Password">
  <button type="submit">Unlock</button>
  <span class="err" id="err"></span>
  <span class="dl" id="dl"></span>
</form>
<div class="g" id="ld" style="display:none"><span class="sp">Tuning in&hellip;</span></div>
<script>
const SALT="__SALT__", NONCE="__NONCE__", ITER=__ITER__;
const b2u=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
/* the payload downloads in the background while you type */
const dlEl=document.getElementById('dl');
const payload=(async()=>{
  const res=await fetch('payload.bin');
  const total=+res.headers.get('content-length')||0;
  if(!res.body){ return new Uint8Array(await res.arrayBuffer()); }
  const reader=res.body.getReader(); const chunks=[]; let got=0;
  for(;;){ const {done,value}=await reader.read(); if(done) break;
    chunks.push(value); got+=value.length;
    if(total) dlEl.textContent='loading the prototype · '+Math.min(100,Math.round(got/total*100))+'%'; }
  dlEl.textContent='';
  const buf=new Uint8Array(got); let o=0;
  for(const c of chunks){ buf.set(c,o); o+=c.length; }
  return buf;
})();
async function key(pw){
  const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt:b2u(SALT),iterations:ITER,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['decrypt']);
}
async function open_(pw){
  const [k,data]=await Promise.all([key(pw),payload]);
  const buf=await crypto.subtle.decrypt({name:'AES-GCM',iv:b2u(NONCE)},k,data);
  sessionStorage.setItem('arpw',pw);
  document.open(); document.write(new TextDecoder().decode(buf)); document.close();
}
const form=document.getElementById('g'), ld=document.getElementById('ld');
form.addEventListener('submit',async e=>{
  e.preventDefault();
  const pw=document.getElementById('pw').value;
  form.style.display='none'; ld.style.display='flex';
  try{ await open_(pw); }
  catch(_){ ld.style.display='none'; form.style.display='flex'; form.classList.remove('shake'); void form.offsetWidth; form.classList.add('shake'); document.getElementById('err').textContent='That is not the password.'; }
});
(async()=>{ const pw=sessionStorage.getItem('arpw'); if(pw){ form.style.display='none'; ld.style.display='flex'; try{ await open_(pw); }catch(_){ sessionStorage.removeItem('arpw'); ld.style.display='none'; form.style.display='flex'; } } })();
</script></body></html>"""

def encrypt_file(pw, path):
    raw=open(path,'rb').read()
    if b'payload.bin' in raw and b'AES-GCM' in raw:
        print('skip (already a gate):', path); return
    salt=secrets.token_bytes(16); nonce=secrets.token_bytes(12)
    ct=AESGCM(derive(pw,salt)).encrypt(nonce, raw, None)
    d=os.path.dirname(path) or '.'
    open(os.path.join(d,'payload.bin'),'wb').write(ct)
    out=(WRAP.replace('__SALT__',base64.b64encode(salt).decode())
             .replace('__NONCE__',base64.b64encode(nonce).decode())
             .replace('__ITER__',str(ITER)))
    open(path,'w').write(out)
    print('gate: %s (%.0fKB) + payload.bin (%.1fMB)'%(path,len(out)/1e3,len(ct)/1e6))

if __name__=='__main__':
    pw=sys.argv[1]
    for f in sys.argv[2:]: encrypt_file(pw,f)
