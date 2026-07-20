/* Sky Matrix — Trial licensing Worker (Cloudflare)
 * Handles: web-form trial requests, email-in trial requests, and admin "grant extra trial".
 * Signs a device-locked, time-limited code with the admin ECDSA private key (stored as a SECRET,
 * env.LIC_PRIV_JWK) so the app verifies it with its embedded public key. Never put the key in code.
 *
 * Secrets to set (wrangler secret put ... / dashboard):
 *   LIC_PRIV_JWK   – the private signing key JWK (JSON string) from the License Manager
 *   RESEND_API_KEY – your Resend API key (for sending email)
 *   ADMIN_TOKEN    – a long random string; required to call /admin/*
 *   LEMON_WEBHOOK_SECRET – Lemon Squeezy webhook signing secret (verifies /lemon/webhook)
 *   ANTHROPIC_API_KEY – Anthropic API key (for the AI OFP reader at /ofp/parse)
 *   FR24_TOKEN – Flightradar24 API bearer token (for aircraft/flight lookup at /fr24/lookup)
 * Bindings:
 *   TRIALS (KV namespace) – remembers one-trial-per-device
 * Vars (wrangler.toml [vars]):
 *   FROM_EMAIL   e.g. "Sky Matrix <trial@skymatrix.biz>"
 *   APP_URL      e.g. "https://skymatrix.biz"
 *   TRIAL_DAYS   e.g. "10"
 */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, x-admin-token, x-group-token",
};
const json = (obj, status=200) =>
  new Response(JSON.stringify(obj), {status, headers: {"Content-Type":"application/json", ...CORS}});

function b64u(buf){
  let s = btoa(String.fromCharCode(...new Uint8Array(buf)));
  return s.replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
const DEV_RE = /SKM-[A-Z0-9]{6}/i;

async function signCode(env, device, days){
  const jwk = JSON.parse(env.LIC_PRIV_JWK);
  const key = await crypto.subtle.importKey("jwk", jwk, {name:"ECDSA", namedCurve:"P-256"}, false, ["sign"]);
  const expDay = Math.floor(Date.now()/86400000) + days;
  const msg = new TextEncoder().encode(device + "|" + expDay);
  const sig = await crypto.subtle.sign({name:"ECDSA", hash:"SHA-256"}, key, msg);
  return { code: expDay + "~" + b64u(sig), expDay };
}
// re-sign the code for a device given its already-stored expiry day (used by /mycode so the app can pull its code)
async function signExp(env, device, expDay){
  const jwk = JSON.parse(env.LIC_PRIV_JWK);
  const key = await crypto.subtle.importKey("jwk", jwk, {name:"ECDSA", namedCurve:"P-256"}, false, ["sign"]);
  const sig = await crypto.subtle.sign({name:"ECDSA", hash:"SHA-256"}, key, new TextEncoder().encode(device + "|" + expDay));
  return expDay + "~" + b64u(sig);
}
// verify a licence code (device-locked ECDSA signature) using the public half of the signing key
async function verifyLicence(env, device, code){
  try{
    if(!env.LIC_PRIV_JWK) return {ok:false};
    const parts = String(code||"").split("~"); if(parts.length!==2) return {ok:false};
    const expDay = parseInt(parts[0],10); if(!expDay) return {ok:false};
    const jwk = JSON.parse(env.LIC_PRIV_JWK);
    const key = await crypto.subtle.importKey("jwk", {kty:jwk.kty, crv:jwk.crv, x:jwk.x, y:jwk.y}, {name:"ECDSA", namedCurve:"P-256"}, false, ["verify"]);
    let b = parts[1].replace(/-/g,"+").replace(/_/g,"/"); while(b.length%4) b+="=";
    const bin = atob(b); const sig = new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) sig[i]=bin.charCodeAt(i);
    const ok = await crypto.subtle.verify({name:"ECDSA", hash:"SHA-256"}, key, sig, new TextEncoder().encode(device+"|"+expDay));
    return ok ? {ok:true, expDay} : {ok:false};
  }catch(e){ return {ok:false}; }
}
function expiryText(expDay){
  return new Date(expDay*86400000).toUTCString().slice(0,16) + " UTC";
}

/* ---- AI OFP reader (Claude Haiku via Anthropic API) ---- */
const OFP_SYSTEM = `You are an expert airline flight dispatcher and OFP analyst. Apply your full knowledge of Operational Flight Plans worldwide — every major flight-planning system (Lido/LIDO, Jeppesen JetPlan, NavBlue N-Flight, Sabre Dispatch Manager, PPS, AVTECH, and airline in-house formats such as PIA, Etihad, Emirates, Qatar, Spirit, etc.), standard dispatch terminology and abbreviations, ICAO/IATA airport codes, ICAO aircraft type designators, registration prefixes, and fuel/weight/time conventions — to read ANY layout accurately. Return ONLY a JSON object (no prose, no code fences) with these keys. Use null if a value is genuinely absent — never guess:
{
 "dep": departure ICAO (4 letters),
 "dest": destination ICAO (4 letters),
 "altn": [alternate ICAOs],
 "fltCs": flight number shown to crew (e.g. "QR704","PIA749","EY792","UAE381"),
 "atcCs": ATC callsign if different (e.g. "QTR30J"),
 "reg": aircraft registration (e.g. "A7-BEJ"),
 "acType": ICAO aircraft type designator (e.g. "B77W","A388","A320"),
 "date": date of departure (e.g. "03JUL"),
 "std": planned off-blocks UTC as HHMM,
 "sta": planned on-blocks UTC as HHMM,
 "blockTimeMin": planned block time in MINUTES,
 "tripTimeMin": planned trip/air time in MINUTES,
 "gndDist": total route/ground distance in NM (labelled "RT DIST","GC DIST","NAM DIST","AIR DIST","GROUND DIST" or the total track miles — e.g. RT DIST 6077 -> "6077"),
 "fuel": {"taxi":kg,"trip":kg,"cont":kg,"altn":kg,"final":kg,"extra":kg,"block":kg,"ramp":kg},
 "weights": {"zfw":kg,"mzfw":kg,"tow":kg,"mtow":kg,"lw":kg,"mlw":kg},
 "initFL": initial cruise level (e.g. "350"),
 "maxFL": highest planned cruise level reached on the flight (top of the step-climb profile, e.g. "400"),
 "ci": cost index,
 "tocTemp": outside-air temp at top of climb. In the NAVIGATION LOG this is the OAT/TEMP column value at the first top-of-climb / first cruise-level waypoint (e.g. a value like -30 or M30). Read it from the nav log if no dedicated TOC line is printed. Return it as shown (e.g. "-30" or "M30"),
 "tropopause": {"fl": lowest tropopause height or FL on the route, "wpt": waypoint where it is lowest, "eet": elapsed time from STD to that waypoint "HH:MM" if the nav log shows it},
 "remarks": short dispatcher remarks,
 "route": full ATS route string exactly as printed (airways + waypoints),
 "navlog": [{"wpt":waypoint/fix name as printed,"cumDistNM":cumulative track distance flown to this fix in NM (the running/total distance column, not the leg distance),"eet":cumulative elapsed time from take-off to this fix as "HH:MM","fuelRemKg":planned fuel REMAINING on board at this fix in KILOGRAMS,"fl":planned flight level / altitude at this fix as printed (e.g. "350"),"oat":outside-air temperature at this fix in °C as printed (e.g. "-51" or "M51"),"wind":wind at this fix as "DDD/SSS" (e.g. "358/050"),"isaDev":ISA deviation at this fix as printed (e.g. "+3" or "P03"),"mora":minimum off-route/grid altitude (MORA) for this fix/segment if shown (e.g. "FL025"),"tropo":tropopause height/FL at this fix if shown,"airway":the airway or route segment leading TO this fix as printed (e.g. "DCT" or an airway like "N601"),"ias":planned IAS in knots if a speed column is shown,"gs":ground speed in knots if shown,"component":wind component as printed (e.g. "TL038" or "HD020" or "P07"),"shear":wind-shear value if shown,"lat":latitude in decimal degrees (South negative) if the fix's lat/long is printed,"lon":longitude in decimal degrees (West negative) if printed,"ittImt":the true/magnitude track pair "ITT/IMT" as printed (e.g. "132/132"),"cdistNM":cumulative distance column if printed separately from cumDistNM,"rdistNM":remaining distance to destination in NM if shown,"airspace":FIR/airspace name for this segment if shown,"freq":navaid frequency for this fix if shown,"ctm":the cumulative-time (CTM) column as "HH:MM" if shown,"rtime":remaining time to destination as "HH:MM" if shown}]  // Read the NAVIGATION LOG / route table row-by-row across the pages provided. Capture as many waypoints as are legible, in order, with every column that is printed for that row (distance, time, fuel, FL, OAT, wind, ISA dev, MORA, tropopause, airway). If a column is missing for a row, use null for that field. Omit navlog entirely only if no nav-log table is visible.,
 "depRwy": planned departure runway e.g. "07R",
 "arrRwy": planned or expected arrival runway,
 "sid": SID / departure procedure name if shown,
 "star": STAR / arrival procedure name if shown,
 "firs": [{"name":FIR/UIR name,"code":ICAO FIR/UIR code,"country":country}]  (in the order overflown),
 "etopsPts": [{"posn":point label e.g. EEP/ETP/EXP,"lat":latitude,"lon":longitude,"altn":enroute alternate(s),"eet":elapsed time "HH:MM"}],
 // ETOPS/EDTO points appear on almost every long-haul OFP. They are usually printed TWICE: once in a dedicated ETOPS/EDTO summary section, and again EMBEDDED in the NAVIGATION LOG as tagged waypoint rows (labels like EEP, EXP, ENTRY, EXIT, ETP, ETP1, ETP2, EEP1, EXP1, ETOPS ENTRY, ETOPS EXIT, or a "-ETP1"-style prefix). ALWAYS cross-check both sources for EVERY airline: scan the navigation log for these tagged rows and merge them with the summary section so no entry/exit or equal-time point is missed. Prefer the lat/long and elapsed time shown in the nav log for each point. De-duplicate points that appear in both places.
 "wx": {"<ICAO>":{"metar":raw METAR if the OFP prints one for that airport,"taf":raw TAF if printed}},
 "notamsRaw": verbatim NOTAM text for departure/destination/alternate if it appears on these pages, else null,
 "confidence": {ONLY list fields you are NOT fully sure about, each set to "low"; omit every field you are confident in}
}
Rules: ALL fuel and weights in KILOGRAMS (if the OFP shows tonnes like 79.0, multiply by 1000). Times UTC 24h HHMM. Cross-check for internal consistency using standard relationships (Take-off Weight = Zero-Fuel Weight + take-off fuel; Landing Weight = TOW − trip fuel; Block/Ramp fuel = trip + taxi + contingency + alternate + final reserve + extra) and correct obvious OCR slips. Mark any field you are not fully certain about as "low" in confidence.
Known airline layout hints (apply only when the OFP clearly matches — never let a hint override what you can plainly read in the images):
- Emirates/EK (UAE... callsigns): weights EZFW/MZFW, ETOW/MTOW; dep/dest printed as ICAO/IATA pairs e.g. VHHH/HKG-OMDB/DXB; TRIP <dest> then fuel then time.
- Etihad/EY: fuel lines like "TAXI<dep>/TRIP<dest>"; figures may be in tonnes (e.g. 79.0) — multiply by 1000 for kg.
- Qatar/QR (QTR... callsigns, Lido): EZFW/MZFW, ETOW/MTOW, ELWT/MLWT; TRIP/CONT/ALTN/FINAL fuel in kg; STD/STA as dd/HHMM.
- PIA: "EST.TOGW" = take-off weight, "EST.LGWT" = landing weight, "EST.ZFW" = ZFW, "TTL.FUEL" = block fuel; "TRIP:"/"FOD:"/"HOLD:"/"ALT:" fuel; route on the FLIGHT PLAN page; date like 14-JUN-2026. ETOPS/EDTO points: the ETOPS entry and exit points are embedded WITHIN the NAVIGATION LOG as waypoint rows tagged like "-ETP1"/"-ETP2" (and FIR ENTER rows), and the full detail is in the "ETOPS INFORMATION" section as "ETP1 ... UATT/ENBO" and "ETP2 ... ENBO/CYFB" with a lat/long line "ETP N66 14.5 E055 27.7 / ... / TIME/HH.MM" — read each ETP's label, its lat/long, its diversion-airport pair as altn (e.g. "UATT / ENBO"), and its TIME as eet. PIA plans do NOT print departure or arrival runways, nor a tropopause value — leave depRwy, arrRwy and tropopause null rather than inferring them.
- Spirit/NK (Jeppesen): OPNL WT / ZFW; fuel table TAXI/TRIP/RESV/ALTN.
- SIF / Serene / Pakistani-charter style (SIF... callsign, "AP-xxx" registration, header line "AP-BOA / V2527-A5 / CRZ FLxxx CIxxx"): registration begins "AP-"; cruise level from "CRZ FLxxx", cost index from "CIxxx" on that header line. Weights are labelled "EST ZFW", "EST LDW", "MAX ZFW" plus a small box of numbers (ZFW / TOW / LDW). Fuel is a table with 6-digit ZERO-PADDED kg and DECIMAL hours: "TRIP FUEL 003061 01.04", "ALTN/<icao> 003734 01.21", "DEST HOLD 000000 00.00", "TAXI 000200", "BLOCK FUEL 008413", plus "RESERVE FUEL 04952". "FLT ID SIFxxx/dd  ORIG/DEST OPQT/OPKC  ACFT A320". Read the block/ramp fuel from "BLOCK FUEL".
Universal robustness rules — apply to EVERY OFP:
- Fuel/weights may be printed ZERO-PADDED (e.g. 003061 = 3061 kg; 058600 = 58600 kg) — strip leading zeros, keep the value in kg.
- Times may be DECIMAL hours "HH.MM" (e.g. 01.04 = 64 min, 05.08 = 308 min) OR "HHMM" — convert both to minutes for tripTimeMin/blockTimeMin.
- If a field is clearly printed on the page you were given, EXTRACT it — only use null when the value is genuinely absent. Do not leave fuel, weights, times, route, dep/dest or callsign null when they are visibly present.
Return only the JSON object.`;

// FIX (AI): merge a new OFP correction into the library — supersede any prior line for the SAME airline+field,
// drop exact duplicates, keep the newest 60. Stops conflicting/duplicate lessons piling up in the prompt.
function mergeOfpExamples(cur, note, byAirline){
  note = String(note||"").replace(/\s+/g," ").trim();
  let lines = String(cur||"").split("\n").map(function(s){return s.replace(/^\s*-\s*/,"").trim();}).filter(Boolean);
  if(note){
    // field-level dedup for corrections (airline+field); airline-level dedup for whole-format learn rules (one per airline)
    const sig = byAirline
      ? function(s){ return s.toLowerCase().split(/ ofps?\b/)[0].trim().slice(0,60); }
      : function(s){ return s.toLowerCase().split(/should|:/)[0].trim().slice(0,60); };
    const ns = sig(note);
    lines = lines.filter(function(l){ return sig(l)!==ns && l.toLowerCase()!==note.toLowerCase(); });
    lines.push(note);
  }
  return lines.slice(-60).map(function(s){return "- "+s;}).join("\n");
}
// ---- silent learning: EVERY registered (licensed) device teaches the reader from each NEW airline it uploads ----
async function autoLearnFromOfp(env, text, data, device){
  try{
    if(!env.ANTHROPIC_API_KEY) return;
    text = String(text||""); if(text.trim().length < 200) return;   // need enough text to characterise a layout
    const airline = ((String((data&&data.fltCs)||"").match(/^[A-Za-z]+/)||[""])[0]
                  || (String((data&&data.reg)||"").match(/^[A-Za-z]+/)||[""])[0]).toUpperCase();
    if(!airline || airline.length < 2) return;
    let cur=""; try{ cur = (await env.TRIALS.get("ofp:examples"))||""; }catch(e){}
    const lc = cur.toLowerCase();
    if(lc.indexOf('for "'+airline.toLowerCase()+'" ofps')>=0 || lc.indexOf('for '+airline.toLowerCase()+' ofps')>=0) return; // airline already learned — first upload wins
    // per-device daily cap so no single device can flood the shared library with junk "airlines"
    if(device && !(await rateOk(env, "autolearn:"+device, 4, 86400))) return;
    const sys = "You are teaching an OFP parser to read a new airline's flight-plan layout. From the OFP text, write ONE concise line (max 240 characters) that helps a parser read THIS airline's format in future: how to RECOGNISE it (callsign/registration prefix or a distinctive label) and the EXACT labels it uses for registration, dep/dest, ZFW & max ZFW, take-off & max take-off weight, landing & max landing weight, trip/taxi/alternate/reserve/block fuel, trip & block time, cost index, cruise level, and where the route string is printed. Note zero-padding or tonnes, and decimal HH.MM times. Begin with: For \""+airline+"\" OFPs. Return ONLY that single line.";
    let out; try{ out = await anthropic(env, sys, "OFP TEXT:\n"+text.slice(0,14000), {max_tokens:400, temperature:0}); }catch(e){ return; }
    const note = out.replace(/```/g,"").replace(/\s+/g," ").trim().slice(0,300);
    if(!note) return;
    cur = mergeOfpExamples(cur, note, true);
    try{ await env.TRIALS.put("ofp:examples", cur); }catch(e){}
    await bumpUse(env, "ai");
  }catch(e){}
}
async function anthropic(env, system, user, opts){
  opts = opts || {};
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method:"POST",
    headers:{ "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version":"2023-06-01", "content-type":"application/json" },
    body: JSON.stringify({ model: opts.model || "claude-haiku-4-5-20251001", max_tokens: opts.max_tokens || 1600, temperature: (typeof opts.temperature==="number"?opts.temperature:1), system, messages:[{role:"user", content:user}] })
  });
  const j = await r.json();
  if(!r.ok) throw new Error((j.error&&j.error.message) || ("HTTP "+r.status));
  return (j.content && j.content[0] && j.content[0].text) || "";
}

function htmlToText(html){
  return String(html||"")
    .replace(/<style[\s\S]*?<\/style>/gi,"")
    .replace(/<br\s*\/?>/gi,"\n")
    .replace(/<\/(p|div|tr|h[1-6]|li)>/gi,"\n")
    .replace(/<[^>]+>/g,"")
    .replace(/&nbsp;/gi," ").replace(/&amp;/gi,"&").replace(/&lt;/gi,"<").replace(/&gt;/gi,">")
    .replace(/\n{3,}/g,"\n\n").replace(/[ \t]{2,}/g," ").trim();
}
async function sendMail(env, to, subject, html, from){
  if(!env.RESEND_API_KEY) return false;
  try{
    const r = await fetch("https://api.resend.com/emails", {
      method:"POST",
      headers:{ "Authorization":"Bearer "+env.RESEND_API_KEY, "Content-Type":"application/json" },
      body: JSON.stringify({
        from: from || env.FROM_EMAIL || "Sky Matrix <trial@skymatrix.biz>",
        to:[to], subject, html,
        text: htmlToText(html),
        reply_to: env.REPLY_TO || "support@skymatrix.biz"
      })
    });
    return r.ok;
  }catch(e){ return false; }
}
function planLabel(plan, attr, days){
  const p = String(plan||"").toLowerCase().replace(/[^a-z0-9]/g,"");
  if(/year|annual/.test(p)) return "Yearly";
  if(p.indexOf("6")>=0 || /half|semi/.test(p)) return "6-month";
  if(/month/.test(p)) return "Monthly";
  if(/trial/.test(p)) return "Trial";
  const nm = String((attr&&(attr.variant_name||attr.product_name))||"").toLowerCase();
  if(/year|annual/.test(nm)) return "Yearly";
  if(/6|half|semi/.test(nm)) return "6-month";
  if(/month/.test(nm)) return "Monthly";
  if(days>=300) return "Yearly"; if(days>=150) return "6-month"; if(days>=25) return "Monthly"; return "Trial";
}
/* ---- extract just the readable message text from a raw MIME email (no headers / ARC-Seal / boundaries) ---- */
function b64d(s){ try{ return decodeURIComponent(escape(atob(String(s).replace(/\s+/g,"")))); }catch(e){ try{ return atob(String(s).replace(/\s+/g,"")); }catch(_){ return s; } } }
function qpd(s){ return String(s).replace(/=\r?\n/g,"").replace(/=([0-9A-Fa-f]{2})/g,function(_,h){return String.fromCharCode(parseInt(h,16));}); }
function stripHtml(h){ return String(h).replace(/<style[\s\S]*?<\/style>/gi,"").replace(/<script[\s\S]*?<\/script>/gi,"").replace(/<\/(p|div|br|tr|li|h[1-6])>/gi,"\n").replace(/<[^>]+>/g," ").replace(/&nbsp;/gi," ").replace(/&amp;/gi,"&").replace(/&lt;/gi,"<").replace(/&gt;/gi,">").replace(/&#39;|&apos;/gi,"'").replace(/&quot;/gi,'"'); }
function decodeBody(body, enc){ enc=String(enc||"").toLowerCase(); if(enc.indexOf("base64")>=0) return b64d(body); if(enc.indexOf("quoted")>=0) return qpd(body); return body; }
function emailBodyText(raw){
  var s=String(raw||""); var idx=s.search(/\r?\n\r?\n/);
  var headers = idx>=0 ? s.slice(0,idx) : ""; var body = idx>=0 ? s.slice(idx).replace(/^\r?\n\r?\n/,"") : s;
  var ct=(headers.match(/content-type:\s*([^\r\n]+)/i)||[])[1]||"";
  var boundary=(ct.match(/boundary="?([^";\r\n]+)"?/i)||[])[1];
  if(boundary){
    var parts=body.split("--"+boundary); var plain="", html="";
    for(var i=0;i<parts.length;i++){ var p=parts[i]; var ph=p.search(/\r?\n\r?\n/); if(ph<0) continue;
      var hh=p.slice(0,ph), pb=p.slice(ph).replace(/^\r?\n\r?\n/,"");
      var pct=(hh.match(/content-type:\s*([^\r\n;]+)/i)||[])[1]||""; var en=(hh.match(/content-transfer-encoding:\s*([^\r\n]+)/i)||[])[1]||"";
      pb=decodeBody(pb,en);
      if(/text\/plain/i.test(pct) && !plain) plain=pb; else if(/text\/html/i.test(pct) && !html) html=pb;
    }
    body = plain || (html?stripHtml(html):"") || body;
  } else {
    var en=(headers.match(/content-transfer-encoding:\s*([^\r\n]+)/i)||[])[1]||"";
    body=decodeBody(body,en); if(/text\/html/i.test(ct)) body=stripHtml(body);
  }
  return body.replace(/\r/g,"").replace(/[ \t]+\n/g,"\n").replace(/\n{3,}/g,"\n\n").trim().slice(0,2000);
}
function emailAddr(s){ var m=String(s||"").match(/<([^>]+@[^>]+)>/); return (m?m[1]:String(s||"")).trim(); }
/* constant-time-ish admin token check; fails closed if the secret is unset */
function tokenOk(env, req){
  const t = req.headers.get("x-admin-token")||"", k = env.ADMIN_TOKEN||"";
  if(!k || t.length!==k.length) return false;
  let out=0; for(let i=0;i<k.length;i++) out |= t.charCodeAt(i)^k.charCodeAt(i);
  return out===0;
}
// group-admin: a delegated admin scoped to ONE group, with its own token (independent of the main ADMIN_TOKEN). Returns the group id or "".
async function groupAdminGroup(env, req){
  try{ const t=(req.headers.get("x-group-token")||"").trim(); if(!t||t.length<6) return ""; const g=await env.TRIALS.get("gadmin:"+t); return g?String(g):""; }catch(e){ return ""; }
}
// the caller holds a valid, device-locked licence code (used to gate the paid AI endpoints against budget abuse)
async function licOk(env, body){
  try{ const d=((body&&body.device)||"").toUpperCase(); const c=(body&&body.code)||"";
    if(!/^SKM-[A-Z0-9]{6}$/.test(d)) return false;
    const v = await verifyLicence(env, d, c);
    if(!(v && v.ok)) return false;
    // FIX #1: an expired (but genuine) code must NOT unlock the paid AI endpoints
    if(v.expDay != null && v.expDay < Math.floor(Date.now()/86400000)) return false;
    return true;
  }catch(e){ return false; }
}
// FIX #2: per-device daily quota on the paid AI endpoints, so one valid code can't run up the Anthropic bill
const AI_DAILY_CAP = 40;
async function aiQuotaOk(env, device){
  try{
    if(!/^SKM-[A-Z0-9]{6}$/.test(device||"")) return true; // admin-token calls carry no device — not limited here
    const day = new Date().toISOString().slice(0,10);
    const k = "aicap:"+device+":"+day;
    const n = (parseInt((await env.TRIALS.get(k))||"0",10)||0);
    if(n >= AI_DAILY_CAP) return false;
    await env.TRIALS.put(k, String(n+1), {expirationTtl:60*60*48});
    return true;
  }catch(e){ return true; } // fail-open on KV error — never block a genuine user because KV hiccupped
}
// FIX #3: lightweight KV rate limiter (approximate fixed window) for the open /trial email gadget
async function rateOk(env, key, limit, windowSec){
  try{
    const k = "rl:"+key;
    const n = (parseInt((await env.TRIALS.get(k))||"0",10)||0);
    if(n >= limit) return false;
    await env.TRIALS.put(k, String(n+1), {expirationTtl:windowSec});
    return true;
  }catch(e){ return true; }
}
function codeEmailHtml(env, device, code, expDay){
  const app = env.APP_URL || "https://skymatrix.biz";
  return `<div style="font-family:Segoe UI,Arial,sans-serif;color:#1e2a44">
    <h2 style="color:#1f6dff;margin:0 0 6px">Sky Matrix — your access code</h2>
    <p style="color:#5a6b86;margin:0 0 14px">Fly informed.</p>
    <p>Here is your access code for device <b>${device}</b>. It is valid until <b>${expiryText(expDay)}</b>.</p>
    <p style="font-family:ui-monospace,Consolas,monospace;background:#f1f5fb;border:1px solid #c7d6ee;border-radius:8px;padding:12px;word-break:break-all;font-size:14px">${code}</p>
    <ol style="color:#1e2a44;line-height:1.6">
      <li>Open Sky Matrix at <a href="${app}">${app}</a>.</li>
      <li>On the lock screen, paste this code and tap <b>Activate</b>.</li>
    </ol>
    <p style="color:#5a6b86;font-size:12px">This code only works on the device it was issued for. Questions? Reply to this email or contact support@skymatrix.biz.</p>
  </div>`;
}

// FIX #4: keep a compact summary in each trial: key's KV METADATA, so the admin console can build the
// user list / mailing list from list() ALONE (1 subrequest per 1000 keys) instead of one get() per user.
function trialMeta(rec){
  const pr = rec.profile||{};
  return { e: rec.email||"", p: rec.plan||"", x: (rec.expDay!=null?rec.expDay:null),
           a: rec.at||0, s: rec.source || (rec.admin?"admin/paid":"self-trial"), g: rec.group||"", n: rec.name||"",
           pn: pr.name||"", pp: pr.position||"", pr: pr.airline||"", pc: pr.aircraft||"" };
}
async function putTrial(env, device, rec){
  try{ await env.TRIALS.put("trial:"+device, JSON.stringify(rec), {metadata: trialMeta(rec)}); }
  catch(e){ await env.TRIALS.put("trial:"+device, JSON.stringify(rec)); }
}
// Belt-and-braces one-email-per-device: if the email:->device binding is missing, scan the trial metadata to see if
// any OTHER device already carries this email (cheap: reads KV metadata from list(); legacy records capped).
async function emailUsedByOther(env, email, device){
  try{
    email=(email||"").toLowerCase(); if(!email) return "";
    let cursor, legacyGets=0;
    do{
      const list = await env.TRIALS.list({prefix:"trial:", cursor});
      for(const k of list.keys){
        const dev=k.name.slice(6); if(dev===device) continue;
        let em="";
        if(k.metadata && k.metadata.e!=null){ em=String(k.metadata.e).toLowerCase(); }
        else if(legacyGets<300){ legacyGets++; try{ em=((JSON.parse((await env.TRIALS.get(k.name))||"{}").email)||"").toLowerCase(); }catch(e){} }
        if(em && em===email) return dev;
      }
      cursor = list.list_complete ? null : list.cursor;
    } while(cursor);
  }catch(e){}
  return "";
}
async function issueTrial(env, device, email, {admin=false, days=null, plan=""} = {}){
  device = device.toUpperCase();
  if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return {ok:false, reason:"baddevice"};
  // admin grants and paid purchases AUTO-UNBLOCK the device; only a self-serve trial is refused for a blocked device
  if(admin){ try{ await unblockDevice(env, device); }catch(e){} }
  else { try{ const bl = await readBlocklist(env); if(bl.indexOf(device) >= 0) return {ok:false, reason:"blocked"}; }catch(e){} }
  // ONE email is permanently bound to ONE device; a device is locked to its first email. Only an admin (grant/delete) can change it.
  const emNorm = (email||"").trim().toLowerCase();
  if(emNorm && !admin){
    let boundDev=""; try{ boundDev = (await env.TRIALS.get("email:"+emNorm))||""; }catch(e){}
    if(!boundDev){ const other = await emailUsedByOther(env, emNorm, device); if(other){ boundDev=other; try{ await env.TRIALS.put("email:"+emNorm, other); }catch(e){} } }  // heal a missing binding so one email can't slip onto a 2nd device
    if(boundDev && boundDev !== device) return {ok:false, reason:"email_taken"};        // email already used on another device
    try{ const prior = await env.TRIALS.get("trial:"+device); if(prior){ const pe=((JSON.parse(prior).email)||"").toLowerCase(); if(pe && pe!==emNorm) return {ok:false, reason:"email_locked"}; } }catch(e){}
  }
  let d = parseInt(days || env.TRIAL_DAYS || "10", 10) || 10;
  d = Math.max(1, Math.min(3650, d));   // clamp: never negative/past-dated, max ~10 years
  // one trial per device (unless admin override)
  if(!admin){
    const prior = await env.TRIALS.get("trial:"+device);
    if(prior) return {ok:false, reason:"used"};
  }
  const { code, expDay } = await signCode(env, device, d);
  const rec = { email: email||"", expDay, at: Date.now(), admin: !!admin, plan: plan || planLabel("", null, d), source: admin?"admin/paid":"self-trial" };
  await putTrial(env, device, rec);
  if(emNorm){ try{ await env.TRIALS.put("email:"+emNorm, device); }catch(e){} }   // bind (or admin-rebind) email -> device
  if(email) await sendMail(env, email, "Sky Matrix — your access code", codeEmailHtml(env, device, code, expDay));
  return {ok:true, code, expDay, days:d};
}

/* ---- usage counters for your paid services (AI + FR24), so the admin console can show consumption ---- */
function ymNow(){ const d=new Date(); return d.getUTCFullYear()+"-"+String(d.getUTCMonth()+1).padStart(2,"0"); }
async function bumpUse(env, svc){
  try{
    const tk="use:"+svc+":total", mk="use:"+svc+":"+ymNow();
    const t=(parseInt((await env.TRIALS.get(tk))||"0",10)||0)+1;
    const m=(parseInt((await env.TRIALS.get(mk))||"0",10)||0)+1;
    await env.TRIALS.put(tk,String(t)); await env.TRIALS.put(mk,String(m));
  }catch(e){}
}
function track(ctx, env, svc){ if(ctx&&ctx.waitUntil) ctx.waitUntil(bumpUse(env,svc)); }
function he(s){ return String(s==null?"":s).replace(/[&<>]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;"}[c]; }); }

/* ---- device blocklist (used to revoke a licence on refund) ---- */
async function readBlocklist(env){ try{ const s = await env.TRIALS.get("blocklist"); const a = s?JSON.parse(s):[]; return Array.isArray(a)?a:[]; }catch(e){ return []; } }
async function blockDevice(env, device){ const a = await readBlocklist(env); if(a.indexOf(device)<0){ a.push(device); await env.TRIALS.put("blocklist", JSON.stringify(a.slice(-5000))); } }
async function unblockDevice(env, device){ const a = await readBlocklist(env); const i=a.indexOf(device); if(i>=0){ a.splice(i,1); await env.TRIALS.put("blocklist", JSON.stringify(a)); } }

/* ---- Lemon Squeezy helpers ---- */
// map the numeric LS product IDs to Sky Matrix licence lengths; anything else (e.g. Matrix Budget) is NOT a Sky Matrix licence
const LEMON_PRODUCT_DAYS = { "1217047":31, "1902874":186, "1902963":366 };
const LEMON_BUDGET_PRODUCT = "1217197";
function hexEq(a,b){ if(a.length!==b.length) return false; let o=0; for(let i=0;i<a.length;i++) o|=a.charCodeAt(i)^b.charCodeAt(i); return o===0; }
async function lemonVerify(env, raw, sig){
  const secret = env.LEMON_WEBHOOK_SECRET; if(!secret || !sig) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), {name:"HMAC", hash:"SHA-256"}, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(raw));
  const hex = [...new Uint8Array(mac)].map(b=>b.toString(16).padStart(2,"0")).join("");
  return hexEq(hex, sig.trim().toLowerCase());
}
const PLAN_DAYS = { monthly:31, month:31, half:186, halfyearly:186, sixmonth:186, "6month":186, semiannual:186, yearly:366, year:366, annual:366, annually:366 };
function planDays(plan, attr){
  const p = String(plan||"").toLowerCase().replace(/[^a-z0-9]/g,"");
  if(PLAN_DAYS[p]) return PLAN_DAYS[p];
  const nm = String((attr&&(attr.variant_name||attr.product_name))||"").toLowerCase();
  if(/year|annual/.test(nm)) return 366;
  if(/6|half|semi/.test(nm)) return 186;
  if(/month/.test(nm)) return 31;
  return 31; // safe default
}

export default {
  async fetch(request, env, ctx){
    const url = new URL(request.url);
    if(request.method === "OPTIONS") return new Response(null, {headers: CORS});
    // deploy check: open /version in a browser to confirm the latest code is live
    if(url.pathname === "/version"){ return json({ok:true, version:"2026-07-15-batch9T", features:["pilot-profile","group-admin","subadmin","ofp-navlog-detail","email-metadata-scan","device-name","block-nondestructive","admin-grant-auto-unblock","grant-error-check","services","usage-counters","cron-reminders","admin-delete","blocked-clears-on-unblock","email-one-device-lock","admin-lookup","delete-revokes","app-register","reviews","checklist-ai","admin-pushdoc","pusheddocs","mycode","grant-email-required","ofp-navlog","mycode-email-required","ai-licence-gated","pusheddocs-expiry","wx-proxy","ofp-learn","user-groups","mycode-one-device","email-text-replyto","ai-expiry-gate","ai-daily-quota","trial-ratelimit","mail-index-metadata","mail-truthful-total","lemon-product-whitelist","webhook-idempotent","mailtrial-ratelimit","ofp-learn-dedupe","ofp-autolearn-all","ofp-feed"]}); }
    try{

    // ---- public web-form trial ----
    if(url.pathname === "/trial" && request.method === "POST"){
      let body={}; try{ body = await request.json(); }catch(e){}
      const device = (body.device||"").trim().toUpperCase();
      const email  = (body.email||"").trim();
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"Enter a valid Device ID (looks like SKM-XXXXXX)."}, 400);
      if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ok:false, error:"Enter a valid email address."}, 400);
      // FIX #3: rate-limit by client IP and by target email so /trial can't be used to email-bomb or drain the Resend quota
      const _ip = request.headers.get("CF-Connecting-IP") || "0";
      if(!(await rateOk(env, "trial-ip:"+_ip, 5, 3600))) return json({ok:false, error:"Too many trial requests from here. Please wait a while and try again."}, 429);
      if(!(await rateOk(env, "trial-em:"+email.toLowerCase(), 3, 86400))) return json({ok:false, error:"Several trial codes have already been sent to this email. Check your inbox/junk, or contact support@skymatrix.biz."}, 429);
      const r = await issueTrial(env, device, email);
      if(!r.ok && r.reason==="email_taken") return json({ok:false, error:"This email is already registered to another device. Use that device, or contact support@skymatrix.biz to move your licence."}, 409);
      if(!r.ok && r.reason==="email_locked") return json({ok:false, error:"This device is already registered to a different email. Contact support@skymatrix.biz to change it."}, 409);
      if(!r.ok && r.reason==="used") return json({ok:false, error:"This device has already used its free trial. Contact support@skymatrix.biz to subscribe or request more time."}, 409);
      if(!r.ok) return json({ok:false, error:"Could not issue a trial. Check the Device ID."}, 400);
      return json({ok:true, code:r.code, expiry: expiryText(r.expDay), days:r.days});
    }

    // ---- admin: grant an extra trial / any-length code to a device (bypasses one-per-device) ----
    if(url.pathname === "/admin/grant" && request.method === "POST"){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      let body={}; try{ body = await request.json(); }catch(e){}
      const device = (body.device||"").trim().toUpperCase();
      const days = body.days ? parseInt(body.days,10) : null;
      const email = (body.email||"").trim() || null;
      const plan = (body.plan||"").toString().trim() || null;
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"bad device"}, 400);
      if(!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ok:false, error:"A valid email address is required to grant a licence."}, 400);
      const r = await issueTrial(env, device, email, {admin:true, days, plan: plan || planLabel(plan||"", null, days||10)});
      if(!r.ok) return json({ok:false, error:"could not grant ("+(r.reason||"error")+")"}, 400);
      return json({ok:true, code:r.code, expiry: expiryText(r.expDay), days:r.days, emailed: !!email});
    }

    // ---- admin: clear a device's trial record so it can self-serve again ----
    if(url.pathname === "/admin/reset" && request.method === "POST"){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      let body={}; try{ body = await request.json(); }catch(e){}
      const device = (body.device||"").trim().toUpperCase();
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"bad device"}, 400);
      await env.TRIALS.delete("trial:"+device);
      return json({ok:true});
    }

    // ---- admin: manually block (revoke) a device's access; the app checks /blocked at launch ----
    if(url.pathname === "/admin/block" && request.method === "POST"){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      let body={}; try{ body = await request.json(); }catch(e){}
      const device = (body.device||"").trim().toUpperCase();
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"bad device"}, 400);
      await blockDevice(env, device); // block only — keep the trial record so Unblock fully restores the user and they stay in the list
      return json({ok:true, blocked:true, device, blocklist:(await readBlocklist(env))});
    }
    // ---- admin: service/subscription tracker (your own paid services: AI API, FR24, hosting, etc.) + live usage counters ----
    if(url.pathname === "/admin/services" && (request.method === "GET" || request.method === "POST")){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      if(request.method === "POST"){
        let body={}; try{ body = await request.json(); }catch(e){}
        const list = Array.isArray(body.services) ? body.services.slice(0,60) : [];
        try{ await env.TRIALS.put("svc:list", JSON.stringify(list)); }catch(e){}
        return json({ok:true, services:list});
      }
      let services=[]; try{ services = JSON.parse((await env.TRIALS.get("svc:list"))||"[]"); }catch(e){}
      const gi = async (k)=> (parseInt((await env.TRIALS.get(k))||"0",10)||0);
      const mo = ymNow();
      const usage = {
        month: mo,
        ai:   { total: await gi("use:ai:total"),   month: await gi("use:ai:"+mo) },
        fr24: { total: await gi("use:fr24:total"), month: await gi("use:fr24:"+mo) }
      };
      return json({ok:true, services, usage});
    }
    // ---- app self-registration: any device that runs the app online records itself (even offline-code ones), so it shows in the admin list ----
    if(url.pathname === "/register" && request.method === "POST"){
      let body={}; try{ body = await request.json(); }catch(e){}
      const device = (body.device||"").trim().toUpperCase();
      const email  = (body.email||"").trim().toLowerCase();
      const code   = (body.code||"").toString();
      const name   = (body.name||"").toString().replace(/[<>]/g,"").slice(0,40).trim();   // user-chosen device name
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"bad device"}, 400);
      const v = await verifyLicence(env, device, code);
      if(!v.ok) return json({ok:false, error:"invalid code"}, 400);   // only record devices holding a genuine signed code
      const existing = await env.TRIALS.get("trial:"+device);
      if(!existing){
        await putTrial(env, device, { email:email||"", expDay:v.expDay, at:Date.now(), admin:false, plan:"External code", source:"app", seen:Date.now(), name:name||"" });
      } else {
        try{ const r=JSON.parse(existing); r.seen=Date.now(); if(email && !r.email) r.email=email; if(name) r.name=name; await putTrial(env, device, r); }catch(e){}
      }
      if(email){ try{ const ek="email:"+email; if(!(await env.TRIALS.get(ek))) await env.TRIALS.put(ek, device); }catch(e){} }
      return json({ok:true});
    }
    // ---- app: save the pilot PROFILE (name once + position/airline/aircraft) — required to use the app; stored for the admin ----
    if(url.pathname === "/profile" && request.method === "POST"){
      let body={}; try{ body = await request.json(); }catch(e){}
      const device=(body.device||"").trim().toUpperCase(); const code=(body.code||"").toString();
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"bad device"}, 400);
      const v=await verifyLicence(env, device, code); if(!v.ok) return json({ok:false, error:"invalid code"}, 403);
      const clean=function(s,n){ return (s||"").toString().replace(/[<>]/g,"").slice(0,n).trim(); };
      const name=clean(body.name,60), position=clean(body.position,40), airline=clean(body.airline,60), aircraft=clean(body.aircraft,40);
      let rec={}; try{ rec=JSON.parse((await env.TRIALS.get("trial:"+device))||"{}"); }catch(e){}
      rec.profile=rec.profile||{};
      if(name && !rec.profile.name) rec.profile.name=name;   // pilot name is set ONCE (immutable thereafter)
      if(position) rec.profile.position=position; if(airline) rec.profile.airline=airline; if(aircraft) rec.profile.aircraft=aircraft;
      rec.seen=Date.now(); if(rec.expDay==null)rec.expDay=v.expDay; if(rec.at==null)rec.at=Date.now();
      await putTrial(env, device, rec);
      return json({ok:true, profile:rec.profile});
    }
    // ---- admin: look up a single user by Device ID or email ----
    if(url.pathname === "/admin/lookup" && request.method === "GET"){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      let device = (url.searchParams.get("device")||"").trim().toUpperCase();
      const email = (url.searchParams.get("email")||"").trim().toLowerCase();
      if(!device && email){ try{ device = ((await env.TRIALS.get("email:"+email))||"").toUpperCase(); }catch(e){} }
      if(!device) return json({ok:true, found:false, reason: email ? "No device is registered to that email." : "Provide a Device ID or email."});
      let rec=null; try{ const r=await env.TRIALS.get("trial:"+device); if(r)rec=JSON.parse(r); }catch(e){}
      const bl = await readBlocklist(env); const blocked = bl.indexOf(device)>=0;
      if(!rec) return json({ok:true, found:false, device, blocked, note:"No server record — this device is likely running an offline License-Manager code, or was never issued a Worker licence."});
      const nowDay = Math.floor(Date.now()/86400000);
      return json({ok:true, found:true, device, email:rec.email||"", plan:rec.plan||"",
        start: rec.at?new Date(rec.at).toISOString().slice(0,10):"",
        end: rec.expDay?new Date(rec.expDay*86400000).toISOString().slice(0,10):"",
        daysLeft: rec.expDay!=null?(rec.expDay-nowDay):null,
        active: rec.expDay!=null?(rec.expDay>=nowDay):false,
        source: rec.source || (rec.admin?"admin/paid":"self-trial"), blocked});
    }
    // ---- admin: permanently delete a device (erase email/licence record + unblock = fresh start) ----
    if(url.pathname === "/admin/delete" && request.method === "POST"){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      let body={}; try{ body = await request.json(); }catch(e){}
      const device = (body.device||"").trim().toUpperCase();
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"bad device"}, 400);
      let _em=""; try{ _em=((JSON.parse((await env.TRIALS.get("trial:"+device))||"{}").email)||"").toLowerCase(); }catch(e){}
      await env.TRIALS.delete("trial:"+device);   // erase email, expiry, plan
      if(_em){ try{ await env.TRIALS.delete("email:"+_em); }catch(e){} }   // free the email
      await blockDevice(env, device);             // AND revoke access: block the device so it's cut off at next online launch
      return json({ok:true, deleted:true, blocked:true, device});
    }
    // ---- admin: unblock (restore) a device ----
    if(url.pathname === "/admin/unblock" && request.method === "POST"){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      let body={}; try{ body = await request.json(); }catch(e){}
      const device = (body.device||"").trim().toUpperCase();
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"bad device"}, 400);
      await unblockDevice(env, device);
      return json({ok:true, blocked:false, device, blocklist:(await readBlocklist(env))});
    }

    // ---- admin: list every user (device, email, plan, start/end, status, blocked) ----
    if(url.pathname === "/admin/users" && request.method === "GET"){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      const bl = await readBlocklist(env);
      const nowDay = Math.floor(Date.now()/86400000);
      const users = []; let cursor;
      let legacyGets = 0;
      do{
        const list = await env.TRIALS.list({prefix:"trial:", cursor});
        for(const k of list.keys){
          const dev = k.name.slice(6);
          let rec;
          // FIX #4: prefer the compact summary stored in KV metadata (no per-user read). Only fall back to a
          // get() for legacy records written before metadata existed, and cap those so we never blow the
          // Workers subrequest limit on a very large, un-migrated dataset.
          if(k.metadata){ const md=k.metadata; rec={ email:md.e, plan:md.p, expDay:(md.x!=null?md.x:null), at:md.a, source:md.s, group:md.g, name:md.n, profile:{name:md.pn||"",position:md.pp||"",airline:md.pr||"",aircraft:md.pc||""} }; }
          else if(legacyGets < 800){ legacyGets++; try{ rec = JSON.parse((await env.TRIALS.get(k.name))||"{}"); }catch(e){ rec={}; } }
          else { rec = { _partial:true }; }
          const end = rec.expDay ? new Date(rec.expDay*86400000).toISOString().slice(0,10) : "";
          const pr = rec.profile||{};
          users.push({
            device: dev, email: rec.email||"", plan: rec.plan||"", name: rec.name||"",
            pilot: pr.name||"", position: pr.position||"", airline: pr.airline||"", aircraft: pr.aircraft||"",
            start: rec.at ? new Date(rec.at).toISOString().slice(0,10) : "",
            end, daysLeft: (rec.expDay!=null) ? (rec.expDay-nowDay) : null,
            active: (rec.expDay!=null) ? (rec.expDay>=nowDay) : false,
            source: rec.source || (rec.admin ? "admin/paid" : "self-trial"),
            group: rec.group || "",
            blocked: bl.indexOf(dev)>=0
          });
        }
        cursor = list.list_complete ? null : list.cursor;
      } while(cursor);
      bl.forEach(function(dev){ if(!users.some(function(u){return u.device===dev;})) users.push({device:dev, email:"", plan:"", start:"", end:"", daysLeft:null, active:false, source:"", blocked:true}); });
      users.sort(function(a,b){ return (a.end<b.end?1:a.end>b.end?-1:0); });
      const activeN = users.filter(function(u){return u.active&&!u.blocked;}).length;
      const blockedN = users.filter(function(u){return u.blocked;}).length;
      return json({ok:true, count:users.length, active:activeN, blocked:blockedN, users});
    }

    // ---- admin: email one / many / all users (from support@ or admin@) ----
    if(url.pathname === "/admin/mail" && request.method === "POST"){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      let body={}; try{ body = await request.json(); }catch(e){}
      const subject = (body.subject||"").toString().slice(0,200).trim();
      const html    = (body.html||body.message||"").toString().slice(0,20000).trim();
      if(!subject || !html) return json({ok:false, error:"subject and message are required"}, 400);
      const from = (String(body.from||"support").toLowerCase().indexOf("admin")>=0)
        ? "Sky Matrix <admin@skymatrix.biz>" : "Sky Matrix Support <support@skymatrix.biz>";
      let emails = [];
      if(Array.isArray(body.to)){ emails = body.to.map(function(x){return String(x||"").trim();}); }
      else {
        const sel = String(body.to||"all").toLowerCase();
        const bl = await readBlocklist(env); const nowDay=Math.floor(Date.now()/86400000);
        let cursor, legacyGets=0;
        do{
          const list = await env.TRIALS.list({prefix:"trial:", cursor});
          for(const k of list.keys){
            // FIX #4: read the recipient's email/expiry from KV metadata (no per-user get); legacy fallback capped
            let rec;
            if(k.metadata){ const md=k.metadata; rec={ email:md.e, expDay:(md.x!=null?md.x:null) }; }
            else if(legacyGets < 400){ legacyGets++; try{ rec=JSON.parse((await env.TRIALS.get(k.name))||"{}"); }catch(e){ rec={}; } }
            else { continue; }
            if(!rec.email) continue;
            const dev=k.name.slice(6), active=(rec.expDay!=null)?(rec.expDay>=nowDay):false, blocked=bl.indexOf(dev)>=0;
            if(sel==="all" || (sel==="active"&&active&&!blocked) || (sel==="blocked"&&blocked)) emails.push(rec.email);
          }
          cursor = list.list_complete ? null : list.cursor;
        } while(cursor);
      }
      emails = Array.from(new Set(emails.filter(function(e){return /.@.+\..+/.test(e);})));
      if(!emails.length) return json({ok:false, error:"no valid recipients"}, 400);
      // FIX #5: send across the WHOLE list (no silent 95 cap) within the subrequest budget, and report the
      // true intended total + whether this run was capped, so "email all" can never silently drop recipients.
      const MAIL_CAP = 500;
      const intended = emails.length;
      const batch = emails.slice(0, MAIL_CAP);
      let sent=0, failed=0;
      for(const e of batch){ const ok = await sendMail(env, e, subject, html, from); if(ok)sent++; else failed++; }
      return json({ok:true, sent, failed, total:intended, capped: intended>MAIL_CAP, remaining: Math.max(0, intended-MAIL_CAP)});
    }

    // ---- public: submit a review — ONLY genuine users (valid licence code) can review; email is never collected ----
    if(url.pathname === "/review" && request.method === "POST"){
      let body={}; try{ body = await request.json(); }catch(e){}
      const device = (body.device||"").trim().toUpperCase();
      const code   = (body.code||"").toString();
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"Enter your Device ID (looks like SKM-XXXXXX)."}, 400);
      const v = await verifyLicence(env, device, code);
      if(!v.ok) return json({ok:false, error:"Could not verify you as a Sky Matrix user. Only pilots who have used the app (trial or subscription) can review. Check your Device ID and access code."}, 403);
      const position = (body.position||"").toString().slice(0,60).trim();
      const airline  = (body.airline||"").toString().slice(0,80).trim();
      const name     = (body.name||"").toString().slice(0,60).trim();
      const comment  = (body.comment||"").toString().slice(0,1000).trim();
      const rating   = Math.max(0, Math.min(5, parseInt(body.rating,10)||0));
      if(comment.length < 3) return json({ok:false, error:"Please write a short comment."}, 400);
      // one review per device (re-submitting edits it); starts as pending until you approve it in the admin console
      try{ await env.TRIALS.put("rev:"+device, JSON.stringify({ position, airline, name, comment, rating, at:Date.now(), approved:false })); }catch(e){}
      return json({ok:true});
    }
    // ---- public: list APPROVED reviews for the website (no email, no device ID) ----
    if(url.pathname === "/reviews" && request.method === "GET"){
      const out=[]; let cursor;
      do{
        const list = await env.TRIALS.list({prefix:"rev:", cursor});
        for(const k of list.keys){ let r={}; try{ r=JSON.parse((await env.TRIALS.get(k.name))||"{}"); }catch(e){}
          if(r.approved) out.push({ position:r.position||"", airline:r.airline||"", name:r.name||"", comment:r.comment||"", rating:r.rating||0, at:r.at||0 }); }
        cursor = list.list_complete ? null : list.cursor;
      } while(cursor);
      out.sort(function(a,b){ return (b.at||0)-(a.at||0); });
      return json({ok:true, reviews: out.slice(0,300)});
    }
    // ---- admin: moderate reviews (list all + approve / hide / delete) ----
    if(url.pathname === "/admin/reviews" && (request.method === "GET" || request.method === "POST")){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      if(request.method === "POST"){
        let body={}; try{ body = await request.json(); }catch(e){}
        const id = (body.id||"").toString(); const action = (body.action||"").toString();
        if(id.indexOf("rev:")!==0) return json({ok:false, error:"bad id"}, 400);
        if(action==="delete"){ try{ await env.TRIALS.delete(id); }catch(e){} return json({ok:true}); }
        let r={}; try{ r=JSON.parse((await env.TRIALS.get(id))||"{}"); }catch(e){}
        r.approved = (action==="approve");
        try{ await env.TRIALS.put(id, JSON.stringify(r)); }catch(e){}
        return json({ok:true, approved:r.approved});
      }
      const out=[]; let cursor;
      do{
        const list = await env.TRIALS.list({prefix:"rev:", cursor});
        for(const k of list.keys){ let r={}; try{ r=JSON.parse((await env.TRIALS.get(k.name))||"{}"); }catch(e){}
          out.push({ id:k.name, device:k.name.slice(4), position:r.position||"", airline:r.airline||"", name:r.name||"", comment:r.comment||"", rating:r.rating||0, at:r.at||0, approved:!!r.approved }); }
        cursor = list.list_complete ? null : list.cursor;
      } while(cursor);
      out.sort(function(a,b){ return (b.at||0)-(a.at||0); });
      return json({ok:true, reviews: out});
    }
    // ---- feedback intake from the app (no auth) ----
    if(url.pathname === "/feedback" && request.method === "POST"){
      let body={}; try{ body = await request.json(); }catch(e){}
      const msg = (body.message||"").toString().slice(0,4000).trim();
      if(msg.length < 2) return json({ok:false, error:"empty"}, 400);
      const rec = { from:(body.email||"").toString().slice(0,120), device:(body.device||"").toString().slice(0,20), subject:(body.subject||"App feedback").toString().slice(0,140), body:msg, at:Date.now(), via:"app" };
      try{ await env.TRIALS.put("fb:"+Date.now()+":"+Math.random().toString(36).slice(2,7), JSON.stringify(rec), {expirationTtl:60*60*24*365}); }catch(e){}
      return json({ok:true});
    }
    // ---- admin: read / clear the feedback + correspondence inbox ----
    if(url.pathname === "/admin/feedback" && (request.method === "GET" || request.method === "DELETE")){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      if(request.method === "DELETE"){
        const id = url.searchParams.get("id")||"";
        if(id.indexOf("fb:")===0){ try{ await env.TRIALS.delete(id); }catch(e){} return json({ok:true}); }
        return json({ok:false, error:"bad id"}, 400);
      }
      const items=[]; let cursor;
      do{
        const list = await env.TRIALS.list({prefix:"fb:", cursor});
        for(const k of list.keys){ let rec={}; try{ rec=JSON.parse((await env.TRIALS.get(k.name))||"{}"); }catch(e){} rec.id=k.name; items.push(rec); }
        cursor = list.list_complete ? null : list.cursor;
      } while(cursor);
      items.sort(function(a,b){ return (b.at||0)-(a.at||0); });
      return json({ok:true, feedback: items.slice(0,300)});
    }

    // ---- Lemon Squeezy payment webhook: on a successful payment, issue a device-locked licence ----
    if(url.pathname === "/lemon/webhook" && request.method === "POST"){
      const raw = await request.text();
      const sig = request.headers.get("X-Signature") || "";
      if(!(await lemonVerify(env, raw, sig))) return json({ok:false, error:"bad signature"}, 401);
      let evt={}; try{ evt = JSON.parse(raw); }catch(e){ return json({ok:false, error:"bad json"}, 400); }
      const name = (evt.meta && evt.meta.event_name) || "";
      const cd   = (evt.meta && evt.meta.custom_data) || {};
      const attr = (evt.data && evt.data.attributes) || {};
      const orderId = String((evt.data && evt.data.id) || attr.order_id || "");
      // first payment + renewals + one-time orders all grant/extend a licence
      if(name==="subscription_payment_success" || name==="subscription_created" || name==="order_created"){
        const device = String(cd.device_id||"").trim().toUpperCase();
        const email  = String(cd.email || attr.user_email || "").trim();
        // identify the product bought via its numeric LS product id
        const aitem = attr.first_order_item || {};
        const productId = String(attr.product_id || aitem.product_id || "");
        // Matrix Budget (and any non-Sky-Matrix product) must NEVER issue a Sky Matrix licence code
        if(productId === LEMON_BUDGET_PRODUCT) return json({ok:true});
        // FIX #6: only KNOWN Sky Matrix products issue a licence. Fall back to an explicit recognized plan in
        // custom_data if the product id is absent, but NEVER default-issue to an unknown/future product.
        let days = LEMON_PRODUCT_DAYS[productId];
        if(!days){
          const _p = String(cd.plan||"").toLowerCase().replace(/[^a-z0-9]/g,"");
          days = PLAN_DAYS[_p] || 0;
        }
        if(!days) return json({ok:true}); // unrecognized product AND no known plan -> acknowledge, issue nothing
        // FIX #11: idempotency — Lemon may re-deliver the same event. If we've already processed this order id, skip re-issuing/re-emailing.
        if(orderId){ try{ if(await env.TRIALS.get("order:"+orderId)) return json({ok:true, dup:true}); }catch(e){} }
        const plan   = planLabel(cd.plan, attr, days);
        if(/^SKM-[A-Z0-9]{6}$/.test(device)){
          await issueTrial(env, device, email||null, {admin:true, days, plan});
          if(orderId){ try{ await env.TRIALS.put("order:"+orderId, device); }catch(e){} }
          await unblockDevice(env, device); // clear any prior refund block on a fresh purchase
        }
      // refund → revoke the licence for that device (7-day money-back etc.)
      } else if(name==="order_refunded" || name==="subscription_payment_refunded" || name==="refund_created"){
        let device = String(cd.device_id||"").trim().toUpperCase();
        if(!/^SKM-[A-Z0-9]{6}$/.test(device) && orderId){ try{ device = String((await env.TRIALS.get("order:"+orderId))||"").toUpperCase(); }catch(e){} }
        if(/^SKM-[A-Z0-9]{6}$/.test(device)){
          await blockDevice(env, device); // keep the record (shows as blocked in the console); a re-purchase auto-unblocks
        }
      }
      return json({ok:true}); // always 200 so LS doesn't keep retrying
    }

    // ---- published device blocklist (app checks this at launch; refunds add to it automatically) ----
    if(url.pathname === "/blocked" && request.method === "GET"){
      return json(await readBlocklist(env));
    }

    // ---- AI OFP reader: extract structured data from OFP text; self-improves via KV corrections ----
    if(url.pathname === "/ofp/parse" && request.method === "POST"){
      if(!env.ANTHROPIC_API_KEY) return json({ok:false, error:"AI OFP reader not configured yet."}, 503);
      let body={}; try{ body = await request.json(); }catch(e){}
      if(!(await licOk(env, body)) && !tokenOk(env, request)) return json({ok:false, error:"This feature needs an active Sky Matrix licence."}, 403);
      if(!tokenOk(env, request) && !(await aiQuotaOk(env, ((body.device)||"").toUpperCase()))) return json({ok:false, error:"Daily AI limit reached for this device. Please try again tomorrow, or contact support@skymatrix.biz."}, 429);
      track(ctx, env, "ai");
      let text = (body.text||"").toString();
      const images = Array.isArray(body.images) ? body.images.filter(function(x){return typeof x==="string" && x.length;}).slice(0,14) : [];
      if(text.length > 90000) text = text.slice(0, 90000);
      if(images.length===0 && text.trim().length < 40) return json({ok:false, error:"No OFP supplied."}, 400);
      let learned=""; try{ const ex = await env.TRIALS.get("ofp:examples"); if(ex) learned = "\n\nLearned corrections from earlier OFPs (apply the same reading to similar layouts):\n"+ex; }catch(e){}
      // OFPs are visual multi-column documents — reading the PAGE IMAGES avoids the label/value scrambling that plain text extraction causes
      let content;
      if(images.length){
        content = [{type:"text", text:"Read this Operational Flight Plan and return the JSON. The page IMAGES are the authoritative source; any text below is a secondary, possibly-scrambled extraction of the same pages — prefer the images when they disagree."}];
        images.forEach(function(b){ content.push({type:"image", source:{type:"base64", media_type:"image/jpeg", data:b}}); });
        content.push({type:"text", text:"SECONDARY TEXT EXTRACTION (full document text — use it to cross-check the images and to find sections that fell outside the selected page images, e.g. the navigation log OAT at top of climb, the ETOPS/EDTO summary, route distance, and weather):\n"+text});
      } else {
        content = "OFP TEXT:\n"+text;
      }
      let out;
      // dense, varied OFP layouts — use the stronger Sonnet (vision) model + more output room for accuracy
      try{ out = await anthropic(env, OFP_SYSTEM + learned, content, {model:"claude-sonnet-4-6", max_tokens:8000, temperature:0}); }
      catch(e){ return json({ok:false, error:"AI parse failed: "+e.message}, 502); }
      let data=null;
      try{
        let s = out.replace(/```json/gi,"").replace(/```/g,"").trim();
        const a = s.indexOf("{"); if(a>0) s = s.slice(a);
        try{ data = JSON.parse(s); }
        catch(e1){
          // repair a truncated JSON: drop the trailing partial token, then close open strings / brackets
          let t = s.replace(/,\s*"[^"]*"\s*:\s*[^,{}\[\]]*$/,"").replace(/,\s*[^,{}\[\]]*$/,"");
          let inStr=false, escp=false, stack=[];
          for(let i=0;i<t.length;i++){ const c=t[i];
            if(escp){escp=false;continue;} if(c==="\\"){escp=true;continue;}
            if(c==='"'){inStr=!inStr;continue;} if(inStr)continue;
            if(c==="{")stack.push("}"); else if(c==="[")stack.push("]");
            else if(c==="}"||c==="]")stack.pop();
          }
          if(inStr)t+='"';
          while(stack.length)t+=stack.pop();
          data = JSON.parse(t);
        }
      }catch(e){ return json({ok:false, error:"AI returned unparseable output.", raw: out.slice(-300)}, 502); }
      // AUTO-LEARN (silent, ALL registered devices): every successful parse is from a valid licence or admin (the gate
      // above enforces this), so learn a format rule from each NEW airline in the background — the reader improves with
      // every flight plan any pilot uploads. Per-device daily cap + first-upload-wins keep it cheap and poison-resistant.
      try{ ctx.waitUntil(autoLearnFromOfp(env, text, data, ((body.device)||"").toUpperCase())); }catch(e){}
      return json({ok:true, data});
    }
    // ---- lightweight learning feed: an airline read WITHOUT the AI (e.g. Qatar, parsed offline) still contributes to
    // the AI's learning — cheaply. The server only calls the model to learn a NEW airline; a known airline is a no-op. ----
    if(url.pathname === "/ofp/feed" && request.method === "POST"){
      let body={}; try{ body = await request.json(); }catch(e){}
      if(!(await licOk(env, body)) && !tokenOk(env, request)) return json({ok:false, error:"This feature needs an active Sky Matrix licence."}, 403);
      const text = (body.text||"").toString();
      const airline = (body.airline||"").toString().replace(/[^A-Za-z0-9]/g,"").slice(0,20);
      ctx.waitUntil(autoLearnFromOfp(env, text, {fltCs:airline}, ((body.device)||"").toUpperCase()));
      return json({ok:true});
    }
    // ---- self-improvement: remember a pilot's correction and feed it back to future parses ----
    if(url.pathname === "/ofp/correct" && request.method === "POST"){
      // admin-only: corrections are fed into every future /ofp/parse prompt, so keep this curated
      // (prevents anyone from poisoning the shared AI context). Pass the admin token to add a correction.
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      let body={}; try{ body = await request.json(); }catch(e){}
      const note = (body.note||"").toString().replace(/\s+/g," ").slice(0,300);
      if(!note) return json({ok:false, error:"empty note"}, 400);
      let cur=""; try{ cur = (await env.TRIALS.get("ofp:examples"))||""; }catch(e){}
      cur = mergeOfpExamples(cur, note);   // supersede same airline+field, dedupe, keep newest 60
      try{ await env.TRIALS.put("ofp:examples", cur); }catch(e){}
      return json({ok:true});
    }
    // ---- admin: UPLOAD an OFP to teach the AI a new airline. The AI derives a concise format hint from the OFP text and stores it in the correction library. ----
    if(url.pathname === "/ofp/learn" && request.method === "POST"){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      if(!env.ANTHROPIC_API_KEY) return json({ok:false, error:"AI not configured yet."}, 503);
      track(ctx, env, "ai");
      let body={}; try{ body = await request.json(); }catch(e){}
      const text = (body.text||"").toString().slice(0, 14000);
      const airline = (body.airline||"").toString().replace(/[^\w \-\/]/g,"").slice(0,60);
      if(text.trim().length < 40) return json({ok:false, error:"Could not read enough OFP text to learn from."}, 400);
      const sys = "You are teaching an OFP parser to read a new airline's flight-plan layout. From the OFP text, write ONE concise line (max 240 characters) that helps a parser read THIS airline's format in future. Include: how to RECOGNISE this airline/format (callsign prefix, registration prefix, or a distinctive label); and the EXACT labels this OFP uses for registration, dep/dest, ZFW & max ZFW, take-off & max take-off weight, landing & max landing weight, trip / taxi / alternate / reserve / block(ramp) fuel, trip & block time, cost index, cruise level, and WHERE the route string is printed. Note if fuel is zero-padded or in tonnes, and if times are decimal HH.MM. Begin with: For \""+(airline||"this")+"\" OFPs. Return ONLY that single line, no preamble, no code fences.";
      let out; try{ out = await anthropic(env, sys, "OFP TEXT:\n"+text, {max_tokens:400, temperature:0}); }
      catch(e){ return json({ok:false, error:"AI failed: "+e.message}, 502); }
      const note = out.replace(/```/g,"").replace(/\s+/g," ").trim().slice(0,300);
      if(!note) return json({ok:false, error:"The AI could not summarise this OFP's format."}, 502);
      let cur=""; try{ cur = (await env.TRIALS.get("ofp:examples"))||""; }catch(e){}
      cur = mergeOfpExamples(cur, note, true);   // airline-level: one format rule per airline
      try{ await env.TRIALS.put("ofp:examples", cur); }catch(e){}
      return json({ok:true, note});
    }
    // ---- admin: view / replace the correction library that feeds every OFP read ----
    if(url.pathname === "/ofp/examples" && (request.method === "GET" || request.method === "POST")){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      if(request.method === "POST"){ // replace the whole library (used to delete/edit entries)
        let body={}; try{ body = await request.json(); }catch(e){}
        const list = (body.examples||"").toString().split("\n").map(function(s){return s.replace(/^\s*-\s*/,"").trim();}).filter(Boolean);
        let cur=""; list.forEach(function(s){ cur = mergeOfpExamples(cur, s); });   // dedupe/supersede the edited library too
        try{ await env.TRIALS.put("ofp:examples", cur); }catch(e){}
        return json({ok:true, examples: cur});
      }
      let cur=""; try{ cur = (await env.TRIALS.get("ofp:examples"))||""; }catch(e){}
      return json({ok:true, examples: cur});
    }

    // ---- Flightradar24 proxy: keeps the paid FR24 token server-side (app can't call FR24 directly: key + CORS) ----
    if(url.pathname === "/fr24/lookup" && request.method === "GET"){
      if(!env.FR24_TOKEN) return json({ok:false, error:"FR24 lookup not configured yet."}, 503);
      // Gate the PAID FR24 quota behind an active licence + a per-device rate limit (previously open to anyone).
      const _fdev = (url.searchParams.get("device")||"").trim().toUpperCase();
      const _fcode = (url.searchParams.get("code")||"").toString();
      if(!tokenOk(env, request)){
        if(!(await licOk(env, {device:_fdev, code:_fcode}))) return json({ok:false, error:"This feature needs an active Sky Matrix licence."}, 403);
        if(!(await rateOk(env, "fr24:"+_fdev, 60, 3600))) return json({ok:false, error:"Too many aircraft lookups from this device. Please try again later."}, 429);
      }
      track(ctx, env, "fr24");
      const cs = (url.searchParams.get("callsign")||"").trim().toUpperCase();
      const reg = (url.searchParams.get("reg")||"").trim().toUpperCase();
      if(!cs && !reg) return json({ok:false, error:"Provide a callsign or registration."}, 400);
      const q = cs ? ("callsigns="+encodeURIComponent(cs)) : ("registrations="+encodeURIComponent(reg));
      try{
        const r = await fetch("https://fr24api.flightradar24.com/api/live/flight-positions/full?"+q, {
          headers:{ "Authorization":"Bearer "+env.FR24_TOKEN, "Accept":"application/json", "Accept-Version":"v1" }
        });
        const j = await r.json().catch(()=>({}));
        if(!r.ok) return json({ok:false, error:(j.message||j.detail||("FR24 HTTP "+r.status))}, 502);
        return json({ok:true, data:j});
      }catch(e){ return json({ok:false, error:"FR24 fetch failed: "+e.message}, 502); }
    }

    // ---- Announcement Prep: fill an uploaded announcement template's blanks with flight data (AI) ----
    if(url.pathname === "/announce" && request.method === "POST"){
      if(!env.ANTHROPIC_API_KEY) return json({ok:false, error:"AI not configured yet."}, 503);
      let body={}; try{ body = await request.json(); }catch(e){}
      if(!(await licOk(env, body)) && !tokenOk(env, request)) return json({ok:false, error:"This feature needs an active Sky Matrix licence."}, 403);
      if(!tokenOk(env, request) && !(await aiQuotaOk(env, ((body.device)||"").toUpperCase()))) return json({ok:false, error:"Daily AI limit reached for this device. Please try again tomorrow, or contact support@skymatrix.biz."}, 429);
      track(ctx, env, "ai");
      const template = (body.template||"").toString().slice(0, 8000);
      const data = (body.data||"").toString().slice(0, 2500);
      const lang = (body.lang||"English").toString().slice(0, 60);
      const proofread = !!body.proofread;
      if(template.trim().length < 10) return json({ok:false, error:"No announcement template text supplied."}, 400);
      const sys = "You are a cabin-announcement writer for airline crew. You receive an announcement TEMPLATE containing blanks/placeholders (underscores, [BRACKETS], {braces}, XXXX, dotted lines, or obvious gaps) and a set of FLIGHT DATA & PREFERENCES. Fill every blank with the correct value from the data, keeping the template's wording, tone and structure exactly — only fill the gaps, never rewrite. " + (proofread ? "Also silently correct any spelling, grammar or punctuation mistakes in the wording without changing its meaning or style. " : "") + "If a needed value is genuinely missing from the data, leave a clearly marked [___] gap rather than inventing it. Then give the finished announcement in " + lang + ". Return ONLY the finished announcement text, no preamble, no notes.";
      let out; try{ out = await anthropic(env, sys, "TEMPLATE:\n" + template + "\n\nFLIGHT DATA & PREFERENCES:\n" + data); }
      catch(e){ return json({ok:false, error:"AI failed: "+e.message}, 502); }
      return json({ok:true, text: out.trim()});
    }

    // ---- Crew roster reader: pull flight-deck & cabin names + ranks out of any roster text (from PDF/Word/text/photo-OCR) ----
    if(url.pathname === "/crew" && request.method === "POST"){
      if(!env.ANTHROPIC_API_KEY) return json({ok:false, error:"AI not configured yet."}, 503);
      let body={}; try{ body = await request.json(); }catch(e){}
      if(!(await licOk(env, body)) && !tokenOk(env, request)) return json({ok:false, error:"This feature needs an active Sky Matrix licence."}, 403);
      if(!tokenOk(env, request) && !(await aiQuotaOk(env, ((body.device)||"").toUpperCase()))) return json({ok:false, error:"Daily AI limit reached for this device. Please try again tomorrow, or contact support@skymatrix.biz."}, 429);
      track(ctx, env, "ai");
      const text = (body.text||"").toString().slice(0, 9000);
      if(text.trim().length < 3) return json({ok:false, error:"No roster text supplied."}, 400);
      const sys = "You extract the crew list from an airline crew roster, sign-on sheet, briefing sheet or OFP crew block. The rank may appear as a prefix, a suffix, a code, or a separate column next to the name. FLIGHT-DECK ranks and their codes: Captain (CP, CAPT, CAP, CA, CMD, PIC, COMMANDER), First Officer (FO, F/O, FIRST OFFICER), Senior First Officer (SFO) -> treat as First Officer, Second Officer (SO) -> Second Officer, Relief/Cruise Pilot (RP, RC, CRP) -> Relief Pilot. A flight can have 2, 3 or 4 flight-deck crew (augmented/heavy crew) — capture ALL of them in the order shown. CABIN ranks and codes: CSD (Cabin Services Director), CS (Cabin Supervisor / Senior), LCC or LC (Lead Cabin Crew), and ordinary cabin crew (CC, FA, STW, CA when clearly cabin). Capture the cabin crew too, seniors first. Return ONLY a JSON object, no prose, no code fences: {\"flightDeck\":[{\"rank\":\"Captain|First Officer|Second Officer|Relief Pilot\",\"name\":\"Full Name\"}],\"cabin\":[{\"rank\":\"CSD|Cabin Supervisor|Lead Cabin Crew|Cabin Crew\",\"name\":\"Full Name\"}]}. Use proper Title Case for names; strip staff/ID numbers and honorifics (Mr/Ms/Capt.). If a section has no crew, use an empty array.";
      let out; try{ out = await anthropic(env, sys, "ROSTER:\n" + text, {max_tokens:1200, temperature:0}); }
      catch(e){ return json({ok:false, error:"AI failed: "+e.message}, 502); }
      let crew=null;
      try{ let s = out.replace(/```json/gi,"").replace(/```/g,"").trim(); const a=s.indexOf("{"); if(a>0)s=s.slice(a); crew=JSON.parse(s); }
      catch(e){ return json({ok:false, error:"Could not read the roster."}, 502); }
      return json({ok:true, crew});
    }

    // ---- Checklist maker: turn any document text into a clean pilot checklist ----
    if(url.pathname === "/checklist" && request.method === "POST"){
      if(!env.ANTHROPIC_API_KEY) return json({ok:false, error:"AI not configured yet."}, 503);
      let body={}; try{ body = await request.json(); }catch(e){}
      if(!(await licOk(env, body)) && !tokenOk(env, request)) return json({ok:false, error:"This feature needs an active Sky Matrix licence."}, 403);
      if(!tokenOk(env, request) && !(await aiQuotaOk(env, ((body.device)||"").toUpperCase()))) return json({ok:false, error:"Daily AI limit reached for this device. Please try again tomorrow, or contact support@skymatrix.biz."}, 429);
      track(ctx, env, "ai");
      const text = (body.text||"").toString().slice(0, 9000);
      if(text.trim().length < 3) return json({ok:false, error:"No document text supplied."}, 400);
      const sys = "You convert a document (a procedure, briefing, manual extract, or notes) into a concise, actionable CHECKLIST for airline pilots. Produce clear imperative check items, one action each, in the document's original order. Merge wrapped lines; drop page numbers, headers/footers and boilerplate. Keep any challenge-response wording or values that matter. Return ONLY a JSON object, no prose, no code fences: {\"items\":[\"item 1\",\"item 2\"]}. Between 3 and 60 items.";
      let out; try{ out = await anthropic(env, sys, "DOCUMENT:\n" + text, {max_tokens:1500, temperature:0}); }
      catch(e){ return json({ok:false, error:"AI failed: "+e.message}, 502); }
      let items=null;
      try{ let s = out.replace(/```json/gi,"").replace(/```/g,"").trim(); const a=s.indexOf("{"); if(a>0)s=s.slice(a); items=(JSON.parse(s)||{}).items; }
      catch(e){ return json({ok:false, error:"Could not build a checklist from that document."}, 502); }
      return json({ok:true, items: Array.isArray(items)?items:[]});
    }

    // ---- admin: push a PDF/doc to a single device or to ALL licensed devices ----
    if(url.pathname === "/admin/pushdoc" && request.method === "POST"){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      let body={}; try{ body = await request.json(); }catch(e){}
      const target = (body.device||"ALL").trim().toUpperCase();
      const name = (body.name||"document.pdf").toString().slice(0,120);
      const mime = (body.mime||"application/pdf").toString().slice(0,80);
      const dataB64 = (body.dataB64||"").toString();
      if(!dataB64) return json({ok:false, error:"no file data"}, 400);
      if(dataB64.length > 20000000) return json({ok:false, error:"file too large (about 14 MB max)"}, 413);
      // target = ALL, one device (SKM-XXXXXX), or a group (GROUP:<id>)
      if(target!=="ALL" && !/^SKM-[A-Z0-9]{6}$/.test(target) && !/^GROUP:[A-Z0-9_-]{1,30}$/.test(target)) return json({ok:false, error:"bad target (device, ALL, or GROUP:<id>)"}, 400);
      const id = Date.now()+""+Math.random().toString(36).slice(2,6);
      await env.TRIALS.put("pushdoc:"+target+":"+id, JSON.stringify({id, name, mime, dataB64, at:Date.now()}), {expirationTtl:60*60*24*120});
      return json({ok:true, id, target});
    }

    // ---- admin: assign a device to a group (so a single push can reach a set of users). Empty group clears it. ----
    if(url.pathname === "/admin/group" && request.method === "POST"){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      let body={}; try{ body = await request.json(); }catch(e){}
      const device = (body.device||"").trim().toUpperCase();
      const group = (body.group||"").trim().toUpperCase().replace(/[^A-Z0-9_-]/g,"").slice(0,30);
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"bad device"}, 400);
      const s = await env.TRIALS.get("trial:"+device);
      if(!s) return json({ok:false, error:"no record for this device (load users first / device must have run the app)"}, 404);
      let rec; try{ rec = JSON.parse(s); }catch(e){ return json({ok:false, error:"record error"}, 500); }
      rec.group = group;
      await putTrial(env, device, rec);
      return json({ok:true, device, group});
    }

    // ---- admin: set a friendly NAME for a device (shows in the users list) ----
    if(url.pathname === "/admin/name" && request.method === "POST"){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      let body={}; try{ body = await request.json(); }catch(e){}
      const device = (body.device||"").trim().toUpperCase();
      const name = (body.name||"").toString().replace(/[<>]/g,"").slice(0,40).trim();
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"bad device"}, 400);
      const s = await env.TRIALS.get("trial:"+device);
      if(!s) return json({ok:false, error:"no record for this device (it must have run the app first)"}, 404);
      let rec; try{ rec = JSON.parse(s); }catch(e){ return json({ok:false, error:"record error"}, 500); }
      rec.name = name;
      await putTrial(env, device, rec);
      return json({ok:true, device, name});
    }

    // ---- MAIN admin: create / list / remove group-admin credentials (a delegated admin scoped to one group) ----
    if(url.pathname === "/admin/subadmin" && (request.method === "GET" || request.method === "POST")){
      if(!tokenOk(env, request)) return json({ok:false, error:"unauthorized"}, 401);
      if(request.method === "POST"){
        let body={}; try{ body = await request.json(); }catch(e){}
        const token=(body.token||"").toString().trim();
        const group=(body.group||"").toString().trim().toUpperCase().replace(/[^A-Z0-9_-]/g,"").slice(0,30);
        if(body.remove){ if(token){ try{ await env.TRIALS.delete("gadmin:"+token); }catch(e){} } return json({ok:true, removed:true}); }
        if(token.length<6) return json({ok:false, error:"token must be at least 6 characters"}, 400);
        if(!group) return json({ok:false, error:"a group id is required"}, 400);
        await env.TRIALS.put("gadmin:"+token, group);
        return json({ok:true, token, group});
      }
      const out=[]; let cursor;
      do{ const list=await env.TRIALS.list({prefix:"gadmin:", cursor}); for(const k of list.keys){ let g=""; try{ g=(await env.TRIALS.get(k.name))||""; }catch(e){} out.push({token:k.name.slice(7), group:g}); } cursor=list.list_complete?null:list.cursor; }while(cursor);
      return json({ok:true, subadmins:out});
    }
    // ---- GROUP admin: list the users in MY group only ----
    if(url.pathname === "/g/users" && request.method === "GET"){
      const grp=await groupAdminGroup(env, request); if(!grp) return json({ok:false, error:"unauthorized"}, 401);
      const bl=await readBlocklist(env); const nowDay=Math.floor(Date.now()/86400000); const users=[]; let cursor;
      do{ const list=await env.TRIALS.list({prefix:"trial:", cursor}); for(const k of list.keys){ const md=k.metadata; if(!md||String(md.g||"").toUpperCase()!==grp) continue; const dev=k.name.slice(6);
        users.push({device:dev, name:md.n||"", email:md.e||"", plan:md.p||"", end:(md.x!=null?new Date(md.x*86400000).toISOString().slice(0,10):""), daysLeft:(md.x!=null?(md.x-nowDay):null), active:(md.x!=null?(md.x>=nowDay):false), blocked:bl.indexOf(dev)>=0}); }
        cursor=list.list_complete?null:list.cursor; }while(cursor);
      return json({ok:true, group:grp, count:users.length, users});
    }
    // ---- GROUP admin: push a document to everyone in MY group ----
    if(url.pathname === "/g/pushdoc" && request.method === "POST"){
      const grp=await groupAdminGroup(env, request); if(!grp) return json({ok:false, error:"unauthorized"}, 401);
      let body={}; try{ body = await request.json(); }catch(e){}
      const name=(body.name||"document.pdf").toString().slice(0,120); const mime=(body.mime||"application/pdf").toString().slice(0,80); const dataB64=(body.dataB64||"").toString();
      if(!dataB64) return json({ok:false, error:"no file data"}, 400);
      if(dataB64.length>20000000) return json({ok:false, error:"file too large (about 14 MB max)"}, 413);
      const id=Date.now()+""+Math.random().toString(36).slice(2,6);
      await env.TRIALS.put("pushdoc:GROUP:"+grp+":"+id, JSON.stringify({id,name,mime,dataB64,at:Date.now()}), {expirationTtl:60*60*24*120});
      return json({ok:true, id, group:grp});
    }
    // ---- GROUP admin: name a device that is already in MY group ----
    if(url.pathname === "/g/name" && request.method === "POST"){
      const grp=await groupAdminGroup(env, request); if(!grp) return json({ok:false, error:"unauthorized"}, 401);
      let body={}; try{ body = await request.json(); }catch(e){}
      const device=(body.device||"").trim().toUpperCase(); const nm=(body.name||"").toString().replace(/[<>]/g,"").slice(0,40).trim();
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"bad device"}, 400);
      const s=await env.TRIALS.get("trial:"+device); if(!s) return json({ok:false, error:"no record for this device"}, 404);
      let rec; try{ rec=JSON.parse(s); }catch(e){ return json({ok:false, error:"record error"}, 500); }
      if(String(rec.group||"").toUpperCase()!==grp) return json({ok:false, error:"that device is not in your group"}, 403);
      rec.name=nm; await putTrial(env, device, rec); return json({ok:true, device, name:nm});
    }

    // ---- app: pull any docs pushed to this device (or to ALL or its group); verified by licence code ----
    if(url.pathname === "/pusheddocs" && request.method === "POST"){
      let body={}; try{ body = await request.json(); }catch(e){}
      const device = (body.device||"").trim().toUpperCase();
      const code = (body.code||"").toString();
      const have = Array.isArray(body.have) ? body.have.map(String) : [];
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"bad device"}, 400);
      const v = await verifyLicence(env, device, code); if(!v.ok) return json({ok:false, error:"unverified"}, 403);
      if(v.expDay && v.expDay < Math.floor(Date.now()/86400000)) return json({ok:false, error:"licence expired"}, 403);
      // include any group this device belongs to, so group-pushes reach it
      let grp=""; try{ const gs=await env.TRIALS.get("trial:"+device); if(gs){ const gr=JSON.parse(gs); grp=(gr.group||"").toString().toUpperCase(); } }catch(e){}
      const prefixes = ["pushdoc:ALL:", "pushdoc:"+device+":"];
      if(grp) prefixes.push("pushdoc:GROUP:"+grp+":");
      const out=[];
      for(const pref of prefixes){
        let cursor;
        do{
          const l = await env.TRIALS.list({prefix:pref, cursor});
          for(const k of l.keys){ const id=k.name.slice(k.name.lastIndexOf(":")+1); if(have.indexOf(id)>=0) continue; const s=await env.TRIALS.get(k.name); if(s){ try{ out.push(JSON.parse(s)); }catch(e){} } }
          cursor = l.list_complete ? null : l.cursor;
        }while(cursor);
      }
      return json({ok:true, docs: out});
    }

    // ---- app: fetch this device's current licence code (e.g. after subscribing); gated by matching email ----
    if(url.pathname === "/mycode" && request.method === "POST"){
      let body={}; try{ body = await request.json(); }catch(e){}
      const device = (body.device||"").trim().toUpperCase();
      const email = (body.email||"").trim().toLowerCase();
      if(!/^SKM-[A-Z0-9]{6}$/.test(device)) return json({ok:false, error:"bad device"}, 400);
      if(!email) return json({ok:false, error:"Enter the email your licence is registered to."}, 403);
      // ONE device per licence: the email is bound to exactly one device; only THAT device may retrieve its code.
      // A different device entering the same email is a second-device attempt and MUST be refused.
      let bound=""; try{ bound = ((await env.TRIALS.get("email:"+email))||"").toUpperCase(); }catch(e){}
      if(!bound) return json({ok:false, error:"No licence is registered to that email."}, 404);
      if(bound !== device) return json({ok:false, error:"This licence is registered to another device. Sky Matrix is licensed to one device only — contact admin@skymatrix.biz to move it."}, 403);
      const s = await env.TRIALS.get("trial:"+device);
      if(!s) return json({ok:false, error:"No licence is on record for this device yet."}, 404);
      let rec; try{ rec = JSON.parse(s); }catch(e){ return json({ok:false, error:"record error"}, 500); }
      const re = (rec.email||"").toLowerCase();
      if(re && re!==email) return json({ok:false, error:"That email does not match this device's licence."}, 403);
      if(!rec.expDay) return json({ok:false, error:"No code stored for this device."}, 404);
      const code = await signExp(env, device, rec.expDay);
      return json({ok:true, code, expiry: expiryText(rec.expDay)});
    }

    // ---- weather proxy: METAR + TAF + D-ATIS fetched server-side (no browser CORS), reliable ----
    if(url.pathname === "/wx" && request.method === "GET"){
      const icao = (url.searchParams.get("icao")||"").toUpperCase().replace(/[^A-Z0-9]/g,"").slice(0,4);
      if(!/^[A-Z]{4}$/.test(icao)) return json({ok:false, error:"Enter a 4-letter ICAO."}, 400);
      async function grab(u){ try{ const r = await fetch(u, {cf:{cacheTtl:120, cacheEverything:true}}); if(!r.ok) return ""; return (await r.text()).trim(); }catch(e){ return ""; } }
      const metar = await grab("https://aviationweather.gov/api/data/metar?ids="+icao+"&format=raw");
      const taf   = await grab("https://aviationweather.gov/api/data/taf?ids="+icao+"&format=raw");
      let datis = "";
      try{ const dr = await fetch("https://datis.clowd.io/api/"+icao, {cf:{cacheTtl:120}}); if(dr.ok){ const dj = await dr.json(); if(Array.isArray(dj)&&dj.length&&dj[0]&&dj[0].datis) datis = dj.map(a=>(a.type?("["+String(a.type).toUpperCase()+"] "):"")+a.datis).join("\n\n"); } }catch(e){}
      return json({ok:true, icao, metar, taf, datis});
    }

    return new Response("Sky Matrix trial service", {headers: CORS});
    }catch(e){ return json({ok:false, error:"service temporarily unavailable"}, 503); }
  },

  // ---- email intake: user emails their Device ID to trial@skymatrix.biz ----
  async email(message, env){
    const subj = message.headers.get("subject") || "";
    const to   = String(message.to||"").toLowerCase();
    const from = message.from;
    const isSupport = /support|feedback|admin|hello|contact/.test(to);
    // forward support/admin/feedback mail to Gmail FIRST — message.raw is a one-shot stream, so forwarding must happen BEFORE we read it below
    if(isSupport){ try{ await message.forward("skymatrix401@gmail.com"); }catch(e){} }
    let raw="";
    try{ raw = await new Response(message.raw).text(); }catch(e){}
    const m = (subj + "\n" + raw).match(DEV_RE);
    // support@/feedback@ mail, or any message with no Device ID -> store in the admin feedback inbox
    if(isSupport || !m){
      try{ await env.TRIALS.put("fb:"+Date.now()+":"+Math.random().toString(36).slice(2,7),
        JSON.stringify({ from: emailAddr(from), subject: subj.slice(0,140), body: emailBodyText(raw), at: Date.now(), via:"email", to }),
        {expirationTtl:60*60*24*365}); }catch(e){}
      if(!isSupport && !m){
        await sendMail(env, from, "Sky Matrix — Device ID needed",
          `<p>Thanks for your interest in Sky Matrix. We couldn't find a Device ID in your email.</p>
           <p>Open the app, copy the <b>Device ID</b> shown on the lock screen (it looks like <b>SKM-XXXXXX</b>), and email it to us — we'll send your trial code.</p>`);
      }
      if(isSupport) return; // support/feedback: filed above, and already forwarded to Gmail before the body was read
    }
    if(!m) return;
    const device = m[0].toUpperCase();
    // FIX #7: blunt mass trial-hijack via email-in — cap how many trial issuances one sender can trigger per day
    const _fromAddr = emailAddr(from).toLowerCase();
    if(_fromAddr && !(await rateOk(env, "mailtrial:"+_fromAddr, 6, 86400))) return;
    const r = await issueTrial(env, device, from);
    if(!r.ok && r.reason==="used"){
      await sendMail(env, from, "Sky Matrix — trial already used",
        `<p>Device <b>${device}</b> has already used its free trial. Please contact support@skymatrix.biz to subscribe or request more time.</p>`);
    }
    // on success, issueTrial already emailed the code
  },

  // ---- daily cron (08:00 UTC): email a reminder when a tracked service is due within 7 days ----
  async scheduled(event, env, ctx){
    try{
      const services = JSON.parse((await env.TRIALS.get("svc:list"))||"[]");
      const today = Math.floor(Date.now()/86400000);
      const due = [];
      services.forEach(function(s){
        if(!s || !s.due) return;
        const t = Date.parse(s.due+"T00:00:00Z"); if(isNaN(t)) return;
        const d = Math.round(t/86400000) - today;
        if(d <= 7){ s._d = d; due.push(s); }   // overdue or within 7 days
      });
      if(!due.length) return;
      due.sort(function(a,b){ return a._d - b._d; });
      const rows = due.map(function(s){
        const when = s._d<0 ? ("OVERDUE by "+(-s._d)+" day(s)") : (s._d===0 ? "due today" : ("in "+s._d+" day(s)"));
        return "<tr><td style='padding:6px 10px;border:1px solid #ddd'>"+he(s.name)+"</td><td style='padding:6px 10px;border:1px solid #ddd'>"+he(s.cost)+"</td><td style='padding:6px 10px;border:1px solid #ddd'>"+he(s.due)+"</td><td style='padding:6px 10px;border:1px solid #ddd'>"+he(when)+"</td></tr>";
      }).join("");
      const html = "<div style=\"font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#12233f\">"
        + "<h2 style=\"margin:0 0 10px\">Sky Matrix &mdash; service reminders</h2>"
        + "<p style=\"margin:0 0 12px\">These tracked services are due within the next 7 days:</p>"
        + "<table style=\"border-collapse:collapse\">"
        + "<tr><th style='padding:6px 10px;border:1px solid #ddd;text-align:left'>Service</th>"
        + "<th style='padding:6px 10px;border:1px solid #ddd;text-align:left'>Cost</th>"
        + "<th style='padding:6px 10px;border:1px solid #ddd;text-align:left'>Due</th>"
        + "<th style='padding:6px 10px;border:1px solid #ddd;text-align:left'>Status</th></tr>"
        + rows + "</table></div>";
      const to = (env.REMINDER_EMAIL||"").trim();
      if(to) await sendMail(env, to, "Sky Matrix - service reminder ("+due.length+" due)", html);
    }catch(e){}
  }
}; 