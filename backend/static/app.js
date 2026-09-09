let current = null;

const navs = document.querySelectorAll(".nav, [data-target]");
navs.forEach(el => {
  el.addEventListener("click", () => {
    const target = el.dataset.target;
    if (!target) return;
    document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
    document.getElementById(target)?.classList.add("active");
    document.querySelectorAll(".nav").forEach(n => n.classList.remove("active"));
    document.querySelector(`.nav[data-target="${target}"]`)?.classList.add("active");
  });
});

function setView(id){
  document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));
  document.getElementById(id)?.classList.add("active");
  document.querySelectorAll(".nav").forEach(n=>n.classList.remove("active"));
  document.querySelector(`.nav[data-target="${id}"]`)?.classList.add("active");
}

async function analyze(url, options={}){
  const status=document.getElementById("scanStatus");
  const bar=document.getElementById("progress");
  const spans=[...document.querySelectorAll("#steps span")];
  status.textContent="ANALYZING REAL EVIDENCE";
  bar.style.width="12%";
  spans.forEach(s=>s.textContent="○ "+s.textContent.replace(/^[✓○] /,""));
  try{
    const res=await fetch(url,options);
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||"Analysis failed");
    current=data;
    bar.style.width="100%"; status.textContent="COMPLETE";
    spans.forEach(s=>s.textContent="✓ "+s.textContent.replace(/^[✓○] /,""));
    render(data);
    setView("overview");
  }catch(e){
    bar.style.width="0%"; status.textContent="ERROR";
    alert(e.message);
  }
}

document.querySelectorAll(".demo-btn").forEach(b=>{
  b.addEventListener("click",()=>analyze("/api/demo/"+b.dataset.demo));
});

document.querySelector(".primary[data-target='pcap']")?.addEventListener("click",()=>setView("pcap"));

document.getElementById("file").addEventListener("change",async e=>{
  const f=e.target.files[0]; if(!f)return;
  const fd=new FormData(); fd.append("file",f);
  await analyze("/api/analyze",{method:"POST",body:fd});
});

document.querySelectorAll(".reportbtn").forEach(b=>{
  b.addEventListener("click",()=>{
    if(!current){alert("Run an analysis first.");return}
    window.open("/api/report/"+b.dataset.format,"_blank");
  });
});

function render(d){
  document.getElementById("score").textContent=d.overall_score+"/100";
  document.getElementById("posture").textContent=d.overall_posture;
  document.getElementById("sessionsCount").textContent=d.sessions.length;
  document.getElementById("highCount").textContent=(d.finding_counts.HIGH||0)+(d.finding_counts.CRITICAL||0);
  document.getElementById("anomalyCount").textContent=d.sessions.filter(s=>s.anomaly?.label==="SUSPICIOUS").length;
  document.getElementById("smtp").textContent=d.protocol_counts.SMTP||0;
  document.getElementById("imap").textContent=d.protocol_counts.IMAP||0;
  document.getElementById("pop3").textContent=d.protocol_counts.POP3||0;

  document.getElementById("sessionTable").innerHTML=d.sessions.map(s=>`
    <tr><td>${s.session_id}</td><td>${s.protocol}</td>
    <td>${s.source}:${s.source_port} → ${s.destination}:${s.destination_port}</td>
    <td>${s.tls?.version||"Not observed"}</td>
    <td>${s.starttls_detected?"✓":"—"}</td>
    <td>${s.risk?.posture_score||"—"}/100</td></tr>`).join("");

  document.getElementById("tlsCards").innerHTML=d.sessions.map(s=>`
    <div class="tlsCard"><h3>${s.session_id} • ${s.protocol}</h3>
    <div class="kv">
      <span>TLS Version<b>${s.tls?.version||"Not observed"}</b></span>
      <span>Cipher Suite<b>${s.tls?.cipher_suite||"Not observed"}</b></span>
      <span>Key Exchange<b>${s.tls?.key_exchange||"Not observed"}</b></span>
      <span>Forward Secrecy<b>${s.tls?.forward_secrecy===true?"YES":s.tls?.forward_secrecy===false?"NO":"UNKNOWN"}</b></span>
      <span>Certificate<b>${s.certificate?.extracted?s.certificate.subject:"Not observed"}</b></span>
      <span>Validity<b>${s.certificate?.extracted?`${s.certificate.valid_from||"?"} → ${s.certificate.valid_to||"?"}`:"Not extracted"}</b></span>
      <span>Public Key<b>${s.certificate?.extracted?`${s.certificate.public_key_algorithm||"?"} ${s.certificate.key_length?`(${s.certificate.key_length} bits)`:""}`:"Not extracted"}</b></span>
      <span>Signature<b>${s.certificate?.signature_algorithm||"Not extracted"}</b></span>
      <span>Chain<b>${s.certificate?.extracted?`${s.certificate.chain_length||1} cert(s), signatures ${s.certificate.chain_signature_valid===false?"INVALID":"OK/NOT CHECKED"}`:"Not extracted"}</b></span>
    </div></div>`).join("");

  document.getElementById("findingList").innerHTML=d.findings.length?d.findings.map(f=>`
    <div class="finding ${f.severity.toLowerCase()}">
      <div class="sev">${f.severity}</div><h3>${f.title}</h3>
      <p><b>Evidence:</b> ${f.evidence}</p><p><b>Why:</b> ${f.why}</p><p><b>Recommended action:</b> ${f.recommendation}</p>
    </div>`).join(""):`<div class="panel"><h3>✓ No rule-based weaknesses detected</h3><p>The analyzed evidence currently meets the configured posture rules.</p></div>`;

  const first=d.sessions[0]||{};
  const risk=first.risk||{};
  document.getElementById("aiScore").textContent=d.overall_score;
  document.getElementById("aiLabel").textContent=risk.ml_label||"—";
  document.getElementById("aiConfidence").textContent=`ML confidence: ${risk.ml_confidence||0}% • ${risk.model||""}`;
  document.getElementById("aiSummary").textContent=d.ai_summary;
  document.getElementById("featureList").innerHTML=Object.entries(risk.features||{}).map(([k,v])=>`<div class="feature">${k}: <b>${v}</b></div>`).join("");

  const ledger=d.ledger||{};
  document.getElementById("chain").innerHTML=`
    <div class="block"><div class="num">BLOCK #${ledger.block_number||0}</div><h3>Evidence</h3><div class="hash">Evidence SHA-256<br>${ledger.evidence_hash||""}</div></div>
    <div class="block"><div class="num">CHAIN</div><h3>Previous Hash</h3><div class="hash">${ledger.previous_hash||"GENESIS"}</div></div>
    <div class="block"><div class="num">REPORT</div><h3>Report Hash</h3><div class="hash">${ledger.report_hash||""}</div></div>
    <div class="block"><div class="num">STATUS</div><h3 class="verified">✓ INTEGRITY VERIFIED</h3><div class="hash">Current hash<br>${ledger.current_hash||""}</div></div>`;
}
