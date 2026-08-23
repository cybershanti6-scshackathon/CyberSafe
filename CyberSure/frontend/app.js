
const CYBERSURE = {
  routes: {
    home: "index.html",
    dashboard: "dashboard.html",
    devices: "devices-vendors.html",
    nes: "nes.html",
    rpp: "rpp.html",
    web: "web-security.html",
    ai: "ai-assistant.html",
    reports: "reports.html"
  }
};

function pageKey(){
  const file = location.pathname.split("/").pop().toLowerCase() || "index.html";
  if(file === "index.html") return "home";
  if(file.includes("devices")) return "devices";
  if(file === "web-security") return "web";
  if(file.includes("ai-assistant")) return "ai";
  return file.replace(".html","");
}

function brandMarkup(){
  return `<a class="brand" href="${CYBERSURE.routes.home}" aria-label="CyberSure home">
    <div class="logo-mark"><span>CS</span></div><span class="brand-name">CyberSure</span>
  </a>`;
}

function navMarkup(){
  const key = pageKey();
  const items = [
    ["dashboard","dashboard","Dashboard"],
    ["devices","devices_other","Devices & Vendors"],
    ["nes","shield","NES"],
    ["rpp","policy","RPP"],
    ["web","language","Web Security"],
    ["ai","smart_toy","AI Assistant"],
    ["reports","description","Reports"]
  ];
  return items.map(([k,icon,label])=>`<a class="nav-item ${key===k?'active':''}" href="${CYBERSURE.routes[k]}" data-route="${k}">
    <span class="nav-icon material-symbols-outlined">${icon}</span><span class="nav-label">${label}</span>
  </a>`).join("");
}

function injectShell(){
  const root = document.querySelector("[data-app]");
  if(!root) return;
  root.innerHTML = `
    <div class="sidebar-overlay" id="sidebarOverlay"></div>
    <aside class="sidebar" id="sidebar">
      ${brandMarkup()}
      <nav class="nav">${navMarkup()}</nav>
      <div class="sidebar-footer">
        <button class="nav-item" id="sidebarCollapse" type="button" title="Collapse sidebar">
          <span class="nav-icon material-symbols-outlined">left_panel_close</span>
          <span class="nav-label sidebar-footer-label">Collapse Sidebar</span>
        </button>
      </div>
    </aside>
    <div class="main" id="main">
      <header class="topbar">
        <div class="toolbar">
          <button class="icon-btn mobile-menu" id="mobileMenu" aria-label="Open menu"><span class="material-symbols-outlined">menu</span></button>
          <span class="eyebrow">Glacier Security Platform</span>
        </div>
        <div class="toolbar">
          <button class="theme-btn" id="themeToggle" aria-label="Toggle theme"><span class="material-symbols-outlined" id="themeIcon">dark_mode</span></button>
        </div>
      </header>
      <main>${root.innerHTML}</main>
    </div>
    <div class="toast" id="toast"></div>
  `;
  root.removeAttribute("data-app");
  setupShell();
}

function setupShell(){
  const sidebar=document.getElementById("sidebar");
  const overlay=document.getElementById("sidebarOverlay");
  const mobile=document.getElementById("mobileMenu");
  const collapse=document.getElementById("sidebarCollapse");
  const theme=document.getElementById("themeToggle");
  const icon=document.getElementById("themeIcon");

  const applyTheme = mode => {
    document.documentElement.classList.toggle("dark", mode==="dark");
    localStorage.setItem("cybersure-theme", mode);
    if(icon) icon.textContent = mode==="dark" ? "light_mode" : "dark_mode";
  };
  applyTheme(localStorage.getItem("cybersure-theme") || "light");

  theme?.addEventListener("click",()=>applyTheme(document.documentElement.classList.contains("dark")?"light":"dark"));

  mobile?.addEventListener("click",()=>{
    sidebar.classList.add("open"); overlay.classList.add("show");
  });
  overlay?.addEventListener("click",()=>{
    sidebar.classList.remove("open"); overlay.classList.remove("show");
  });
  collapse?.addEventListener("click",()=>{
    if(window.innerWidth <= 900){
      sidebar.classList.remove("open"); overlay.classList.remove("show");
    }else{
      sidebar.classList.toggle("collapsed");
      localStorage.setItem("cybersure-sidebar-collapsed", sidebar.classList.contains("collapsed"));
    }
  });
  if(window.innerWidth > 900 && localStorage.getItem("cybersure-sidebar-collapsed")==="true") sidebar.classList.add("collapsed");

  sidebar.querySelectorAll("a[data-route]").forEach(a=>{
    a.addEventListener("click",()=>{ if(window.innerWidth<=900){sidebar.classList.remove("open");overlay.classList.remove("show")} });
  });
}

function toast(message){
  const t=document.getElementById("toast"); if(!t)return;
  t.textContent=message;t.classList.add("show");
  setTimeout(()=>t.classList.remove("show"),2500);
}

function initAssessment(config){
  const form=document.getElementById(config.formId);
  if(!form)return;
  const analysis=document.getElementById(config.analysisId);
  const results=document.getElementById(config.resultsId);
  const reportBtn=document.getElementById(config.reportBtnId);
  const rerun=document.getElementById(config.rerunId);
  form.addEventListener("submit",e=>{
    e.preventDefault();
    if(!form.checkValidity()){form.reportValidity();return}
    analysis.classList.add("show"); results.classList.remove("show");
    setTimeout(()=>{
      analysis.classList.remove("show"); results.classList.add("show");
      toast("Assessment completed using demo analysis data.");
      window.scrollTo({top:results.getBoundingClientRect().top+window.scrollY-90,behavior:"smooth"});
    },1400);
  });
  reportBtn?.addEventListener("click",()=>downloadReport(config.title,config.reportText||"CyberSure assessment report."));
  rerun?.addEventListener("click",()=>{results.classList.remove("show");form.scrollIntoView({behavior:"smooth"});});
}

function downloadReport(title,text){
  if(window.jspdf?.jsPDF){
    const {jsPDF}=window.jspdf; const doc=new jsPDF();
    doc.setFontSize(20);doc.text("CyberSure",20,20);
    doc.setFontSize(14);doc.text(title,20,34);
    doc.setFontSize(10);
    const lines=doc.splitTextToSize(text,170);doc.text(lines,20,48);
    doc.save(title.toLowerCase().replace(/[^a-z0-9]+/g,"-")+".pdf");
  }else{
    window.print();
  }
}

document.addEventListener("DOMContentLoaded",()=>{
  injectShell();
});
