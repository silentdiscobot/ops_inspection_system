const fs=require('fs'),vm=require('vm'),assert=require('assert');
(async()=>{
const source=fs.readFileSync('templates/reports.html','utf8').replace(/\{%[\s\S]*?%\}/g,'');let output='';
const esc=x=>String(x).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const c={document:{getElementById:()=>({set innerHTML(v){output=v}}),createElement:()=>({set textContent(v){this.text=v},get innerHTML(){return esc(this.text)}})},axios:{get:async()=>({data:[{filename:"a'<img src=x onerror=alert(1)>.pdf",mtime:'<svg/onload=alert(1)>'}]})},console};
vm.createContext(c);const start=source.indexOf('function escapeReportText'),end=source.indexOf('async function deleteReport');vm.runInContext(source.slice(start,end),c);c.loadReports();await new Promise(r=>setImmediate(r));assert(!output.includes('<img'));assert(!output.includes('<svg'));assert(output.includes('a%27'));console.log('PASS: report filename/time HTML escaped and apostrophe encoded');
})().catch(e=>{console.error(e);process.exit(1)});
