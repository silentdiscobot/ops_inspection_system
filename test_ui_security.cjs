const fs=require('fs'),vm=require('vm'),assert=require('assert');
function element(){return {children:[],listeners:{},textContent:'',appendChild(x){this.children.push(x)},addEventListener(k,f){this.listeners[k]=f},set innerHTML(x){assert.equal(x,'','untrusted HTML assignment');this.children=[]}}}
(async()=>{
 const tbody=element(), calls=[];
 const users=[{id:1,username:"a'\"><img src=x onerror=alert(1)>",display_name:'<svg/onload=alert(1)>',contact:'x',role:'operator'},{id:2,username:'second',role:'viewer'}];
 const c={document:{getElementById:()=>tbody,createElement:element},fetch:async()=>({json:async()=>users}),showEditUserModal:(...x)=>calls.push(x),deleteUser:(...x)=>calls.push(x),console};
 vm.createContext(c);
 const html=fs.readFileSync('templates/users.html','utf8');
 const start=html.indexOf('function loadUsers()'),end=html.indexOf('\nfunction ',start+1);
 vm.runInContext(html.slice(start,end),c);c.loadUsers();await new Promise(r=>setImmediate(r));
 assert.equal(tbody.children.length,2);
 for(let i=0;i<2;i++){
 const row=tbody.children[i];assert.equal(row.children[1].textContent,users[i].username);
 row.children[7].children[0].listeners.click();assert.equal(calls.at(-1)[0],users[i].id);
 row.children[7].children[1].listeners.click();assert.equal(calls.at(-1)[0],users[i].id);
 }
 console.log('PASS: user XSS payload remains text; edit/delete target correct user');
})().catch(e=>{console.error(e);process.exit(1)});
