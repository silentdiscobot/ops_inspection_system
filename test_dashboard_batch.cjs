const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync('static/data-center-dashboard.js','utf8');
const noop=()=>{};const gradient={addColorStop:noop};
const ctx=new Proxy({createLinearGradient:()=>gradient,createRadialGradient:()=>gradient,measureText:t=>({width:String(t).length*6})},{get:(o,k)=>k in o?o[k]:noop});
let width=1200,height=700;
const canvas={width:0,height:0,getContext:()=>ctx,getBoundingClientRect:()=>({width,height,left:0,top:0})};
const c={console,window:{devicePixelRatio:1},sceneRotX:22,sceneRotY:0,scenePanX:0,scenePanY:0,editView:false,projectionFitCache:null,focusRow:null,focusRack:'',selectedRackName:'',rackDrag:null,rackScene:[],rackZones:[],rackHitAreas:[],rackCabinetAreas:[],rackRowDropAreas:[],RACK_SLOT_CAPACITY:15,STATUS:{online:{key:'normal',label:'正常'},offline:{key:'error',label:'报错'},checking:{key:'warning',label:'警告'}},byId:()=>canvas};
vm.createContext(c);
for(const name of ['polygon','rowCode','densityProfile','worldPoint','projectedBounds','buildProjector','roundedRect','paintPolygon','drawOpenRackFloor','drawRack3D','drawRackScene','statusOf','arrangeRack','rackLocation','naturalCompare','naturalParts']){const a=source.indexOf('  function '+name+'('),b=source.indexOf('\n  function ',a+4);assert(a>=0,name);vm.runInContext(source.slice(a,b),c);}
let cases=0;const start=Date.now();
for(const count of [1,4,20,50,100])for(const size of [[600,400],[1200,700],[2400,1400]]){
 [width,height]=size;c.rackScene=[];const rows=[];
 for(let i=0;i<count;i++){const servers=Array.from({length:10},(_,j)=>({id:i*10+j+1,name:'server',ip:'198.18.1.1',status:['online','offline','checking'][j%3],rack_level:'U'+(j+1)}));const rack={id:'r'+i,name:'R'+i,roomKey:'room',room:'测试',servers,arranged:c.arrangeRack(servers),counts:{normal:4,warning:3,error:3}};c.rackScene.push(rack);if(!rows[Math.floor(i/7)])rows[Math.floor(i/7)]=[];rows[Math.floor(i/7)].push(rack.name);}
 c.rackZones=[{key:'room',name:'测试',racks:c.rackScene,layout:{rows}}];
 for(let angle=0;angle<360;angle+=15){c.sceneRotY=angle;c.focusRow=null;c.drawRackScene();assert.equal(c.rackCabinetAreas.length,count);for(const b of c.rackCabinetAreas)assert([b.x,b.y,b.w,b.h].every(Number.isFinite));cases++;c.focusRow={zone:'room',row:0};c.drawRackScene();assert(c.rackCabinetAreas.length<=count);assert(c.rackCabinetAreas.length>=rows[0].length);cases++;}
}
console.log(JSON.stringify({cases,elapsedMs:Date.now()-start,result:'PASS'}));

// Additional inventory edge cases: no server may disappear from the rack.
for(const levels of [[null,null,'U1','U1','U42'],Array.from({length:100},(_,i)=>'U'+(i+1))]){
 const servers=levels.map((rack_level,id)=>({id,rack_level,status:'online'}));
 const arranged=c.arrangeRack(servers);assert.equal(arranged.length,servers.length);assert.equal(new Set(arranged.map(x=>x.slot)).size,servers.length);
}
console.log('PASS: missing, duplicate, U42 and 100-server rack inventories');
// Pointer capture sends click to the scene, so the listener must be on it.
let click;const clickContext={scene:{addEventListener:(name,fn)=>click=fn},dragDistance:0,rackCanvas:canvas,rackHitAreas:[],focusRow:null,rackScene:[],editView:false,cabinetAt:()=>({id:'rack',zoneKey:'room',row:1}),updateRackInspector:noop,enterFocus:(row)=>clickContext.selection=row,showDetail:noop};
vm.createContext(clickContext);let a=source.indexOf("    scene.addEventListener('click', function(event) {"),b=source.indexOf("    rackCanvas.addEventListener('pointermove'",a);vm.runInContext(source.slice(a,b),clickContext);
const event={clientX:100,clientY:100,target:{closest:()=>null}};click(event);assert.equal(clickContext.selection.row,1);clickContext.selection=null;clickContext.dragDistance=10;click(event);assert.equal(clickContext.selection,null);clickContext.dragDistance=0;click({...event,target:{closest:()=>({})}});assert.equal(clickContext.selection,null);
console.log('PASS: captured-scene click selects row; drag and toolbar do not select');
