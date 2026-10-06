const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, 'public');
const DATA = path.join(__dirname, 'data');
const sessions = new Map();

const BUILTIN_ROLES = ['admin','doctor','nurse','pharmacy','laboratory','reception'];
const ROLE_FILE = path.join(DATA,'roles.json');
function loadRoles(){
  const custom=read('roles.json',[]);
  const map={
    admin:{label:'Administrator',permissions:['dashboard','patients','doctors','appointments','admissions','laboratory','pharmacy','billing','expenditures','reports','users','settings','attendance','periods','messages']},
    doctor:{label:'Doctor',permissions:['dashboard','patients','doctors','appointments','laboratory','expenditures','attendance','periods','messages']},
    nurse:{label:'Nurse',permissions:['dashboard','patients','appointments','admissions','expenditures','attendance','periods','messages']},
    pharmacy:{label:'Pharmacist',permissions:['dashboard','patients','pharmacy','expenditures','attendance','periods','messages']},
    laboratory:{label:'Laboratory',permissions:['dashboard','patients','laboratory','expenditures','attendance','periods','messages']},
    reception:{label:'Receptionist',permissions:['dashboard','patients','appointments','expenditures','attendance','periods','messages']}
  };
  for(const r of custom){ if(r&&r.key&&r.label) map[r.key]={label:r.label,permissions:Array.isArray(r.permissions)?r.permissions:[]}; }
  return map;
}
const ROLE_MAP = loadRoles();
const ROLES = Object.keys(ROLE_MAP);
const ROLE_PERMISSIONS = Object.fromEntries(Object.entries(ROLE_MAP).map(([k,v])=>[k,v.permissions]));
const EXPENSE_CATEGORY = Object.fromEntries(Object.entries(ROLE_MAP).map(([k,v])=>[k,k==='admin'?'General':v.label+' / Expenditure']));
function roleLabel(role){ return ROLE_MAP[role]?.label || role; }

function read(name, fallback=[]) { try { return JSON.parse(fs.readFileSync(path.join(DATA,name),'utf8')); } catch { return fallback; } }
function write(name,data) { fs.writeFileSync(path.join(DATA,name), JSON.stringify(data,null,2)); }
function now(){ return new Date().toISOString(); }
function moneyTotal(e){ return (Number(e.unitPrice)||0) * Math.max(1, Number(e.quantity)||1); }
function hashPassword(password,saltHex){ return crypto.scryptSync(password,Buffer.from(saltHex,'hex'),64).toString('hex'); }
function send(res,status,obj){ res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store','Access-Control-Allow-Origin':'*','Access-Control-Allow-Credentials':'true'}); res.end(JSON.stringify(obj)); }
function body(req){ return new Promise((resolve,reject)=>{let b='';req.on('data',c=>b+=c);req.on('end',()=>{try{resolve(b?JSON.parse(b):{})}catch(e){reject(e)}})}); }
function cookies(req){ const out={};(req.headers.cookie||'').split(';').forEach(x=>{const i=x.indexOf('=');if(i>0)out[x.slice(0,i).trim()]=decodeURIComponent(x.slice(i+1).trim())});return out; }
function auth(req){ const sid=cookies(req).sid; return sid ? sessions.get(sid) : null; }
function requireAuth(req,res){ const u=auth(req);if(!u){send(res,401,{error:'Please log in'});return null}return u; }
function allowed(u,section){ return u.role==='admin' || (ROLE_PERMISSIONS[u.role]||[]).includes(section); }
function patientTotal(p){ return (p.expenses||[]).reduce((s,e)=>s+moneyTotal({unitPrice:e.price,quantity:e.quantity}),0); }
function ensureExpenditures(){
  const file=path.join(DATA,'expenditures.json');
  if(fs.existsSync(file)) return;
  const out=[];
  for(const p of read('patients.json')) for(const e of (p.expenses||[])) out.push({id:e.id||crypto.randomUUID(),patientId:p.id,patientName:p.name,category:e.category||'General',item:e.drug||e.description||'Item',description:e.description||'',unitPrice:Number(e.price)||0,quantity:Math.max(1,Number(e.quantity)||1),total:moneyTotal({unitPrice:e.price,quantity:e.quantity}),profession:e.profession||'Pharmacy',recordedBy:e.recordedBy||'Imported record',recordedAt:e.recordedAt||now()});
  write('expenditures.json',out);
}
function sanitizePatient(p,u){
  const base={id:p.id,name:p.name,age:p.age,gender:p.gender,phone:p.phone,department:p.department,status:p.status,doctorId:p.doctorId,doctorName:p.doctorName,createdAt:p.createdAt,totalExpenditure:patientTotal(p)};
  if(['admin','doctor','nurse','reception'].includes(u.role)) base.clinical=p.clinical||{};
  if(['admin','doctor','nurse','pharmacy'].includes(u.role)) base.medications=p.medications||[];
  if(['admin','doctor','nurse','laboratory'].includes(u.role)) base.labs=p.labs||[];
  if(['admin','nurse'].includes(u.role)) base.vitals=p.vitals||[];
  if(['admin','doctor','nurse','pharmacy','laboratory','reception'].includes(u.role)) base.expenses=p.expenses||[];
  if(u.role==='admin') base.nursingNotes=p.nursingNotes||[];
  return base;
}
function staticFile(req,res){
  let p=decodeURIComponent(req.url.split('?')[0]);if(p==='/')p='/index.html';
  const file=path.normalize(path.join(PUBLIC,p));
  if(!file.startsWith(PUBLIC)){res.writeHead(403);return res.end('Forbidden')}
  fs.readFile(file,(err,data)=>{if(err){res.writeHead(404);return res.end('Not found')}const ext=path.extname(file);const types={'.html':'text/html','.css':'text/css','.js':'application/javascript','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp'};res.writeHead(200,{'Content-Type':types[ext]||'text/plain'});res.end(data);});
}
ensureExpenditures();

const server=http.createServer(async(req,res)=>{
  if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'Content-Type'});return res.end();}
  try{
    if(!req.url.startsWith('/api/')) return staticFile(req,res);
    const raw=req.url.split('?')[0];
    if(raw==='/api/roles'&&req.method==='GET'){
      const u0=requireAuth(req,res); if(!u0)return; if(u0.role!=='admin')return send(res,403,{error:'Only administrators can manage roles'}); return send(res,200,Object.entries(ROLE_MAP).map(([key,v])=>({key,label:v.label,permissions:v.permissions,builtin:BUILTIN_ROLES.includes(key)})));
    }
    if(raw==='/api/login'&&req.method==='POST'){
      const x=await body(req),email=String(x.email||'').toLowerCase().trim(),password=String(x.password||'');
      const user=read('users.json').find(z=>z.email.toLowerCase()===email);
      if(!user||hashPassword(password,user.salt)!==user.passwordHash)return send(res,401,{error:'Invalid email or password'});
      const sid=crypto.randomBytes(32).toString('hex');sessions.set(sid,{id:user.id,email:user.email,name:user.name,role:user.role,profession:user.profession});
      res.writeHead(200,{'Content-Type':'application/json','Set-Cookie':`sid=${sid}; HttpOnly; SameSite=Lax; Path=/`});return res.end(JSON.stringify({user:sessions.get(sid),permissions:ROLE_PERMISSIONS[user.role]}));
    }
    if(raw==='/api/logout'&&req.method==='POST'){sessions.delete(cookies(req).sid);res.writeHead(200,{'Content-Type':'application/json','Set-Cookie':'sid=; Max-Age=0; Path=/'});return res.end(JSON.stringify({ok:true}));}
    if(raw==='/api/me'&&req.method==='GET'){const u=requireAuth(req,res);if(!u)return;return send(res,200,{user:u,permissions:ROLE_PERMISSIONS[u.role]||[]});}
    const u=requireAuth(req,res);if(!u)return;

    if(raw==='/api/roles'&&req.method==='POST'){
      if(u.role!=='admin')return send(res,403,{error:'Only administrators can create professions'});
      const x=await body(req),label=String(x.label||'').trim(),key=String(x.key||'').toLowerCase().trim().replace(/[^a-z0-9_-]/g,'_').replace(/^_+|_+$/g,'');
      if(!label||!key)return send(res,400,{error:'Profession name and role key are required'});
      if(ROLE_MAP[key])return send(res,409,{error:'That role already exists'});
      const permissions=Array.isArray(x.permissions)?x.permissions.filter(v=>['dashboard','patients','appointments','expenditures','attendance','periods','messages','reports'].includes(v)):['dashboard','patients','expenditures','attendance','periods','messages'];
      const all=read('roles.json',[]); all.push({key,label,permissions,createdAt:now(),createdBy:u.name}); write('roles.json',all); ROLE_MAP[key]={label,permissions}; ROLE_PERMISSIONS[key]=permissions; ROLES.push(key); EXPENSE_CATEGORY[key]=label+' / Expenditure';
      return send(res,201,{key,label,permissions,builtin:false});
    }
    if(raw==='/api/users'&&req.method==='POST'){
      if(u.role!=='admin')return send(res,403,{error:'Only administrators can create staff users'});
      const x=await body(req),name=String(x.name||'').trim(),email=String(x.email||'').toLowerCase().trim(),password=String(x.password||''),role=String(x.role||'').toLowerCase().trim();
      if(!name||!email||!password||!role)return send(res,400,{error:'Name, email, password and profession are required'});
      if(!ROLE_MAP[role])return send(res,400,{error:'Profession role does not exist'});
      const all=read('users.json'); if(all.some(z=>z.email.toLowerCase()===email))return send(res,409,{error:'Email already exists'});
      const salt=crypto.randomBytes(16).toString('hex'); const nu={id:crypto.randomUUID(),email,name,role,profession:ROLE_MAP[role].label,salt,passwordHash:hashPassword(password,salt)}; all.push(nu); write('users.json',all); return send(res,201,{id:nu.id,name:nu.name,email:nu.email,role:nu.role,profession:nu.profession});
    }

    if(raw==='/api/dashboard'&&req.method==='GET'){
      const patients=read('patients.json'),apps=read('appointments.json'),expenses=read('expenditures.json');
      const visibleExpenses=u.role==='admin'?expenses:expenses.filter(e=>e.professionRole===u.role||e.recordedById===u.id);
      const staff=read('users.json').filter(x=>x.role!=='admin');
      const today=new Date().toISOString().slice(0,10);
      const att=read('attendance.json').filter(a=>u.role==='admin'||a.userId===u.id||a.date===today);
      return send(res,200,{patients:patients.length,appointments:apps.filter(a=>u.role==='admin'||a.doctorId===u.id||u.role==='reception').length,admitted:patients.filter(p=>p.status==='Admitted').length,doctors:staff.filter(x=>x.role==='doctor').length,totalExpenditures:expenses.reduce((s,e)=>s+Number(e.total||moneyTotal(e)),0),myExpenditures:visibleExpenses.reduce((s,e)=>s+Number(e.total||moneyTotal(e)),0),attendance:att,expenseSummary:ROLES.filter(r=>r!=='admin').map(r=>({role:r,label:EXPENSE_CATEGORY[r],total:expenses.filter(e=>e.professionRole===r).reduce((s,e)=>s+Number(e.total||0),0)}))});
    }

    if(raw==='/api/patients'&&req.method==='GET'){if(!allowed(u,'patients'))return send(res,403,{error:'Patients are not available for your role'});return send(res,200,read('patients.json').map(p=>sanitizePatient(p,u)));}
    if(raw==='/api/patients'&&req.method==='POST'){
      if(!allowed(u,'patients'))return send(res,403,{error:'Not allowed'});const x=await body(req),patients=read('patients.json');
      const p={id:crypto.randomUUID(),createdAt:now(),name:String(x.name||''),age:x.age||'',gender:x.gender||'',phone:x.phone||'',department:x.department||'',status:x.status||'Outpatient',doctorId:x.doctorId||(u.role==='doctor'?u.id:''),doctorName:x.doctorName||(u.role==='doctor'?u.name:''),clinical:x.clinical||{},vitals:[],labs:[],nursingNotes:[],medications:[],expenses:[]};
      patients.unshift(p);write('patients.json',patients);return send(res,201,sanitizePatient(p,u));
    }
    const pm=raw.match(/^\/api\/patients\/([^/]+)(?:\/([^/]+))?$/);
    if(pm){
      const id=pm[1],action=pm[2],patients=read('patients.json'),i=patients.findIndex(p=>p.id===id);if(i<0)return send(res,404,{error:'Patient not found'});const p=patients[i];
      if(req.method==='GET'&&!action)return send(res,200,sanitizePatient(p,u));
      if(req.method==='POST'&&action==='clinical'){if(!['admin','doctor'].includes(u.role))return send(res,403,{error:'Clinical notes are restricted to doctors and administrators'});const x=await body(req);p.clinical={...(p.clinical||{}),diagnosis:x.diagnosis||'',treatment:x.treatment||'',updatedAt:now(),updatedBy:u.name};write('patients.json',patients);return send(res,200,sanitizePatient(p,u));}
      if(req.method==='POST'&&action==='vitals'){if(!['admin','nurse'].includes(u.role))return send(res,403,{error:'Vitals are restricted to nurses and administrators'});const x=await body(req);p.vitals=p.vitals||[];p.vitals.unshift({id:crypto.randomUUID(),temperature:x.temperature||'',bp:x.bp||'',pulse:x.pulse||'',respiration:x.respiration||'',weight:x.weight||'',recordedAt:now(),recordedBy:u.name});write('patients.json',patients);return send(res,200,p.vitals[0]);}
      if(req.method==='POST'&&action==='nursing-note'){if(!['admin','nurse'].includes(u.role))return send(res,403,{error:'Nursing notes are restricted to nurses and administrators'});const x=await body(req);p.nursingNotes=p.nursingNotes||[];p.nursingNotes.unshift({id:crypto.randomUUID(),note:x.note||'',recordedAt:now(),recordedBy:u.name});write('patients.json',patients);return send(res,200,p.nursingNotes[0]);}
      if(req.method==='POST'&&action==='lab'){if(!['admin','laboratory','doctor'].includes(u.role))return send(res,403,{error:'Laboratory access denied'});const x=await body(req);p.labs=p.labs||[];p.labs.unshift({id:crypto.randomUUID(),test:x.test||'',result:x.result||'',status:x.status||'Requested',recordedAt:now(),recordedBy:u.name});write('patients.json',patients);return send(res,200,p.labs[0]);}
      if(req.method==='POST'&&action==='medication'){if(!['admin','pharmacy','doctor','nurse'].includes(u.role))return send(res,403,{error:'Medication access denied'});const x=await body(req);p.medications=p.medications||[];const med={id:crypto.randomUUID(),drug:x.drug||'',dose:x.dose||'',route:x.route||'Oral',frequency:x.frequency||'',scheduledTime:x.scheduledTime||'',quantity:Number(x.quantity)||1,price:Number(x.price)||0,prescribedAt:now(),prescribedBy:u.name,administeredAt:'',administeredBy:''};p.medications.unshift(med);write('patients.json',patients);return send(res,200,med);}
      if(req.method==='POST'&&action==='medication-administer'){if(!['admin','nurse'].includes(u.role))return send(res,403,{error:'Only nurses or administrators can record medication administration'});const x=await body(req),m=(p.medications||[]).find(m=>m.id===x.medicationId);if(!m)return send(res,404,{error:'Medication not found'});m.administeredAt=now();m.administeredBy=u.name;write('patients.json',patients);return send(res,200,m);}
      if(req.method==='POST'&&action==='expense'){
        if(!allowed(u,'expenditures'))return send(res,403,{error:'Expenditure access denied'});
        const x=await body(req),unitPrice=Number(x.unitPrice??x.price)||0,quantity=Math.max(1,Number(x.quantity)||1),item=String(x.item??x.drug??x.description??'').trim();
        if(!item)return send(res,400,{error:'Expenditure item is required'});
        const ex={id:crypto.randomUUID(),patientId:p.id,patientName:p.name,category:String(x.category||EXPENSE_CATEGORY[u.role]),item,description:String(x.description||''),unitPrice,quantity,total:unitPrice*quantity,professionRole:u.role,profession:u.profession,recordedBy:u.name,recordedById:u.id,recordedAt:now()};
        const all=read('expenditures.json');all.unshift(ex);write('expenditures.json',all);p.expenses=p.expenses||[];p.expenses.push({id:ex.id,category:ex.category,drug:ex.item,description:ex.description,price:unitPrice,quantity,total:ex.total,recordedAt:ex.recordedAt,recordedBy:u.name,profession:u.profession});write('patients.json',patients);return send(res,201,ex);
      }
      if(req.method==='DELETE'&&!action)return send(res,403,{error:'Patient records are permanent and cannot be deleted. Mark the record inactive instead.'});
    }

    if(raw==='/api/expenditures'&&req.method==='GET'){
      if(!allowed(u,'expenditures'))return send(res,403,{error:'Expenditure access denied'});const all=read('expenditures.json');const visible=u.role==='admin'?all:all.filter(e=>e.professionRole===u.role||e.recordedById===u.id);return send(res,200,{records:visible,summary:{count:visible.length,total:visible.reduce((s,e)=>s+Number(e.total||0),0)}});
    }
    if(raw==='/api/expenditures'&&req.method==='POST'){
      if(!allowed(u,'expenditures'))return send(res,403,{error:'Expenditure access denied'});const x=await body(req),patients=read('patients.json');
      const p=patients.find(z=>z.id===x.patientId);if(!p)return send(res,404,{error:'Patient not found'});const item=String(x.item||'').trim();if(!item)return send(res,400,{error:'Item/service is required'});
      const unitPrice=Number(x.unitPrice)||0,quantity=Math.max(1,Number(x.quantity)||1),ex={id:crypto.randomUUID(),patientId:p.id,patientName:p.name,category:String(x.category||EXPENSE_CATEGORY[u.role]),item,description:String(x.description||''),unitPrice,quantity,total:unitPrice*quantity,professionRole:u.role,profession:u.profession,recordedBy:u.name,recordedById:u.id,recordedAt:now()};
      const all=read('expenditures.json');all.unshift(ex);write('expenditures.json',all);p.expenses=p.expenses||[];p.expenses.push({id:ex.id,category:ex.category,drug:ex.item,description:ex.description,price:unitPrice,quantity,total:ex.total,recordedAt:ex.recordedAt,recordedBy:u.name,profession:u.profession});write('patients.json',patients);return send(res,201,ex);
    }

    if(raw==='/api/messages'&&req.method==='GET'){const all=read('messages.json');return send(res,200,all.filter(m=>u.role==='admin'||m.toRole===u.role||m.fromUserId===u.id));}
    if(raw==='/api/messages'&&req.method==='POST'){const x=await body(req),patients=read('patients.json');if(!patients.some(p=>p.id===x.patientId))return send(res,404,{error:'Patient not found'});const target=String(x.toRole||'').toLowerCase();if(!ROLES.includes(target))return send(res,400,{error:'Invalid recipient profession'});if(target===u.role&&u.role!=='admin')return send(res,400,{error:'Choose another profession'});const all=read('messages.json'),m={id:crypto.randomUUID(),patientId:String(x.patientId),toRole:target,fromRole:u.role,fromUserId:u.id,fromName:u.name,subject:String(x.subject||'Patient information'),message:String(x.message||''),createdAt:now(),read:false};all.unshift(m);write('messages.json',all);return send(res,201,m);}
    if(raw.match(/^\/api\/messages\/[^/]+\/read$/)&&req.method==='POST'){const id=raw.split('/')[3],all=read('messages.json'),m=all.find(x=>x.id===id);if(!m)return send(res,404,{error:'Message not found'});if(u.role!=='admin'&&m.toRole!==u.role)return send(res,403,{error:'Message is not addressed to your profession'});m.read=true;m.readAt=now();write('messages.json',all);return send(res,200,m);}

    if(raw==='/api/attendance'&&req.method==='GET'){const all=read('attendance.json');if(u.role==='admin')return send(res,200,{records:all,users:read('users.json').filter(x=>x.role!=='admin').map(x=>({id:x.id,name:x.name,profession:x.profession,role:x.role}))});return send(res,200,{records:all.filter(a=>a.userId===u.id),users:[]});}
    if(raw==='/api/attendance/manual'&&req.method==='POST'){
      if(u.role!=='admin')return send(res,403,{error:'Only the administrator controls attendance'});const x=await body(req),all=read('attendance.json'),staff=read('users.json').find(z=>z.id===x.userId&&z.role!=='admin');if(!staff)return send(res,404,{error:'Staff member not found'});const date=String(x.date||'').slice(0,10);if(!date)return send(res,400,{error:'Attendance date is required'});const status=String(x.status||'Present'),valid=['Present','Absent','Late','Leave'];if(!valid.includes(status))return send(res,400,{error:'Invalid attendance status'});
      const existing=all.find(a=>a.userId===staff.id&&a.date===date);const record=existing||{id:crypto.randomUUID(),userId:staff.id,name:staff.name,profession:staff.profession,role:staff.role,date};Object.assign(record,{status,note:String(x.note||''),manual:true,markedAt:now(),markedBy:u.name,markedById:u.id});if(!existing)all.unshift(record);write('attendance.json',all);return send(res,200,record);
    }
    if(raw==='/api/attendance/checkin'||raw==='/api/attendance/checkout')return send(res,403,{error:'Attendance is manually controlled by the administrator.'});

    if(raw==='/api/periods'&&req.method==='GET')return send(res,200,read('periods.json'));
    if(raw==='/api/periods'&&req.method==='POST'){if(u.role!=='admin')return send(res,403,{error:'Only the administrator can create periods'});const x=await body(req),start=String(x.startDate||'').slice(0,10),end=String(x.endDate||'').slice(0,10);if(!x.name||!start||!end)return send(res,400,{error:'Period name, start date and end date are required'});const all=read('periods.json'),period={id:crypto.randomUUID(),name:String(x.name),startDate:start,endDate:end,description:String(x.description||''),createdAt:now(),createdBy:u.name};all.unshift(period);write('periods.json',all);return send(res,201,period);}

    if(raw==='/api/appointments'&&req.method==='GET'){let apps=read('appointments.json');if(u.role==='doctor')apps=apps.filter(a=>a.doctorId===u.id);return send(res,200,apps);}
    if(raw==='/api/appointments'&&req.method==='POST'){if(!allowed(u,'appointments'))return send(res,403,{error:'Appointment access denied'});const x=await body(req),apps=read('appointments.json'),a={id:crypto.randomUUID(),createdAt:now(),patient:x.patient||'',doctor:x.doctor||u.name,doctorId:x.doctorId||(u.role==='doctor'?u.id:''),date:x.date||'',time:x.time||'',reason:x.reason||'',status:'Scheduled'};apps.unshift(a);write('appointments.json',apps);return send(res,201,a);}
    if(raw==='/api/users'&&req.method==='GET'){if(u.role!=='admin')return send(res,403,{error:'Only administrators can view users'});return send(res,200,read('users.json').map(x=>({id:x.id,name:x.name,profession:x.profession,role:x.role,email:x.email})));}
    return send(res,404,{error:'API endpoint not found'});
  }catch(e){console.error(e);send(res,500,{error:'Server error'});}
});
server.listen(PORT, "0.0.0.0", () => {
  console.log(`Hospital Management System running on port ${PORT}`);
});
