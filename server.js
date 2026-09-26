const http=require('http');
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');

const PORT=Number(process.env.PORT||3000);
const PUBLIC=path.join(__dirname,'public');
const DB=path.join(__dirname,'data.json');

if(!process.env.ADMIN_PASSWORD){
  console.error('ERROR: set ADMIN_PASSWORD before starting the server.');
  console.error("Termux: export ADMIN_PASSWORD='your-secret-password'");
  process.exit(1);
}

const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD;
const sessions=new Map();
const attempts=new Map();
let anime=fs.existsSync(DB)?JSON.parse(fs.readFileSync(DB,'utf8')):[];

function send(res,status,type,body,extra={}){
  res.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store',...extra});
  res.end(body);
}
function json(res,status,obj,extra={}){send(res,status,'application/json; charset=utf-8',JSON.stringify(obj),extra)}
function readBody(req){
  return new Promise((resolve,reject)=>{
    let s='';
    req.on('data',d=>{
      s+=d;
      if(s.length>1e6){req.destroy();reject(new Error('body too large'))}
    });
    req.on('end',()=>{try{resolve(JSON.parse(s||'{}'))}catch(e){reject(e)}});
  });
}
function hashPassword(password){
  return crypto.scryptSync(String(password),ADMIN_PASSWORD,32,{N:16384,r:8,p:1}).toString('hex');
}
const passwordDigest=hashPassword(ADMIN_PASSWORD);

function getSession(req){
  const c=req.headers.cookie||'';
  const m=c.match(/(?:^|;\s*)ah2_session=([^;]+)/);
  if(!m)return false;
  const exp=sessions.get(m[1]);
  if(!exp)return false;
  if(exp<Date.now()){sessions.delete(m[1]);return false}
  return true;
}
function clientKey(req){return String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0]}
function allowedLogin(req){
  const key=clientKey(req), now=Date.now();
  const x=attempts.get(key)||{n:0,until:0};
  if(x.until>now)return false;
  return true;
}
function failedLogin(req){
  const key=clientKey(req), now=Date.now();
  const x=attempts.get(key)||{n:0,until:0};
  x.n++;
  if(x.n>=5){x.n=0;x.until=now+10*60*1000}
  attempts.set(key,x);
}
function successfulLogin(req){attempts.delete(clientKey(req))}
function safeFile(p){
  const clean=path.normalize(p).replace(/^(\.\.[/\\])+/, '');
  return path.join(PUBLIC,clean==='/'?'index.html':clean);
}

const server=http.createServer(async(req,res)=>{
  try{
    if(req.method==='POST'&&req.url==='/api/admin/login'){
      if(!allowedLogin(req))return json(res,429,{error:'too_many_attempts'});
      const b=await readBody(req);
      const supplied=hashPassword(String(b.password||''));
      const ok=crypto.timingSafeEqual(Buffer.from(supplied,'hex'),Buffer.from(passwordDigest,'hex'));
      if(!ok){failedLogin(req);return json(res,401,{error:'unauthorized'})}
      successfulLogin(req);
      const token=crypto.randomBytes(32).toString('hex');
      sessions.set(token,Date.now()+6*60*60*1000);
      const secure=process.env.COOKIE_SECURE==='1'?'; Secure':'';
      return json(res,200,{ok:true},{
        'Set-Cookie':`ah2_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=21600${secure}`
      });
    }

    if(req.method==='POST'&&req.url==='/api/admin/logout'){
      const c=req.headers.cookie||'',m=c.match(/(?:^|;\s*)ah2_session=([^;]+)/);
      if(m)sessions.delete(m[1]);
      return json(res,200,{ok:true},{'Set-Cookie':'ah2_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'});
    }

    if(req.method==='GET'&&req.url==='/api/admin/status'){
      return json(res,200,{authenticated:getSession(req)});
    }

    if(req.method==='GET'&&req.url==='/api/catalog'){
      return json(res,200,anime);
    }

    if(req.method==='POST'&&req.url==='/api/admin/anime'){
      if(!getSession(req))return json(res,401,{error:'unauthorized'});
      const b=await readBody(req);
      const title=String(b.title||'').trim();
      if(!title)return json(res,400,{error:'title'});
      const item={
        id:Date.now(),
        t:title.slice(0,160),
        g:'custom',
        e:Math.max(1,Math.min(999,Number(b.episodes)||1)),
        img:String(b.image||'').slice(0,1000),
        meta:'Моя библиотека'
      };
      anime.unshift(item);
      fs.writeFileSync(DB,JSON.stringify(anime,null,2));
      return json(res,200,anime);
    }

    if(req.method==='GET'){
      const u=new URL(req.url,'http://localhost');
      let file=safeFile(decodeURIComponent(u.pathname));
      if(!fs.existsSync(file)||fs.statSync(file).isDirectory())file=path.join(PUBLIC,'index.html');
      const ext=path.extname(file).toLowerCase();
      const types={
        '.html':'text/html; charset=utf-8',
        '.css':'text/css',
        '.js':'text/javascript',
        '.json':'application/json',
        '.svg':'image/svg+xml'
      };
      return send(res,200,types[ext]||'application/octet-stream',fs.readFileSync(file));
    }
  }catch(e){
    console.error(e);
    return json(res,500,{error:'server'});
  }
});

server.listen(PORT,'0.0.0.0',()=>console.log(`AnimeHub 2.2: http://0.0.0.0:${PORT}`));
