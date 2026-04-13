
const express=require("express");
const cors=require("cors");
const bcrypt=require("bcrypt");
const jwt=require("jsonwebtoken");
const sqlite3=require("sqlite3").verbose();

const app=express();
app.use(cors());
app.use(express.json());

const SECRET="supersegredo";
const db=new sqlite3.Database("./database.db");

db.run(`CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE,
password TEXT,
blocked INTEGER DEFAULT 0
)`);

// ADMIN CREATE USER
app.post("/create-user", async (req,res)=>{
  const token=req.headers.authorization;
  try{
    const user=jwt.verify(token,SECRET);
    if(user.username!=="thzzxq7") return res.sendStatus(403);

    const hash=await bcrypt.hash(req.body.password,10);
    db.run("INSERT INTO users (username,password) VALUES (?,?)",
    [req.body.username,hash],
    (err)=>{
      if(err) return res.json({error:"Usuário já existe"});
      res.json({ok:true});
    });
  }catch{
    res.sendStatus(403);
  }
});

// LOGIN
app.post("/login",(req,res)=>{
  db.get("SELECT * FROM users WHERE username=?",[req.body.username],async(err,user)=>{
    if(!user) return res.json({error:"Usuário não encontrado"});
    if(user.blocked) return res.json({error:"Usuário bloqueado"});

    const valid=await bcrypt.compare(req.body.password,user.password);
    if(!valid) return res.json({error:"Senha errada"});

    const token=jwt.sign({id:user.id,username:user.username},SECRET);
    res.json({token,username:user.username});
  });
});

function auth(req,res,next){
  try{
    req.user=jwt.verify(req.headers.authorization,SECRET);
    next();
  }catch{
    res.sendStatus(403);
  }
}

// LIST USERS
app.get("/users",auth,(req,res)=>{
  if(req.user.username!=="thzzxq7") return res.sendStatus(403);
  db.all("SELECT id,username,blocked FROM users",[],(err,rows)=>res.json(rows));
});

// BLOCK
app.post("/block/:id",auth,(req,res)=>{
  if(req.user.username!=="thzzxq7") return res.sendStatus(403);
  db.run("UPDATE users SET blocked=1 WHERE id=?",[req.params.id],()=>res.json({ok:true}));
});

// UNBLOCK
app.post("/unblock/:id",auth,(req,res)=>{
  if(req.user.username!=="thzzxq7") return res.sendStatus(403);
  db.run("UPDATE users SET blocked=0 WHERE id=?",[req.params.id],()=>res.json({ok:true}));
});

app.listen(3000,()=>console.log("rodando"));
