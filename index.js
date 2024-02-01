// With the bcrypt and the jwt the authentication and the authorization is done

require('dotenv').config()
const express=require('express')
const app=express();
const bcrypt=require('bcrypt')
const jwt=require("jsonwebtoken")


app.use(express.json());

const users=[]

app.get('/users',(req,res,next)=>[
    res.json(users)
]);

app.post('/signup',async(req,res,next)=>{
    const username=req.body.name;
    const hashedpassword=await bcrypt.hash(req.body.password,10);
    const user={
        name:username,
        password:hashedpassword
    }
    users.push(user);
    console.log(users);
    const accesstoken=jwt.sign(username,process.env.ACCESS_TOKEN_SECRET);
    res.json({accesstoken:accesstoken})
});

app.post('/login',(async(req,res,next)=>{
    const user=users.find(user=>user.name===req.body.name)
    if(user==null)return res.status(400).send();
    try{
        if(await bcrypt.compare(req.body.password,user.password)){
            authenticateToken(req,res,next);
        }
    }
    catch{
        res.status(403).send("There is an error happened in the js");
    }
    
    

}));

function authenticateToken(req,res,next){
    const authheader=req.headers['authorization']
    const token=authheader && authheader.split(' ')[1];
    if(token==null) return res.send("There is no token");
    jwt.verify(token,process.env.ACCESS_TOKEN_SECRET,(err,user)=>{
        if(err) return res.send(err);
        req.user=user;
        res.send("Authenticated");
    })
}

app.listen(3000);
