import express from 'express'
import session from 'express-session'
import bcrypt from 'bcrypt'
import mongoose from 'mongoose'
import passport from 'passport'
import {Strategy as LocalStrategy} from 'passport-local'
import {dirname} from 'path'
import {fileURLToPath} from 'url'
import {User} from './models/user.js'
import dotenv from 'dotenv'
import minimist from 'minimist'
import {fork} from 'child_process'
import cluster from 'cluster'
import os, { hostname } from 'os'
import compression from 'compression'
import log4js from 'log4js'

log4js.configure({
    appenders: {
        miLoggerConsole: { type: 'console' },
        miLoggerFile: { type: 'file', filename: 'warns.log' },
        miLoggerFile2: { type: 'file', filename: 'errors.log' }
    },
    categories: {
        default: { appenders: ['miLoggerConsole'], level: 'info' },
        archivo: { appenders: ['miLoggerFile'], level: 'warn' },
        archivo2: { appenders: ['miLoggerFile2'], level: 'error' },
    }
})

let loggerConsole = log4js.getLogger()
let loggerWarn = log4js.getLogger('archivo')
let loggerError = log4js.getLogger('archivo2')

const numCPUs = os.cpus().length

dotenv.config()

const options = {default:{modo:'fork'}, alias:{p:'port'}}
const args = minimist(process.argv.slice(2),options)

const __dirname = dirname(fileURLToPath(import.meta.url))

const app = express()
const PORT = args.port||8080

switch (args.modo) {
    case 'fork':
        const server = app.listen(PORT,()=>loggerConsole.info(`Listening on port ${PORT}`))
        break;
    case 'cluster':
        if(cluster.isPrimary){
            loggerConsole.info(`master ${process.pid} is running`)
            for(let i = 0;i<numCPUs;i++){
                cluster.fork()
            }
            cluster.on('exit',(worker,code,signal)=>{
                loggerConsole.info(`worker ${worker.process.pid} died`)
            })
        } else {
            const server = app.listen(PORT,()=>loggerConsole.info(`Listening on port ${PORT}`))
            console.log(`worker ${process.pid} started`)
        }
        break;
    default:
        break;
}

app.set('views', __dirname+'/views')
app.set('view engine', 'ejs')

app.use(express.json())
app.use(express.urlencoded({extended:true}))

app.use(compression())

app.use(session({
    secret: process.env.SECRET,
    resave:true,
    saveUninitialized:true,
    cookie:{
        expires: 30000
    }
}))

app.use(passport.initialize())
app.use(passport.session())

passport.serializeUser((user,done)=>{return done(null,user)})
passport.deserializeUser((id,done)=>{
    User.findById(id,(err,user)=>{
        return done(err,user.id)
    })
})

const createHash = (password) => {
    return bcrypt.hashSync(
        password,
        bcrypt.genSaltSync(10)
    )
}

const isUserLogged = (req,res,next)=>{
    if(req.isAuthenticated()) return next()
    res.redirect('/login')
}

passport.use('signupStrategy', new LocalStrategy(
    (username, password, done)=>{
        User.findOne({username:username},(err,user)=>{
            if(err) return done(err)
            if(user) return done(null,false,{message:'user already register'})

            const newUser = {
                username: username,
                password: createHash(password)
            }

            User.create(newUser,(err,userCreated)=>{
                if(err) return done(err)
                return done(null,userCreated)
            })
        })
    }
))

passport.use('loginStrategy', new LocalStrategy(
    (username, password, done)=>{
        User.findOne({username:username},(err,userFound)=>{
            if(err) return done(err)
            if(!userFound) return done(null,false,{message:'user dont exist'})
            if(!bcrypt.compareSync(password,userFound.password)) return done(null,false,{message:'invalid password'})
            return done(null,userFound)
        })
    }
))

const URL = process.env.URL

mongoose.connect(URL,{
    useNewUrlParser:true,
    useUnifiedTopology:true
},(err)=>{
    try {
        if(err) throw new Error('unable to connect to DB')
        loggerConsole.info('connected to DB')
    } catch (error) {
        loggerError.error(error)
        loggerConsole.error(error)
    }
})

app.get('/',(req,res)=>{
    res.render('home',{prueba:0})
    loggerConsole.info(`${req.method} to ${req.get('host')}${req.originalUrl}`)
})
app.get('/signup',(req,res)=>{
    if(req.isAuthenticated()) return res.redirect('/profile')
    res.render('signup')
    loggerConsole.info(`${req.method} to ${req.get('host')}${req.originalUrl}`)
})
app.get('/login',(req,res)=>{
    if(req.isAuthenticated()) return res.redirect('/profile')
    res.render('login')
    loggerConsole.info(`${req.method} to ${req.get('host')}${req.originalUrl}`)
})
app.get('/profile',isUserLogged,(req,res)=>{
    res.render('profile',{user:req.session.passport.user.username})
    loggerConsole.info(`${req.method} to ${req.get('host')}${req.originalUrl}`)
})
app.get('/logout',(req,res)=>{
    if(req.isAuthenticated()) {
        req.logOut()
        res.render('logout') 
    }
    res.redirect('/')
    loggerConsole.info(`${req.method} to ${req.get('host')}${req.originalUrl}`)
})

app.get('/userExist',(req,res)=>{
    res.render('userExist')
    loggerConsole.info(`${req.method} to ${req.get('host')}${req.originalUrl}`)
})
app.get('/invalidPassword',(req,res)=>{
    res.render('invalidPassword')
    loggerConsole.info(`${req.method} to ${req.get('host')}${req.originalUrl}`)
})

app.post('/signup',passport.authenticate('signupStrategy',{
    failureRedirect:'/userExist'
}),(req,res)=>{
    res.redirect('/profile')
    loggerConsole.info(`${req.method} to ${req.get('host')}${req.originalUrl}`)
})

app.post('/login',passport.authenticate('loginStrategy',{
    failureRedirect:'/invalidPassword'
}),(req,res)=>{
    res.redirect('/profile')
    loggerConsole.info(`${req.method} to ${req.get('host')}${req.originalUrl}`)
})

app.get('/info',(req,res)=>{
    const info = {
        argv: args,
        platform: process.platform,
        version: process.version,
        rss: process.memoryUsage,
        path: process.execPath,
        pid: process.pid,
        folder: process.env.PWD,
        CPUs: numCPUs
    }
    console.log(info)
    res.send(info)
    loggerConsole.info(`${req.method} to ${req.get('host')}${req.originalUrl}`)
})

const child = fork('./src/child.js')

// app.get('/api/random',(req,res)=>{
//     let objFinal = []
//     let cant = req.query.cant
//     child.send(cant||50000000)
//     child.on('message',obj=>{
//         objFinal = obj
//     })
    
//     setTimeout(() => {
//         res.json({PID:process.pid, objFinal})
//     }, 3500);

// })

app.get('*',(req,res)=>{
    loggerConsole.warn(`${req.method} to ${req.get('host')}${req.originalUrl}`)
    loggerWarn.warn(`${req.method} to ${req.get('host')}${req.originalUrl}`)
})