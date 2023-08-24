var express = require('express');
var app = express();                 
var mysql = require('mysql');                       
var bodyParser = require('body-parser');
var morgan = require('morgan');
// new
const session = require('express-session');
const FileStore = require('session-file-store')(session);

var authRouter = require('./lib_login/auth');
var authCheck = require('./lib_login/authCheck.js');
var template = require('./lib_login/template.js');
//------------------------


// new
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: '~~~',	// 원하는 문자 입력
  resave: false,
  saveUninitialized: true,
  store:new FileStore(),
}))


// 인증 라우터
app.use('/auth', authRouter);

//------------------------


app.use(morgan('short'));                            // log middle ware
app.use(bodyParser.urlencoded({extended:false}));


// app.use(express.static('./public'))                 // use after login function
// var userRouter = require('./routes/user.js')

var domainRouter = require('./routes/domain.js');
// app.use(userRouter) // use after login function
app.use(domainRouter);



       
app.listen(3003,function(){
    console.log("Listening on port 3003") 
});   