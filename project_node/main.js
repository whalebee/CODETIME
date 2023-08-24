var express = require('express');
var app = express();                 
var bodyParser = require('body-parser');
var morgan = require('morgan');
const session = require('express-session');
const FileStore = require('session-file-store')(session);

var authRouter = require('./lib_login/auth');
var domainRouter = require('./routes/domain.js');
// var mysql = require('mysql');                       

app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: '~~~',	// 원하는 문자 입력
  resave: false,
  saveUninitialized: true,
  store:new FileStore(),
}))

// 인증 라우터
app.use('/auth', authRouter);

app.use(morgan('short'));                            // log middle ware
app.use(bodyParser.urlencoded({extended:false}));


app.use(domainRouter);

app.listen(3003,function(){
    console.log("Listening on port 3003") 
});   