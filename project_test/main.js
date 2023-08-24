var express = require('express');
var app = express();                
var mysql = require('mysql');            

var domainRouter = require('./routes/domain.js')
var userRouter = require('./routes/user.js')
app.use(userRouter) // use after login function
app.use(domainRouter)




app.listen(3003,function(){
    console.log("Listening on port 3003") 
})   