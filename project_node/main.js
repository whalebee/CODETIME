var express = require('express');
var app = express()                 
var mysql = require('mysql')                       
var bodyParser = require('body-parser');
var morgan = require('morgan')    

app.use(morgan('short'))                            // log middle ware
app.use(bodyParser.urlencoded({extended:false}))

// app.use(express.static('./public'))                 // use after login function
// var userRouter = require('./routes/user.js')

var domainRouter = require('./routes/domain.js')
// app.use(userRouter) // use after login function
app.use(domainRouter)
       
app.listen(3003,function(){
    console.log("Listening on port 3003") 
})   