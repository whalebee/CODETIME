const db = require('mysql');
const http = require('http');
const url = require('url');
var qs = require('querystring');
var db = mysql.createConnection({
    host:'localhost',
    user:'dbuser',
    password:'dbuserpass',
    database:'project_db'
  });
db.connect();


var app = http.createServer(function(request,response) {
    // 아 ~ 이거 언제 다하징 ㅋ.ㅋ


});
app.listen(4000);