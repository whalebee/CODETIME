const mysql = require('mysql');
const express = require('express');
const app = express();
const dbconfig   = require('./config/db_config.js');
const conn = mysql.createConnection(dbconfig);
const http = require('http');

app.get('/',function(req, res){

    

	conn.connect(); // mysql과 연결

    var sql = 'select * from tb_packet_block'
    conn.query(sql, function(err, rows, fields)
    {
        if (err) {
            console.error('error connecting: ' + err.stack);
        }
        res.send(rows);
    });
    conn.end(); // 연결 해제
}); 

app.get('/' , function(req, res) {

    res.sendfile('./index.html');
})
 
app.listen(3333, function(){
	console.log('Listening at 3333');
}); 