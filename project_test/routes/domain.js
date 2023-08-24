var express = require('express');
var router = express.Router();

//   MySQL 로드
var mysql = require('mysql');
var pool = mysql.createPool({
    connectionLimit: 5,
    host     : 'localhost',
    user     : 'root',
    password : '1234',
    database : 'project_db'    
});

router.get('/', function(req, res, next) {
    res.redirect('/domain/list');
});

router.get('/list', function(req,res,next){
    pool.getConnection(function (err, connection) {
        var sql = "SELECT * FROM tb_packet_block";
        connection.query(sql, function (err, rows) {
            if (err) console.error("err : " + err);
           console.log("rows : " + JSON.stringify(rows));

            res.render('domain/list', {rows: rows?rows:{}});
            connection.release();
        });
    }); 
});


module.exports = router;