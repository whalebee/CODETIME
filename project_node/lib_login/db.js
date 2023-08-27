var mysql = require('mysql');
var db = mysql.createConnection({
    host: '192.168.35.4',
    user: 'dbuser',
    password: 'dbuserpass',
    database: 'project_db'
});

db.connect();

module.exports = db;