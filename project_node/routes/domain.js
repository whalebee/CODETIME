var express = require('express')
var router = express.Router()
var mysql = require('mysql')
var fs = require('fs')
var ejs = require('ejs')
var bodyParser = require('body-parser');


router.use(bodyParser.urlencoded({ extended: false }))

// board pasing
router.get("/pasing/:cur", function (req, res) {

    
    var page_size = 10; // 페이지 장수
    var page_list_size = 10; // 리스트 개수
    var no = ""; // LIMIT variable
    var totalPageCount = 0;

    var queryString = 'SELECT count(*) AS cnt FROM tb_packet_block'
    getConnection().query(queryString, function (error2, data) {
        if (error2) {
            console.log(error2 + "mysql_error() main page");
            return
        }
        
        totalPageCount = data[0].cnt
 
        console.log(req.params);
        var curPage = req.params.cur;

        console.log("현재 페이지 : " + curPage, "전체 페이지 : " + totalPageCount);

        if (totalPageCount < 0) {
            totalPageCount = 0
        }

        var totalPage = Math.ceil(totalPageCount / page_size);
        var totalSet = Math.ceil(totalPage / page_list_size);        
        var curSet = Math.ceil(curPage / page_list_size) 
        var startPage = ((curSet - 1) * 10) + 1 
        var endPage = (startPage + page_list_size) - 1; 

        if (curPage < 0) {
            no = 0
        } else {
            //0보다 크면 limit 함수에 들어갈 첫번째 인자 값 구하기
            no = (curPage - 1) * 10
        }

        

        console.log('[0] curPage : ' + curPage + 
                    ' | [1] page_list_size : ' + page_list_size + 
                    ' | [2] page_size : ' + page_size + 
                    ' | [3] totalPage : ' + totalPage + 
                    ' | [4] totalSet : ' + totalSet + 
                    ' | [5] curSet : ' + curSet + 
                    ' | [6] startPage : ' + startPage + 
                    ' | [7] endPage : ' + endPage
                    )

        var result2 = {
            "curPage": curPage,
            "page_list_size": page_list_size,
            "page_size": page_size,
            "totalPage": totalPage,
            "totalSet": totalSet,
            "curSet": curSet,
            "startPage": startPage,
            "endPage": endPage
        };


        fs.readFile('crud/list_test.html', 'utf-8', function (error, data) {

            if (error) {
                console.log("ejs오류" + error);
                return
            }
            console.log("몇번부터 몇번까지냐~~~~~~~" + no)

            var queryString = "SELECT *, DATE_FORMAT(created_at,'%Y년-%m월-%d일-%H시-%i분') created_at FROM tb_packet_block ORDER BY created_at DESC LIMIT ?,?";
            
            getConnection().query(queryString, [no, page_size], function (error, result) {
                if (error) {
                    console.log("페이징 에러" + error);
                    return
                }
                    
                res.send(ejs.render(data, {
                    data: result,
                    pasing: result2
                }));
            });
        }); 

 

    })

})


// board log
router.get("/pasing_log/:cur", function (req, res) {

    
    var page_size = 10; // 페이지 장수
    var page_list_size = 10; // 리스트 개수
    var no = ""; // LIMIT variable
    var totalPageCount = 0;

    var queryString = 'SELECT count(*) AS cnt FROM tb_packet_log'
    getConnection().query(queryString, function (error2, data) {
        if (error2) {
            console.log(error2 + "mysql_error() main page");
            return
        }
        
        totalPageCount = data[0].cnt
 
        console.log(req.params);
        var curPage = req.params.cur;

        console.log("현재 페이지 : " + curPage, "전체 페이지 : " + totalPageCount);

        if (totalPageCount < 0) {
            totalPageCount = 0
        }

        var totalPage = Math.ceil(totalPageCount / page_size);
        var totalSet = Math.ceil(totalPage / page_list_size);        
        var curSet = Math.ceil(curPage / page_list_size) 
        var startPage = ((curSet - 1) * 10) + 1 
        var endPage = (startPage + page_list_size) - 1; 

        if (curPage < 0) {
            no = 0
        } else {
            //0보다 크면 limit 함수에 들어갈 첫번째 인자 값 구하기
            no = (curPage - 1) * 10
        }

        

        console.log('[0] curPage : ' + curPage + 
                    ' | [1] page_list_size : ' + page_list_size + 
                    ' | [2] page_size : ' + page_size + 
                    ' | [3] totalPage : ' + totalPage + 
                    ' | [4] totalSet : ' + totalSet + 
                    ' | [5] curSet : ' + curSet + 
                    ' | [6] startPage : ' + startPage + 
                    ' | [7] endPage : ' + endPage
                    )

        var result2 = {
            "curPage": curPage,
            "page_list_size": page_list_size,
            "page_size": page_size,
            "totalPage": totalPage,
            "totalSet": totalSet,
            "curSet": curSet,
            "startPage": startPage,
            "endPage": endPage
        };


        fs.readFile('crud/list_log.html', 'utf-8', function (error, data) {

            if (error) {
                console.log("ejs오류" + error);
                return
            }
            console.log("몇번부터 몇번까지냐~~~~~~~" + no)

            var queryString = "SELECT *, DATE_FORMAT(created_at,'%Y년-%m월-%d일-%H시-%i분') created_at FROM tb_packet_log ORDER BY created_at DESC LIMIT ?,?";
            
            getConnection().query(queryString, [no, page_size], function (error, result) {
                if (error) {
                    console.log("페이징 에러" + error);
                    return
                }
                    
                res.send(ejs.render(data, {
                    data: result,
                    pasing_log: result2
                }));
            });
        }); 

 

    })

})


// main
router.get("/", function (req, res) {
    console.log("main")
    res.redirect('/pasing_log/' + 1) // log ? block ? -> select log ㄱㄱ
});

// delete
router.get("/delete/:id", function (req, res) {
    console.log("delete starting")

    getConnection().query('DELETE FROM tb_packet_block WHERE id = ?', [req.params.id], function () {
        res.redirect('/')
    });

})
// insert
router.get("/insert", function (req, res) {
    console.log("insert starting")

    fs.readFile('crud/insert.html', 'utf-8', function (error, data) {
        res.send(data)
    })

})
// insert post
router.post("/insert", function (req, res) {
    console.log("insert post starting")
    var body = req.body;
    getConnection().query('INSERT INTO tb_packet_block (domain,dst_port) values (?,?)', [body.domain, body.dst_port], function () {
        res.redirect('/');
    })

})
// edit
router.get("/edit/:id", function (req, res) {
    console.log("edit starting")

    fs.readFile('crud/edit.html', 'utf-8', function (error, data) {
        getConnection().query('SELECT * FROM tb_packet_block WHERE id = ?', [req.params.id], function (error, result) {
            console.log(result[0]);
            res.send(ejs.render(data, {
                data: result[0]
            }))
            console.log(result[0]);
        })
    });

})
// edit post
router.post("/edit/:id", function (req, res) {
    console.log("edit post starting")
    var body = req.body;
    getConnection().query('UPDATE tb_packet_block SET domain = ?, dst_port = ? where id = ?',
        [body.domain, body.dst_port, req.params.id], function () {
            res.redirect('/')
        })
})


// detail
router.get("/detail/:id", function (req, res) {
    console.log("detail starting")

    fs.readFile('crud/detail.html', 'utf-8', function (error, data) {
        getConnection().query("SELECT *, DATE_FORMAT(created_at,'%Y년-%m월-%d일-%H시-%i분') created_at FROM tb_packet_block WHERE id = ?", [req.params.id], function (error, result) {
            res.send(ejs.render(data, {
                data: result[0]
            }))
        })
    });
})




//mysql db log in
var pool = mysql.createPool({
    connectionLimit: 10,
    host: '192.168.111.12',
    user: 'dbuser',
    database: 'project_db',
    password: 'dbuserpass'
})

//DB connect
function getConnection() {
    return pool
}

module.exports = router