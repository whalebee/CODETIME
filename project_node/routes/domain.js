var express = require('express')
var router = express.Router()
var mysql = require('mysql')
var fs = require('fs')
var ejs = require('ejs')
var bodyParser = require('body-parser');
var authCheck = require('../lib_login/authCheck.js');
var db = require('../lib_login/db.js');


router.use(bodyParser.urlencoded({ extended: false }))

// board pasing
router.get("/pasing/:cur", function (req, res) {

    if (!authCheck.isOwner(req, res)) {  // 로그인 안되어있으면 로그인 페이지로 이동시킴
        res.redirect('/auth/login');
        return false;
      }

    
    
    var page_size = 10; // 페이지 장수
    var page_list_size = 10; // 리스트 개수
    var no = ""; // LIMIT variable
    var totalPageCount = 0;

    var queryString = 'SELECT count(*) AS cnt FROM tb_packet_block'
    db.query(queryString, function (error2, data) {
        if (error2) {
            console.log(error2 + "mysql_error() main page");
            return
        }
        
        totalPageCount = data[0].cnt
 
        // console.log(req.params);
        var curPage = req.params.cur;

        // console.log("현재 페이지 : " + curPage, "전체 페이지 : " + totalPageCount);

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
            // console.log("몇번부터 몇번까지냐~~~~~~~" + no)

            var queryString = "SELECT *, DATE_FORMAT(created_at,'%Y년-%m월-%d일-%H시-%i분') created_at FROM tb_packet_block ORDER BY created_at DESC LIMIT ?,?";
            
            db.query(queryString, [no, page_size], function (error, result) {
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


    if (!authCheck.isOwner(req, res)) {  
        res.redirect('/auth/login');
        return false;
      }

    var page_size = 10;         // 페이지 장수
    var page_list_size = 10;    // 리스트 개수
    var no = "";                // LIMIT variable
    var totalPageCount = 0;

    var queryString = 'SELECT count(*) AS cnt FROM tb_packet_log'
    db.query(queryString, function (error2, data) {
        if (error2) {
            console.log(error2 + "mysql_error() main page");
            return
        }
        
        totalPageCount = data[0].cnt
 
        // console.log(req.params);
        var curPage = req.params.cur;

        // console.log("현재 페이지 : " + curPage, "전체 페이지 : " + totalPageCount);

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
            // console.log("몇번부터 몇번까지냐~~~~~~~" + no)

            var queryString = "SELECT *, DATE_FORMAT(created_at,'%Y년-%m월-%d일-%H시-%i분') created_at FROM tb_packet_log ORDER BY id DESC LIMIT ?,?";
            
            db.query(queryString, [no, page_size], function (error, result) {
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




// 메인 페이지
router.get('/', (req, res) => {
  if (!authCheck.isOwner(req, res)) {  
    res.redirect('/auth/login');
    return false;
  }
    authCheck.statusUI(req, res)
  res.redirect('/pasing_log/1');
})

// delete_block
router.get("/delete/:id", function (req, res) {

    if (!authCheck.isOwner(req, res)) {  
        res.redirect('/auth/login');
        return false;
      }

    console.log("block delete starting")

    db.query('DELETE FROM tb_packet_block WHERE id = ?', [req.params.id], function () {
        res.redirect('/pasing/1')
    });

})

// delete_log
router.get("/delete_log/:id", function (req, res) {

    if (!authCheck.isOwner(req, res)) {  
        res.redirect('/auth/login');
        return false;
      }

    console.log("log delete starting")

    db.query('DELETE FROM tb_packet_log WHERE id = ?', [req.params.id], function () {
        res.redirect('/pasing_log/1')
    });

})

// insert
router.get("/insert", function (req, res) {
    if (!authCheck.isOwner(req, res)) {  
        res.redirect('/auth/login');
        return false;
      }


    console.log("insert starting")

    fs.readFile('crud/insert.html', 'utf-8', function (error, data) {
        res.send(data)
    })

})
// insert post
router.post("/insert", function (req, res) {
    if (!authCheck.isOwner(req, res)) {  
        res.redirect('/auth/login');
        return false;
      }


    console.log("insert post starting")
    var body = req.body;
    db.query('INSERT INTO tb_packet_block (domain,comment) values (?,?)', [body.domain, body.comment], function () {
        res.redirect('/pasing/1');
    })

})

// edit
router.get("/edit/:id", function (req, res) {
    if (!authCheck.isOwner(req, res)) { 
        res.redirect('/auth/login');
        return false;
      }


    console.log("edit starting")

    fs.readFile('crud/edit.html', 'utf-8', function (error, data) {
        db.query('SELECT * FROM tb_packet_block WHERE id = ?', [req.params.id], function (error, result) {
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
    if (!authCheck.isOwner(req, res)) {  
        res.redirect('/auth/login');
        return false;
      }


    console.log("edit post starting")
    var body = req.body;
    db.query('UPDATE tb_packet_block SET domain = ?, comment = ? where id = ?',
        [body.domain, body.comment, req.params.id], function () {
            res.redirect('/pasing/1')
        })
})


// detail
router.get("/detail/:id", function (req, res) {

    if (!authCheck.isOwner(req, res)) {  
        res.redirect('/auth/login');
        return false;
      }

    // console.log("block_detail starting")

    fs.readFile('crud/detail.html', 'utf-8', function (error, data) {
        db.query("SELECT *, DATE_FORMAT(created_at,'%Y년-%m월-%d일-%H시-%i분') created_at FROM tb_packet_block WHERE id = ?", [req.params.id], function (error, result) {
            res.send(ejs.render(data, {
                data: result[0]
            }))
        })
    });
})

// detail log
router.get("/detail_log/:id", function (req, res) {
    if (!authCheck.isOwner(req, res)) {  
        res.redirect('/auth/login');
        return false;
      }

    console.log("log_detail starting")

    fs.readFile('crud/detail.html', 'utf-8', function (error, data) {
        console.log(req.params.id);
        db.query("SELECT *, DATE_FORMAT(created_at,'%Y년-%m월-%d일-%H시-%i분') created_at FROM tb_packet_log WHERE id = ?", [req.params.id], function (error, result) {
            console.log(result[0]);
            res.send(ejs.render(data, {
                data: result[0]
            }))
        })
    });
})

module.exports = router