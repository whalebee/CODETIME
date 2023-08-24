var express = require('express');
var app = express();

const maria = require('./database/connect/maria');
maria.connect();

app.set('view engine','ejs');
app.use(express.static(__dirname + '/public'));

app.get('/hello', function(req,res){
  res.render('hello', {name:req.query.nameQuery});
});

app.get('/hello/:nameParam', function(req,res){
  res.render('hello', {name:req.params.nameParam});
});

app.get('/log', function(req,res){
  //res.render('hello');
  maria.query('SELECT * FROM tb_cpu_usage ORDER BY created_at DESC limit 10',
  	function(err, rows, fields){
  		if(!err) {
  			
  			var response_text = "";
  			// add html part
  			response_text += "<!DOCTYPE html>" ;
  			response_text += "<html>" ;
  			response_text += "<head>" ;
  			response_text += "<meta charset=\"utf-8\">" ;
  			response_text += '<link rel="stylesheet" href="/css/master.css">' ;
  			response_text += "<title>LOG PAGE</title>" ;
			response_text += "</head>" ;
  			
  			response_text += "<table><thead>" ;
  			response_text += "<th>ID</th>" ;
 			response_text += "<th>CREATED_AT</th>" ;
 			response_text += "<th>DOMAIN</th>" ;
 			response_text += "<th>RESULT</th>" ;
 			response_text += "</thead>" ;
 			
 			response_text += "<tbody>" ;
  			//response_text = response_text + JSON.stringify(rows);
  			for ( var row of rows ) {
  				response_text += "<tr>" ;
				response_text += `<td>${row.id}</td>`;
				response_text += `<td>${row.created_at}</td>`;
				response_text += `<td>${row.domain}</td>`;
				response_text += `<td>${row.result}</td>`;
  				response_text += "</tr>" ;
				
  			}
			response_text += "</tbody>" ;
 			
 			response_text += "</table>" ;

			console.log("DEBUG: response_text = " + response_text + " .");
  			res.send( response_text );	// responses send rows
		} else {
			console.log("ERR : " + err);
			res.send(err);	// response send err
		} // end of if.
  	}	// end of function .
  );	// end of maria.query .
});

app.get('/domain', function(req,res){
  //res.render('hello');
  maria.query('SELECT * FROM tb_domain_list ORDER BY id ASC',
  	function(err, rows, fields){
  		if(!err) {
  			
  			var response_text = "";
  			// add html part
  			response_text += "<!DOCTYPE html>" ;
  			response_text += "<html>" ;
  			response_text += "<head>" ;
  			response_text += "<meta charset=\"utf-8\">" ;
  			response_text += '<link rel="stylesheet" href="/css/master.css">' ;
  			response_text += "<title>domain list PAGE</title>" ;
			response_text += "</head>" ;
  			
  			response_text += "<table><thead>" ;
  			response_text += "<th>ID</th>" ;
 			response_text += "<th>DOMAIN</th>" ;
 			response_text += "<th>CREATED_AT</th>" ;
 			response_text += "<th>주석</th>" ;
 			response_text += "</thead>" ;
 			
 			response_text += "<tbody>" ;
  			//response_text = response_text + JSON.stringify(rows);
  			for ( var row of rows ) {
  				response_text += "<tr>" ;
				response_text += `<td>${row.id}</td>`;
				response_text += `<td>${row.domain}</td>`;
				response_text += `<td>${row.created_at}</td>`;
				response_text += `<td>${row.comment}</td>`;
  				response_text += "</tr>" ;
				
  			}
			response_text += "</tbody>" ;
 			
 			response_text += "</table>" ;

			console.log("DEBUG: response_text = " + response_text + " .");
  			res.send( response_text );	// responses send rows
		} else {
			console.log("ERR : " + err);
			res.send(err);	// response send err
		} // end of if.
  	}	// end of function .
  );	// end of maria.query .
});


var port = 3000;
app.listen(port, function(){
  console.log('server on! http://localhost:'+port);
});
