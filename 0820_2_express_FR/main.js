var express = require('express')
var app = express()
var fs = require('fs');
var template = require('./lib/template.js');
 
//route, routing
//app.get('/', (req, res) => res.send('Hello World!'))
app.get('/', function(request, response) { 
  fs.readdir('./data', function(error, filelist){
    var title = 'Welcome';
    var description = 'Hello, Node.js';
    var list = template.list(filelist);
    var html = template.HTML(title, list,
      `<h2>${title}</h2>${description}`,
      `<a href="/create">create</a>`
    ); 
    response.send(html);
  });
});
 
app.get('/page/:pageId/:chapterId', function(request, response) { 
  response.send(request.params);
});
 
app.get('/temp', function(request, response) { 
  response.sendFile( __dirname + "/temp" + '/index.html')
});


app.listen(3000, function() {
  console.log('Example app listening on port 3000!')
});