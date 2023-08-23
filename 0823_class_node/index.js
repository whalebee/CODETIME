const http = require('http');
const express = require( 'express' );
const app = express();
const ejs = require('ejs');

const server = http.createServer(app);

const hostname = '127.0.0.1';
const port = 8080;


app.set('view engine', 'ejs');
app.set('views', './views');

app.get('/', (req, res) => {
    res.render('index');
})

app.listen(3000, () => {
    console.log("Listening on 3000 !!! \n");
})

server.listen(port, hostname, () => {
    console.log(`server running at http://${hostname}`)
})