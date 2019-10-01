'use strict';//Strict mode throws more errors and disables some features in an effort to make your code more robust, readable, and accurate.
const express = require('express');//this nodejs framework is used to support socket communication
const multer = require('multer');//this is used to upload the file to the directory in the server
const app = express();//a constant variable used as a reference to express framework
const http = require('http').Server(app);//using HTTP to create a server-client connection via express framework
const io = require('socket.io')(http);//used as a library that enables real-time and bidirectional communication between the client and the server
const path = require('path');//used to work with directory for uploading files
const uuid = require('uuid/v4');//used to generate a unique Id for each user connection. Used to append this ID with files while uploading. V4 is used to generate randomness  of the UUID

//function where file is uploaded to the 'upload' folder using multer when the call is received from the client side. 
const storage = multer.diskStorage({
    destination: './uploads/',
    filename(req, file, cb) {
        const ext = path.extname(file.originalname);
        const fileName = `${uuid()}${ext}`;
        cb(null, fileName);
    }
});

//multer function is called where the storage variable is used
const upload = multer({ storage });

//middleware used to divert the route of express to save static files
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));

//this function is a API call for uploading the file
app.post('/api/upload', upload.single('file'), (req, res, next) => {
    res.json(req.file)
});

//function where the socket connection happens between the server and client
io.on('connection', function (socket) {
   
//a function where a new user is tagged to the server for display on the receiving client
    socket.on('user:SentSocket', data => {
        data.userId = socket.id;
        if(data.Anewuser){
        	console.log("A new user " + data.Anewuser + " is connected to the chat");
        }
        else if(data.Bnewuser){
        	console.log("A new user " + data.Bnewuser + " is connected to the chat");
        }     	
        io.emit('user:ReceiveSocket', data);
    });

//a function where a new message is tagged to the server for display on the receiving client 
    socket.on('message:new', data => {
        io.emit('message:received', data);
    });
});

//function where the server port is 3000
http.listen(3000, function () {
    console.log('listening on port number 3000');
});