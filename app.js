var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var bodyParser = require('body-parser');
var app = express();
const db = require('./database');
const bcrypt = require('bcrypt');
const cors = require('cors')



app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(bodyParser.json())

app.use(
  cors({
    origin: 'http://localhost:3001',
    credentials: true,
  })
);


app.post('/login', async(req, res, next)=>{
  const username = req.body.username;
  const password = req.body.password;

  try{
    const userSearch = "SELECT * FROM userdetails WHERE Username = ?";
    console.log(username)
    const user_query = db.format(userSearch,[username]);
    const [result] = await db.promise().query(user_query);
    
    if (result.length === 0){
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const hashedPassword = result[0].Password;
    console.log(hashedPassword)
    if(await bcrypt.compare(hashedPassword, password)){
      console.log(password);
      req.session.userID = result[0].user_ID;
      req.session.isLoggedIn = true;

    } else {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

  } catch {
    console.error(error);
    return res.status(500).json({ message: 'An unexpected error occurred' });
  }
})

app.post('/signup', async (req, res, next) => {
  const username = req.body.name; 
  const email = req.body.email;
  const password = req.body.password;
  const confirmPass = req.body.confirmPassword;

  try {
    if (password !== confirmPass) {
      return res.status(400).json({ message: 'Passwords do not match.' });
    }

    const userQuery = "SELECT * FROM userdetails WHERE Username = ?";
    const userSearch = await db.format(userQuery, [username]);
    const [result] = await db.promise().query(userSearch);


    if (result.length > 0) {
      return res.status(400).json({ message: 'Username already taken.' });
    }

    const hashedPassword = await bcrypt.hash(confirmPass, 12);
    const sqlInsert = "INSERT INTO userdetails (Username, Email, Password) VALUES (?, ?, ?)";
    const sqlQuery = db.format(sqlInsert, [username, email, hashedPassword]);

    await db.promise().query(sqlQuery);


  
    res.status(201).json({ message: 'User created successfully!' });
    console.log("User Created succesfully")

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

module.exports = app;
