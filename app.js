  var createError = require('http-errors');
  var express = require('express');
  var path = require('path');
  var cookieParser = require('cookie-parser');
  var morgan = require('morgan');
  var bodyParser = require('body-parser');
  const db = require('./database');
  const bcrypt = require('bcrypt');
  const cors = require('cors');
  const session = require('express-session');
  const passport = require('passport');
  const LocalStrategy = require('passport-local').Strategy;
  require("dotenv").config();

  const app = express();


  app.use(
    cors({
      origin: 'http://localhost:3001',
      credentials: true,
    })
  );
  app.use(session({
    secret: 'skillodyssey',
    resave: false,
    saveUninitialized: true,
    cookie: {secure: false,  sameSite: 'lax'}
  }));

  app.use(passport.initialize());
  app.use(passport.session());



  passport.use(new LocalStrategy(
    async function(username, password, done) {
      try {
        const userSearch = "SELECT * FROM userdetails WHERE Username = ?";
        const [result] = await db.promise().query(userSearch, [username]);

        if (result.length === 0) {
          return done(null, false, { message: 'User does not exist' });
        }

        const user = result[0];
        const match = await bcrypt.compare(password, user.Password);

        if (match) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Invalid password' });
        }
      } catch (error) {
        return done(error);
      }
    }
  ));

  passport.deserializeUser(async (id, done) => {
    try {
      const userSearch = "SELECT * FROM userdetails WHERE user_ID = ?";
      const [result] = await db.promise().query(userSearch, [id]);

      if (result.length === 0) {
        return done(new Error('User not found'));
      }

      const user = result[0];
      done(null, user);
    } catch (error) {
      done(error);
    }
  });


  passport.serializeUser((user, done) => {
    done(null, user.user_ID);
  });

  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  app.use(cookieParser());
  app.use(morgan('dev'));


  app.post('/login', passport.authenticate('local'), (req, res) => {
    if (req.user) { // Check if user is authenticated
      res.json({ message: 'Login successful', username: req.user.Username, isLoggedIn: true }); // Send username in response
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  });

  



  app.get('/api/user', passport.authenticate('local'), (req, res) => {
    // User is authenticated (checked by passport.authenticate)
    if (req.user) {
      const username = req.user.Username;
      res.json({ username });
    } else {
      res.status(401).json({ message: 'Unauthorized' });
    }
  });


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

  app.get('/logout', async(req, res, next) =>{
    req.logout(); 
    res.redirect('/');
  })


  module.exports = app;
