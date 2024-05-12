const router = require('express').Router()
var express = require('express');
var cookieParser = require('cookie-parser');
var morgan = require('morgan');
var bodyParser = require('body-parser');
const db = require('./database');
const bcrypt = require('bcrypt');
const cors = require('cors');
const session = require('express-session');


router.use(bodyParser.urlencoded({ extended: false }))
router.use(bodyParser.json())
router.use(morgan('dev'));
router.use(express.json());
router.use(express.urlencoded({ extended: false }));
router.use(cookieParser());
router.use(bodyParser.json())
router.use(express.json());


module.exports = router;