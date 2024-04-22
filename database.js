const mysql = require('mysql2')
require("dotenv").config();

const db = mysql.createPool({
    host: process.env.DB_Hostname,
    port: process.env.DB_Port,
    user: process.env.DB_Username,
    password: process.env.DB_Password,
    database: process.env.DB_Database
})

module.exports = db;