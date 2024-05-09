require("dotenv").config();

const express = require('express');
const mysql = require('mysql');
const bodyParser = require("body-parser");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const encryptText = require('./encryptFunction');
const decryptText = require('./decryptFunction');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));  

app.set("view engine", "ejs");
app.set("views", "views");

const db = mysql.createConnection({
    host: "localhost",
    database: "hugo",
    user: "root",
    password: ""
});

db.connect((err) => {
    if (err) throw err;
    console.log('Database connected');

    app.get("/", (req, res) => {
        res.render("login")
    })
    app.get("/register", (req, res) => {
        res.render("register");
    })

    app.get("/home", (req, res) => {
        try {
            const token = req.cookies.token;
            const secret = process.env.SECRET_KEY;
            const tokenObj = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
            const user = tokenObj.user;

            jwt.verify(token, secret);


            const sql = "SELECT * FROM encrypt12 WHERE user = ?";
            db.query(sql, user, (err, result) => {
                if (err) throw err;
                const texts = JSON.parse(JSON.stringify(result));
                res.render("home", { texts: texts, title: "SYMMETRIC ENCRYPT DECRYPT", decryptedTexts: [] });
            });
        }catch (err) {
            console.log(err);
            res.clearCookie("token");
            res.redirect('/');
        }
    });

    
    app.post("/inputdata", (req, res) => {
        const token = req.cookies.token;
        const tokenObj = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
        const user = tokenObj.user;
        const userInput = req.body.inputText;

        if (userInput == '') {
            res.redirect('/home');
        } else {
            const encrypted = encryptText(userInput);
            const encryptedText = encrypted.encrypted;
            const key = encrypted.AESKey;
            const insertSql = `INSERT INTO encrypt12 (encryptedText, plainText, encryptKey, user) VALUES ('${encryptedText}', '${userInput}', '${key}', '${user}')`;
            db.query(insertSql, (err, result) => {
                if (err) throw err;
                res.redirect("/home");
            });
        }
    });

    app.post("/decrypt_password", (req, res) => {
        const selectedTexts = req.body.selected_texts;
    
        const getPasswordsQuery = `SELECT user, encryptedText, encryptKey FROM encrypt12 WHERE id IN (?)`;
        db.query(getPasswordsQuery, selectedTexts, (err, results) => {
            if (err) throw err;
            const decryptedTexts = results.map(row => {
                const decryptedText = decryptText(row.encryptedText, row.encryptKey);
                return { user: row.user, text: decryptedText };
            });
            console.log(decryptedTexts);
            res.render("decrypt_password", { decryptedTexts: decryptedTexts });
        });
    });

    app.post("/deleteText", (req, res) => {
        const selectedTexts = req.body.selected_texts;
        console.log(selectedTexts);

        const deleteQuery = `DELETE FROM encrypt12 WHERE id IN (?)`;
        db.query(deleteQuery, selectedTexts, (err, results) => {
            if (err) throw err;
            console.log(results.affectedRows + " user(s) deleted");
            res.redirect("/home");
        });
    });

    app.post("/register", async (req, res) => {
        const user = req.body.user;
        const passRaw = req.body.pass;
        const salt = await bcrypt.genSalt();
        const hashedPass = await bcrypt.hash(passRaw, salt);

        const checkQuery = `SELECT * FROM user WHERE user = ?`
        db.query(checkQuery, user, (err, result) => {
            if (err) throw err;
            
            if (result.length > 0) {
                console.log('User already exists!');
                res.redirect('/register');
            }else {
                const addUserQuery = `INSERT INTO user (user, password) VALUES ('${user}', '${hashedPass}')`;
                db.query(addUserQuery, (err, result) => {
                    if (err) throw err;
                    res.redirect("/");
                })
            }
        })
    })

    app.post("/login", async (req, res) => {    
        const username = req.body.username;
        const password = req.body.password

        const checkQuery = `SELECT * FROM user WHERE user = ?`;
        db.query(checkQuery, username, (err, result) => {
            if (err) throw err;
            if (result.length > 0) {
                const user = JSON.parse(JSON.stringify(result[0]));
                const id = user.id;
                const pass = user.password;
                bcrypt.compare(password, pass, (err, isMatch) => {
                    if (err) throw err;
                    if (isMatch) {
                        const token = jwt.sign({id: id, user: user.user}, process.env.SECRET_KEY, {expiresIn: "5m"});
                        res.cookie("token", token, {
                            httpOnly: true
                        })
                        res.redirect('/home');
                    }else {
                        console.log('Invalid password');
                        res.redirect('/');
                    }
                })
            } else {
                console.log('User doesnt exist');
                res.redirect('/');
            }
        })

    })

    app.post("/back", (req, res) => {
        res.redirect("/home");
    })

app.listen(8000, () => {    
    console.log("Server Ready!")
});
});
