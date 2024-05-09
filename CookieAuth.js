require("dotenv").config();

const jwt = require('jsonwebtoken');

exports.cookieAuth = (req, res, next) => {
    const token = req.cookies.token;
    try {
        const check = jwt.verify(token, process.env.SECRET_KEY);
        console.log('check');
    } catch (err) {

    }
}