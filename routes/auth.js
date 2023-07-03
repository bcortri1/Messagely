const express = require("express");
const router = new express.Router();
const db = require("../db");
const ExpressError = require("../expressError");
const User = require("../models/user");
const { SECRET_KEY } = require("../config");
const jwt = require("jsonwebtoken");



/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async function (req, res, next) {
    try {
        if (await User.authenticate(req.body.login)) {
            const username = req.body.login.username
            const token = jwt.sign({ username }, SECRET_KEY)
            await User.updateLoginTimestamp(username)
            return res.json({ token })
        }
        else {
            throw new ExpressError("Invalid Username/Password", 401)
        }
    } catch (err) {
        return next(err);
    }
});



/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async function (req, res, next) {
    try {
        await User.register(req.body)
        const token = jwt.sign(req.body.username, SECRET_KEY)
        await User.updateLoginTimestamp(req.body.username)
        return res.json({ token })
    } catch (err) {
        return next(err);
    }
});



module.exports = router;