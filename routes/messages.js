const express = require("express");
const router = new express.Router();
const db = require("../db");
const ExpressError = require("../expressError");
const { ensureLoggedIn } = require("../middleware/auth");
const Message = require("../models/message");
/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

router.get("/:id", ensureLoggedIn, async function(req, res, next) {
    try {
        const message = await Message.get(req.params.id)
        if((message.from_user.username === req.user.username) || (message.to_user.username === req.user.username)){
            return res.json({ message })
        }
        else{
            throw new ExpressError("Unauthorized", 401)
        }
    } catch (err) {
      return next(err);
    }
});


/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post("/", ensureLoggedIn, async function(req, res, next) {
    try {
        let from_username = req.user.username;
        let to_username = req.body.to_username;
        let body = req.body.body;
        const message = await Message.create({from_username, to_username, body})
        return res.json({ message })
    } catch (err) {
      return next(err);
    }
});


/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post("/:id/read", ensureLoggedIn, async function(req, res, next) {
    try {
        //ensure only recipient may mark message as read
        let message = await Message.get(req.params.id)
        if(message.to_user.username === req.user.username){
            message = await Message.markRead(req.params.id)
            return res.json({ message })
        }
        else{
            throw new ExpressError("Unauthorized", 401)
        }

    } catch (err) {
      return next(err);
    }
});

module.exports = router;