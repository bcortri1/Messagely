const bcrypt = require("bcrypt");
const db = require("../db");
const ExpressError = require("../expressError");
const { BCRYPT_WORK_FACTOR } = require("../config")
/** User class for message.ly */



/** User of the site. */

class User {
    /** register new user -- returns
     *    {username, password, first_name, last_name, phone}
     */

    static async register({ username, password, first_name, last_name, phone }) {
        let hash = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
        
        const result = await db.query("INSERT INTO users (username, password, first_name, last_name, phone, join_at) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)", [username, hash, first_name, last_name, phone])
        return result.rows[0];
        //return {username, password, first_name, last_name, phone}
    }

    /** Authenticate: is this username/password valid? Returns boolean. */

    static async authenticate({username, password}) {
        const result = await db.query("SELECT password FROM users WHERE username=$1", [username]);
        const user = result.rows[0]
        const auth = await bcrypt.compare(password, user.password);
        return auth;
    }

    /** Update last_login_at for user */

    static async updateLoginTimestamp(username) {
        const result = await db.query("UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE username=$1", [username]);
    }

    /** All: basic info on all users:
     * [{username, first_name, last_name, phone}, ...] */

    static async all() {
        const result = await db.query("SELECT username, first_name, last_name, phone FROM users");
        return result.rows;
    }

    /** Get: get user by username
     *
     * returns {username,
     *          first_name,
     *          last_name,
     *          phone,
     *          join_at,
     *          last_login_at } */

    static async get(username) {
        const result = await db.query("SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users WHERE username=$1", [username]);
        return result.rows[0];
    }

    /** Return messages from this user.
     *
     * [{id, to_user, body, sent_at, read_at}]
     *
     *  to_user needs to return as
     *   {username, first_name, last_name, phone}
     */

    static async messagesFrom(username) {
        const result = await db.query("SELECT * FROM users, messages WHERE from_username=$1", [username]);
        const obj = result.rows.map(r =>({
            id:r.id,
            to_user:{
                username:r.username,
                first_name:r.first_name,
                last_name:r.last_name,
                phone:r.phone
            },
            body:r.body,
            sent_at:r.sent_at,
            read_at:r.read_at
        }))
        return obj;
    }

    /** Return messages to this user.
     *
     * [{id, from_user, body, sent_at, read_at}]
     *
     * from_user needs to return as
     *   {username, first_name, last_name, phone}
     */

    static async messagesTo(username) {
        const result = await db.query("SELECT * FROM users, messages WHERE to_username=$1", [username]);
        const obj = result.rows.map(r =>({
            id:r.id,
            from_user:{
                username:r.username,
                first_name:r.first_name,
                last_name:r.last_name,
                phone:r.phone
            },
            body:r.body,
            sent_at:r.sent_at,
            read_at:r.read_at
        }))
        return obj;
    }
}


module.exports = User;