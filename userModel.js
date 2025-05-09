import bcrypt from "bcrypt";
import Model from "./core/Model.js";

class UserModel extends Model {

    async createUser(email, password, activationLink) {
        const client = await this.pool.connect();
        try {
            await client.query('BEGIN');

            const insertUserQuery = "INSERT INTO users (registration_date) VALUES (now()) RETURNING * ";
            const user_create_result = await client.query(insertUserQuery);
            const user = user_create_result.rows[0];

            if (!user) {
                throw new Error("Unknown error");
            }

            let hashedPassword = await bcrypt.hash(password, 2304)
            const loginInfoInsertQuery = "INSERT INTO user_login_info (email, user_id, password) VALUES ($1, $2, $3) RETURNING *";
            const loginInfoResult = await client.query(
                loginInfoInsertQuery,
                [email, user.user_id, hashedPassword]
            );

            if (loginInfoResult.rows.length === 0) {
                throw new Error("Unknown error");
            }

            const activationLinkResult = await client.query(
                "INSERT INTO users_activation_links (user_id, activation_link) VALUES ($1, $2) RETURNING *",
                [user.user_id, activationLink]
            );

            if (activationLinkResult.rows.length === 0) {
                throw new Error("Unknown error");
            }

            await client.query('COMMIT');
            return user;

        } catch (err) {
            await client.query('ROLLBACK');
            throw new Error("Unknown error");
        }
    }

    async deleteUser(user_id) {
        const query = "DELETE FROM users WHERE user_id = $1 RETURNING user_id";
        const values = [user_id];
        const result = await this.pool.query(query, values);
        return result.rows[0];
    }

    async authUser(email, password) {
        const query = `SELECT li.user_id, li.password
                       FROM user_login_info li
                                JOIN users u on (u.user_id = li.user_id and u.is_activated = true)
                       WHERE li.email = $1`
        const values = [email];
        const result = await this.pool.query(query, values);
        if (!result.rows[0]) return undefined

        let compareResult = await bcrypt.compare(password, result.rows[0].password);

        if (compareResult) return result.rows[0];
        return undefined;
    }

    async changeUserPassword(newPassword, password_change_token) {
        const client = await this.pool.connect();
        try {
            await client.query('BEGIN');
            let hashedPassword = await bcrypt.hash(newPassword, 2304);

            const passwordChangeTokenQuery = `
                DELETE FROM users_password_change_tokens
                WHERE password_change_token = $1 RETURNING *`
            const values = [password_change_token];
            const passwordChangeTokenRes = await client.query(passwordChangeTokenQuery, values);

            if (passwordChangeTokenRes.rows.length === 0) {
                await client.query('ROLLBACK');
                return false;
            }

            const updatePasswordQuery = `UPDATE user_login_info
                                         SET password = $1
                                         WHERE user_id = $2 RETURNING *`;
            let updatePasswordResult = await client.query(updatePasswordQuery, [hashedPassword, passwordChangeTokenRes.rows[0].user_id]);
            if (updatePasswordResult.rows.length === 0) {
                throw new Error("Unknown error");
            }

            await client.query('COMMIT');
            return true;
        } catch (e) {
            await client.query('ROLLBACK');
        }
        return false;
    }

    async getUserByEmail(email) {
        const query = `SELECT u.user_id, u.is_activated
                       FROM user_login_info ul
                       JOIN users u on u.user_id = ul.user_id
                       WHERE ul.email = $1`
        const result = await this.pool.query(query, [email]);
        return result.rows[0]
    }

    async saveRefreshToken(user_id, refresh_token) {
        const query = "INSERT INTO users_tokens (user_id, refreshtoken) VALUES ($1, $2) RETURNING *";
        const result = await this.pool.query(query, [user_id, refresh_token]);
        return result;
    }

    async findRefreshToken(refresh_token) {
        const query = "SELECT * FROM users_tokens WHERE refreshtoken = $1"
        const result = await this.pool.query(query, [refresh_token]);
        return result.rows[0]
    }

    async removeRefreshToken(refresh_token) {
        const query = "DELETE FROM users_tokens WHERE refreshtoken = $1 RETURNING *";
        const result = await this.pool.query(query, [refresh_token]);
        return result.rows[0];
    }

    async tryGetUserPasswordForgotToken(user_id){
        const query = `SELECT * FROM users_password_change_tokens WHERE user_id = $1`;
        return (await this.pool.query(query, [user_id])).rows[0];
    }

    async setForgotPasswordToken(user_id, forgotPasswordToken) {
        const query = "INSERT INTO users_password_change_tokens (user_id, password_change_token) VALUES($1, $2) RETURNING *";
        const result = await this.pool.query(query, [user_id, forgotPasswordToken]);
        return result.rows[0]
    }

    async findUserByPasswordForgotToken(passwordForgotToken) {
        const query = `
                SELECT ut.user_id, u.is_activated 
                FROM users_password_change_tokens ut 
                JOIN users u on u.user_id = ut.user_id
                WHERE ut.password_change_token = $1`;
        const result = await this.pool.query(query, [passwordForgotToken]);
        return result.rows[0]
    }

    async findUserByActivationLink(activationLink) {
        const query = "SELECT user_id FROM users_activation_links WHERE activation_link = $1"
        const result = await this.pool.query(query, [activationLink]);
        return result.rows[0]
    }

    async activateUser(user_id) {
        const client = await this.pool.connect();
        try {
            await client.query('BEGIN');

            const query = "UPDATE users SET is_activated = true WHERE user_id = $1 RETURNING *"
            const result = await client.query(query, [user_id])
            let activationLinkTableQuery = `DELETE FROM users_activation_links WHERE user_id = $1 RETURNING *`;
            let result2 = await client.query(activationLinkTableQuery, [user_id]);

            if (result.rows.length === 0 || result2.rows.length === 0) {
                await client.query("ROLLBACK");
                return false;
            }

            await client.query("COMMIT");
            return true;

        } catch (e) {
            await client.query("ROLLBACK");
        }
        return false;
    }

    async getUserById(user_id) {
        const query = `SELECT *
                       FROM users
                       WHERE user_id = $1`;
        const result = await this.pool.query(query, [user_id]);
        return result.rows[0];
    }
}

export default new UserModel();

