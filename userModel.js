import bcrypt from "bcrypt";
import Model from "./core/Model.js";

class UserModel extends Model {

    async createUser(email, password, activationLink) {
        let hashedPassword = await bcrypt.hash(password, 2304)
        const query = "INSERT INTO users (email, password, activation_link) VALUES ($1, $2, $3) RETURNING * ";
        const values = [email, hashedPassword, activationLink];
        const result = await this.pool.query(query, values);
        return result.rows[0];
    }

    async deleteUser(user_id) {
        const query = "DELETE FROM users WHERE user_id = $1 RETURNING user_id";
        const values = [user_id];
        const result = await this.pool.query(query, values);
        return result.rows[0];
    }

    async authUser(email, password) {
        const query = "SELECT user_id, password FROM users WHERE email = $1 and is_activated = true"
        const values = [email];
        const result = await this.pool.query(query, values);
        if (!result.rows[0]) return undefined

        let compareResult = await bcrypt.compare(password, result.rows[0].password);

        if (compareResult) return result.rows[0];
        return undefined;
    }

    async changeUserPassword(newPassword, password_change_token) {
        let hashedPassword = await bcrypt.hash(newPassword, 2304)
        const query = "UPDATE users SET password = $1, password_change_token = '' WHERE password_change_token = $2 RETURNING *"
        const values = [hashedPassword, password_change_token];
        const result = await this.pool.query(query, values);
        return result.rows[0]
    }

    async getUserByEmail(email) {
        const query = `SELECT *
                       FROM users
                       WHERE email = $1`
        const result = await this.pool.query(query, [email]);
        return result.rows[0]
    }

    async saveRefreshToken(user_id, refresh_token) {
        const query = "INSERT INTO user_tokens (user_id, refreshtoken) VALUES ($1, $2) RETURNING *";
        const result = await this.pool.query(query, [user_id, refresh_token]);
        return result;
    }

    async findRefreshToken(refresh_token) {
        const query = "SELECT * FROM user_tokens WHERE refreshtoken = $1"
        const result = await this.pool.query(query, [refresh_token]);
        return result.rows[0]
    }

    async removeRefreshToken(refresh_token) {
        const query = "DELETE FROM user_tokens WHERE refreshtoken = $1 RETURNING *";
        const result = await this.pool.query(query, [refresh_token]);
        return result.rows[0];
    }

    async setForgotPasswordToken(user_id, forgotPasswordToken) {
        const query = "UPDATE users SET password_change_token = $1 WHERE user_id =  $2 RETURNING *";
        const result = await this.pool.query(query, [forgotPasswordToken, user_id]);
        return result.rows[0]
    }

    async findUserByPasswordForgotToken(passwordForgotToken) {
        const query = "SELECT user_id, is_activated FROM users WHERE password_change_token = $1";
        const result = await this.pool.query(query, [passwordForgotToken]);
        return result.rows[0]
    }

    async findUserByActivationLink(activationLink) {
        const query = "SELECT user_id FROM users WHERE activation_link = $1"
        const result = await this.pool.query(query, [activationLink]);
        return result.rows[0]
    }

    async activateUser(user_id) {
        const query = "UPDATE users SET is_activated = true, activation_link = NULL WHERE user_id = $1 RETURNING *"
        const result = await this.pool.query(query, [user_id])
        return result.rows[0]
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

