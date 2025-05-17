import UserModel from "./userModel.js";
import * as uuid from "uuid";
import mailService from "./services/mail-service.js";
import tokenService from "./services/tokenService.js";

class UserController {

    async doesUserExist(req, res){
        let user = req.user;
        if (!user.is_server){
            return res.status(400).json({
                success: false,
                error: 'Ошибка доступа'
            });
        }
        try {
            let {user_id} = req.query;
            let checkUser = await UserModel.getUserById(user_id);

            return res.status(200).json({
                success: true,
                data: {
                    exist: !!checkUser
                }
            });
        } catch (e) {
            res.status(500).json({
                success: false,
                error: 'Unknown error'
            });
        }
    }
    async createUser(req, res){
        let user = req.user;
        if (user) {
            return res.status(200).json({
                success: false,
                error: 'User_authorized'
            });
        }

        let createdUserId = -1;

        try {
            const {email, password} = req.body;
            if (!email || !password) {
                return res.status(200).json({
                    success: false,
                    error: 'email, фамилия, имя и пароль обязательны'
                });
            }

            if (password.length > 40) {
                return res.status(200).json({
                    success: false,
                    error: 'Пароль д.б не пустой и не длиннее 40 символов!',
                    error_field: "password"
                });
            }

            if (!email || email.length === 0) {
                return res.status(200).json({
                    success: false,
                    error: 'Email не может быть пустым',
                    error_field: "email"
                });
            }

            let userWithEmail = await UserModel.getUserByEmail(email);
            if (userWithEmail) {
                return res.status(200).json({
                    success: false,
                    error: 'Пользователь с таким email уже зарегистрирован в системе!',
                    error_field: "email"
                });
            }

            let activationLink = uuid.v4();
            let user = await UserModel.createUser(email, password, activationLink);
            if (!user) {
                return res.status(200).json({
                    success: false,
                    error: 'Unknown_error'
                });
            }

            createdUserId = user.user_id;

            await mailService.sendActivationMail(email, "http://"+process.env.API_URL+"/activation/" + activationLink)
                res.status(200).json({
                    success: true,
                    data: {}
                });

        } catch (error) {
            if (createdUserId !== -1) await UserModel.deleteUser(createdUserId);
            if (error.code === '23505') { // Ошибка уникальности в PostgreSQL
                return res.status(200).json({
                    success: false,
                    error: 'Пользователь с таким email уже зарегистрирован в системе!',
                    error_field: "email"
                });
            }
            res.status(500).json({
                success: false,
                error: 'Unknown error'
            });
        }
    }

    async loginUser(req, res){
        let user = req.user;
        if (user) {
            return res.status(200).json({
                success: false,
                error: 'User_authorized'
            });
        }

        try {
            const {email, password} = req.body;
            if (!email || !password) {
                return res.status(200).json({
                    success: false,
                    error: 'email and password are required'
                });
            }

            let user = await UserModel.authUser(email, password);
            if (!user) {
                return res.status(200).json({
                    success: false,
                    error: 'Неправильный логин или пароль'
                });
            }

            await this.doAuth(res, user);
        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async refreshToken(req, res) {
        try {
            const {refreshToken} = req.cookies;

            if (!refreshToken) {
                return res.status(200).json({
                    success: false,
                    error: 'wrong token'
                });
            }

            let userData = tokenService.validateRefreshToken(refreshToken)
            if (!userData) {
                return res.status(200).json({
                    success: false,
                    error: 'wrong token'
                });
            }

            const foundToken = await UserModel.findRefreshToken(refreshToken);
            if (!foundToken) {
                return res.status(200).json({
                    success: false,
                    error: 'User_not_found'
                });
            }

            const user = await UserModel.getUserById(userData.user_id);
            if (!user) {
                return res.status(200).json({
                    success: false,
                    error: 'User_not_found'
                });
            }

            const tokens = tokenService.generateTokens({user_id: user.user_id})
            let saveTokenRes = await UserModel.saveRefreshToken(user.user_id, tokens.refreshToken);
            if (!saveTokenRes) {
                return res.status(200).json({
                    success: false,
                    error: 'Save token failed'
                });
            }

            res.cookie('refreshToken', refreshToken, {maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true})


            res.status(200).json({
                success: true,
                data: {
                    user_id: user.id,
                    ...tokens
                }
            });

        } catch (e) {
            res.status(500).json({
                success: false,
                error: "Unknown_error"
            });
        }
    }

    async logout(req, res){

        try {
            const {refreshToken} = req.cookies;
            let delRes = await UserModel.removeRefreshToken(refreshToken);
            if (!delRes) {
                return res.status(200).json({
                    success: false,
                    error: 'Logout failed'
                });
            }
            res.clearCookie('refreshToken');
            res.status(200).json({
                success: true,
                data: {}
            });

        } catch (e) {
            res.status(500).json({
                success: false,
                error: "Unknown_error"
            });
        }
    }

    async forgotPassword(req, res){
        let user = req.user;
        if (user) {
            return res.status(200).json({
                success: false,
                error: 'User_authorized'
            });
        }


        try {
            const {email} = req.body;

            let user = await UserModel.getUserByEmail(email);
            if (!user || !user.is_activated) {
                return res.status(200).json({
                    success: false,
                    error: 'Пользователь не найден'
                });
            }

            let forgotTokenExists = await UserModel.tryGetUserPasswordForgotToken(user.user_id);
            if (forgotTokenExists) {
                return res.status(200).json({
                    success: false,
                    error: 'Ссылка для восстановления пароля была уже отправлена на email'
                });
            }

            const forgotPasswordLink = uuid.v4();
            let setChangeLinkRes = await UserModel.setForgotPasswordToken(user.user_id, forgotPasswordLink);

            if (!setChangeLinkRes) {
                return res.status(200).json({
                    success: false,
                    error: 'Unknown_error'
                });
            }

            await mailService.sendChangePasswordMail(email, "http://"+process.env.API_URL+"/changePassword/" + forgotPasswordLink);
            res.status(200).json({
                success: true,
                data: {}
            });


        } catch (e) {
            res.status(500).json({
                success: false,
                error: "Unknown_error"
            });
        }
    }

    async changePassword(req, res){
        try {
            const {password_change_token, password} = req.body;

            if (!password_change_token) {
                return res.status(200).json({
                    success: false,
                    error: 'Пользователь не найден'
                });
            }

            if (!password || password.length > 40) {
                return res.status(200).json({
                    success: false,
                    error: 'Пароль д.б не пустой и не длиннее 40 символов!',
                    error_field: "password"
                });
            }

            let user = await UserModel.findUserByPasswordForgotToken(password_change_token);
            if (!user || !user.is_activated) {
                return res.status(200).json({
                    success: false,
                    error: 'Пользователь не найден'
                });
            }

            let changePasswordRes = await UserModel.changeUserPassword(password, password_change_token);
            if (!changePasswordRes) {
                return res.status(200).json({
                    success: false,
                    error: 'Unknown_error'
                });
            }

            await this.doAuth(res, user);

        } catch (e) {
            res.status(500).json({
                success: false,
                error: "Unknown_error"
            });
        }
    }

    async doAuth(res, user) {
        const tokens = tokenService.generateTokens({user_id: user.user_id, is_admin: user.is_admin});
        await UserModel.saveRefreshToken(user.user_id, tokens.refreshToken)

        res.cookie('refreshToken', tokens.refreshToken, {maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true})

        res.status(200).json({
            success: true,
            data: {
                user_id: user.user_id,
                refreshToken: tokens.refreshToken,
                accessToken: tokens.accessToken
            }
        });
    }

    async activateAccount(req, res) {
        try {
            const {activation_link} = req.query;

            if (!activation_link) {
                return res.status(200).json({
                    success: false,
                    error: 'User_not_found'
                });
            }

            let user = await UserModel.findUserByActivationLink(activation_link);
            if (!user) {
                return res.status(200).json({
                    success: false,
                    error: 'User_not_found'
                });
            }

            let activationResult = await UserModel.activateUser(user.user_id);
            if (!activationResult) {
                return res.status(200).json({
                    success: false,
                    error: 'Unknown_error'
                });
            }

            await this.doAuth(res, user);

        } catch (e) {
            res.status(500).json({
                success: false,
                error: "Unknown_error"
            });
        }
    }

}

export default new UserController();