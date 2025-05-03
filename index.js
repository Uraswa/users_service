import dotenv from "dotenv"

dotenv.config();

import express from 'express'
import cors from "cors";
import cookieParser from "cookie-parser";
import Model from "./core/Model.js";
import notAuthMiddleware from "./middleware/not-auth-middleware.js";
import UserController from "./userController.js";
import authMiddleware from "./middleware/auth-middleware.js";

Model.connect();

const app = express()
app.use(express.json())
app.use(cookieParser());
app.use(cors({
    origin: "http://localhost:9000", // или true для любого origin
    credentials: true, // разрешаем куки и авторизационные заголовки
    allowedHeaders: ['Content-Type', 'Authorization']
}))

const router = express.Router()
app.use(router);

router.post('/api/createUser', notAuthMiddleware, UserController.createUser.bind(UserController));
router.post('/api/login', notAuthMiddleware, UserController.loginUser.bind(UserController));
router.post('/api/refreshToken', UserController.refreshToken.bind(UserController));
router.post('/api/logout', authMiddleware, UserController.logout.bind(UserController));
router.post('/api/forgotPassword', notAuthMiddleware, UserController.forgotPassword.bind(UserController));
router.post('/api/changePassword', notAuthMiddleware, UserController.changePassword.bind(UserController));
router.get('/api/activateAccount', notAuthMiddleware, UserController.activateAccount.bind(UserController));
router.get('/api/doesUserExist', authMiddleware, UserController.doesUserExist.bind(UserController));

router.get('/health', (req, res) => res.status(200).send('OK'));


app.listen(8002, () => {

})
