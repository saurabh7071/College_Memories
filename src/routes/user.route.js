import { Router } from "express"
import {
    registerUser,
    checkUsername,
    verifyOTP,
    resendOTP,
    loginUser,
    logoutUser,
    refreshAccessToken
} from "../controllers/user.controller.js"
import { verifyJWT } from "../middlewares/auth.middleware.js"

const router = Router()

router.route("/register").post(registerUser)
router.route("/checkUsername").post((checkUsername))
router.route("/verify-otp").post(verifyOTP)
router.route("/resend-otp").post(resendOTP)
router.route("/loginUser").post(loginUser)
router.route("/logoutUser").post(verifyJWT, logoutUser)
router.route("/refreshAccessToken").post(refreshAccessToken)

export default router