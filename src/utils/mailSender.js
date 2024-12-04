import nodemailer from "nodemailer"
import dotenv from "dotenv"
import { ApiError } from "../utils/ApiError.js";

dotenv.config({
    path: './.env'
})

const mailSender = async (to, subject, text) =>{
    try {
        // create a transporter to send emails
        const transporter = nodemailer.createTransport({
            service: "Gmail",
            auth: {
                user: "saurabhvaidya541@gmail.com",
                pass: "kkqs zjtf crqp gpah"
            }
        });
        
        // Send emails to users 
        const mailOptions = {
            from: "saurabhvaidya541@gmail.com",
            to,
            subject,
            text,
        }

        console.log("mailOptions are : ",mailOptions);

        await transporter.sendMail(mailOptions)
        
    } catch (error) {
        throw new ApiError(500, error?.message || "Something went wrong while sending email")
    }
}

export { mailSender }