import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { uploadOnCloudinary, deleteFromCloudinary } from "../utils/cloudinary.js";
import { mailSender } from "../utils/mailSender.js";
import fast2sms from "fast-two-sms"
import disposableEmailDomain from "disposable-email-domains"
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import { response } from "express";

// Function to send OTP using Fast2SMS
const sendOTP = async (contact, otp) => {
    try {
        const options = {
            authorization: process.env.FAST2SMS_APIKEY,
            message: message,
            numbers: [contact]
        };

        const response = await fast2sms.sendMessage(options);
        console.log('OTP sent Successfully', response);
        return response;
    } catch (error) {
        console.error('Error sending OTP', error);
        throw new Error('Failed to send OTP');
    }
}

// User Registration 
const registerUser = asyncHandler(async (req, res) => {
    // get the user details from frontend
    const { fullname, username, contact, password } = req.body;

    // validate it is not empty
    if ([fullname, username, contact, password].some((field) => { !field || field?.trim() === "" })) {
        throw new ApiError(400, "All fields are required!!")
    }

    // Check if contact is email or phone number
    const isEmail = /\S+@\S+\.\S+/.test(contact);
    const query = isEmail ? { email: contact } : { phoneNumber: contact };

    // if email, check if it's a disposable email address
    if(isEmail){
        const domain = contact.split('@')[1];   // Get the domain of the email
        if (disposableEmailDomain.includes(domain)){
            throw new ApiError(400, "Disposable email address is not allowed. Please use a valid email adddress.");
        } 
    }

    // check if user already exists
    const existedUser = await User.findOne({
        $or: [{ username }, query]
    })

    if (existedUser) {
        if (!existedUser.emailVerified) {
            throw new ApiError(400, "Email already existed but not verified. please verify your email or resent OTP.")
        }
        throw new ApiError(400, "User with email or username already exists!!")
    }

    // create user object - create entry in db
    const user = new User.create({
        fullname,
        username,
        password,
        email: isEmail ? contact : null,
        phoneNumber: isEmail ? null : contact,
    })

    const otp = await user.generateOTP();

    console.log("user are : ", user);

    // Prepare respons without sensitive fields
    const createdUser = await User.findById(user.id).select("-password -refreshToken")

    if (!createdUser) {
        throw new ApiError(404, "Something went wrong while registering the user.")
    }

    // Send OTP to user's email
    const message = isEmail
        ? `Dear ${user.username},\n\nUse the following OTP to verify your email: ${otp}`
        : `Dear ${user.username},\n\nUse the following OTP to verify your phone number: ${otp}`;

    if (isEmail) {
        // send OTP via email
        await mailSender(user.email, "OTP Verification", message)
            .catch(error => {
                throw new ApiError(500, `Failed to send email: ${error.message}`);
            })
    } else {
        // Send OTP via SMS
        try {
            await sendOTP(contact, otp);
        } catch (error) {
            throw new ApiError(500, "Failed to send OTP to phone number");
        }

    }

    return res
        .status(200)
        .json(new ApiResponse("OTP sent. Please verify.", 201, createdUser))
})

// Username Availability 
const checkUsername = asyncHandler(async (req, res) => {
    const { username } = req.body;

    if (!username || username.trim() === "") {
        throw new ApiError(400, "Username is required")
    }

    // check if the username existed in the database 
    const existingUser = await User.findOne({ username });

    if (existingUser) {
        return res
        .status(200)
        .json(new ApiResponse("Username is already taken. Please choose another", 201, existingUser))
    }

    return res
    .status(200)
    .json(new ApiResponse("Username is available", 201, existingUser))
})

// OTP Varification
const verifyOTP = asyncHandler(async (req, res) => {
    const { contact, otp } = req.body;

    if (!contact || !otp) {
        throw new ApiError(400, "Please provide both contact and OTP");
    }

    const query = /\S+@\S+\.\S+/.test(contact) ? { email: contact } : { phoneNumber: contact };
    const user = await User.findOne(query);

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    console.log("Received OTP :", otp);
    console.log("Hashed OTP from DB", user.otp);

    if (user.emailVerified) {
        throw new ApiError(400, "Email already verified!!. No need to use the OTP again.")
    }

    //Check if the OTP matches and is not expired
    if (user.otpExpiry && user.otpExpiry < Date.now()) {
        throw new ApiError(400, "OTP has expired, Please request a new OTP!!")
    }

    // Compare provided OTP with the hashed OTP stored in the database
    const isOtpValid = await bcrypt.compare(otp, user.otp);

    if (!isOtpValid) {
        throw new ApiError(400, "Invalid OTP!!")
    }

    // mark the email as varified and clear OTP fields
    user.emailVerified = true;
    user.otp = undefined;       // claar otp after verification
    user.otpExpiry = undefined;

    await user.save();

    return res
        .status(200)
        .json(new ApiResponse(201, user.emailVerified, "Email verified successfully!!"))
})

export {
    registerUser,
    checkUsername,
    verifyOTP
}