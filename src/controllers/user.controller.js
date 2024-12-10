import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiResponse } from "../utils/ApiResponse.js";
// import { uploadOnCloudinary, deleteFromCloudinary } from "../utils/cloudinary.js";
import { mailSender } from "../utils/mailSender.js";
import { readFileSync } from "fs";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const disposableEmailDomains = JSON.parse(
    readFileSync("./node_modules/disposable-email-domains/index.json", "utf-8")
);

// Generating Access and Refresh tokesn 
const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        // Storing refresh token into database
        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: true })

        return { accessToken, refreshToken }

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access token ")
    }
}

// User Registration 
const registerUser = asyncHandler(async (req, res) => {
    // get the user details from frontend
    const { fullname, username, email, password } = req.body;

    // validate it is not empty
    if ([fullname, username, email, password].some((field) => !field || field?.trim() === "")) {
        throw new ApiError(400, "All fields are required!!")
    }

    // if email, check if it's a disposable email address
    if (email) {
        const domain = email.split('@')[1]?.toLowerCase();   // Get the domain of the email
        if (!domain || disposableEmailDomains.includes(domain)) {
            throw new ApiError(400, "Disposable email address is not allowed. Please use a valid email adddress.");
        }
    }

    // check if user already exists
    const existedUser = await User.findOne({
        $or: [{ email, username }]
    })

    if (existedUser) {
        if (!existedUser.emailVerified) {
            throw new ApiError(400, "Email or Phone Number already existed but not verified. please verify via resent OTP.")
        }
        throw new ApiError(400, "User with email or username already exists!!")
    }

    // create user object - create entry in db
    const user = await User.create({
        fullname,
        username,
        email,
        password
    })

    const otp = await user.generateOTP();

    console.log("user are : ", user);

    // Prepare respons without sensitive fields
    const createdUser = await User.findById(user.id).select("-password -refreshToken")

    if (!createdUser) {
        throw new ApiError(404, "Something went wrong while registering the user.")
    }

    // send OTP via email
    await mailSender(
        user.email,
        "OTP Verification",
        `Dear ${user.username},\n\nWe received a request to verify your email address. Please use the following One-Time Password (OTP) to complete the verification process:\n\nOTP: ${otp}\n\nThis OTP will expire in 2 minutes. If you did not request this, please ignore this email.\n\nThank you!!`
    )
    .catch(error => {
        throw new ApiError(500, `Failed to send email: ${error.message}`);
    })

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
    const isOtpValid = await bcrypt.compare(otp.trim(), user.otp);

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

// Resend the OTP request
const resendOTP = asyncHandler(async (req, res) => {
    const { email } = req.body;

    if (!email) {
        throw new ApiError(400, "Please provide email")
    }

    // Find the user by email
    const user = await User.findOne({ email });

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    // check if the user has already verified their email
    if (user.emailVerified) {
        throw new ApiError(400, "Your Email is already verified. No need to resend the OTP");
    }

    // check if the OTP request limit has been reached 
    const currentTime = Date.now();

    // check if the OTP is still valid (not expired)
    if (user.otp && user.otpExpiry && user.otpExpiry > currentTime) {
        const remainingTime = Math.ceil((user.otpExpiry - currentTime) / 1000);
        throw new ApiError(400, `OTP is still valid. Please wait ${remainingTime} seconds before requesting a new OTP.`);
    }

    // Generate new OTP
    const otp = await user.generateOTP();
    await user.save();

    // Send new OTP to the user via Email
    await mailSender(
        user.email,
        " OTP Verification",
        `Your new OTP for verification is: ${otp}. Please use this OTP within the 2 minute to complete your verification process.`
    )

    return res
        .status(200)
        .json(new ApiResponse("New OTP sent successfully!", 200, null))
})

// Login
const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if(!email || !password){
        throw new ApiError(404, "Please provide email and password");
    }

    const user = await User.findOne({email})

    if(!user){
        throw new ApiError(400, "User not found. Please Register First!!")
    }

    // check if the email is verified 
    if(!user.emailVerified){
        throw new ApiError(400, "Your Email is not verified. Please verify your email first")
    }

    // check password
    const ispasswordValid = await user.comparePassword(password)

    if(!ispasswordValid){
        throw new ApiError(400, "Invalid User Credentials!!")
    }

    // generate access and refresh token
    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id)

    // Fetch its own posts 

    // send accessToken and refresh token - cookie
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            201,
            {
                user: {
                    ...loggedInUser._doc,   // use _doc to spread the user object
                },
                accessToken, refreshToken
            },
            "User logged in Successfully !!"
        )
    )
})

// logOut
const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user?._id,
        {
            $unset: {
                accessToken: 1,
            }
        },
        {
            new: true
        }
    )
    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("accessToken", options)
    .json(new ApiResponse(200, {}, "User logged Out successfully!!"))
})

// for Refreshing the tokens 
const refreshAccessToken = asyncHandler(async (req, res) => {
    // Take incoming token from user
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    console.log(incomingRefreshToken);

    // validate incoming token
    if(!incomingRefreshToken){
        throw new ApiError(400, "Unauthorized request - Token not provided or invalid")
    }

    try{
        // verify incoming token
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)

        // fetch UserId from decoded token
        const user = await User.findById(decodedToken?._id)

        if(!user){
            throw new ApiError(400, "Invalid Refresh Token")
        }

        // check both token match or not 
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(400, "Refresh token is expired or used")
        }

        // if both token are match - generate new token
        const options = {
            httpOnly: true,
            secure: true
        }

        const { accessToken, newRefreshToken } = await generateAccessAndRefreshToken(user._id)

        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(new ApiResponse(
            201,
            {
                accessToken, refreshToken: newRefreshToken
            },
            "Tokens are Refreshed Successfully"
        ))
    }catch(error){
        throw new ApiError(401, error?.message || "Invalid Refresh Token")
    }
})

export {
    registerUser,
    checkUsername,
    verifyOTP,
    resendOTP,
    loginUser,
    logoutUser,
    refreshAccessToken
}