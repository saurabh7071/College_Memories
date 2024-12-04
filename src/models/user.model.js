import mongoose, {Schema} from "mongoose"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
// for generating OTP

const userSchema = new Schema({
    fullname: {
        type: String,
        required: true,
        trim: true,
        index: true
    },
    username: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        index: true,
        lowercase: true
    },
    email: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        lowercase: true,
        sparse: true    // Optional, unique, sparse ensures only one unique email
    },
    phoneNumber: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        sparse: true    // Optional, unique, sparse ensures only one unique phone number
    },
    password: {
        type: String,
        required: [true, 'Password is Required!!']
    },
    emailVerified: {
        type: Boolean,
        default: false
    },
    otp: {
        type: String,   // OTP will be stored temporarily for email verification
    },
    otpExpiry: {
        type: Date, // set expiry time for the OTP
    },
    otpRequestCount: {
        type: Number,
        default: 0
    },
    otpLastRequest: {
        type: Date
    },
    bio: {
        type: String,
        trim: true,
        maxLength: 500,
        default: "This user hasn't added a bio yet."
    },
    profilePicture: {
        type: String,   // cloudinary url 
        default: ""
    },
    gender: {
        type: String,
        enum: ['male', 'female', 'other'],
        default: 'other',
        set: val => val.toLowerCase(),
    },
    dob: {
        type: Date,
        default: null
    },
    ownPosts: [
        {
            type: Schema.Types.ObjectId,
            ref: 'Post'
        }
    ],
    refreshToken: {
        type: String
    }
},{timestamps: true})

export const User = mongoose.model("User", userSchema)