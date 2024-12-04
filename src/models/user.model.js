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

// Email OTP generation
const MAX_LIMIT = 3;                        // maximum number of OTP request allow in 24 hours 
const OTP_REQUEST_TIMEOUT = 30 * 1000;      // 30 sec (time between OTP request)
userSchema.methods.generateOTP = async function(){
    const currentTime = Date.now();
    const oneDay = 24 * 60 * 60 * 1000;

    // Reset OTP request count after 24 hours 
    if(this.otpLastRequest && currentTime - this.otpLastRequest.getTime() >= oneDay){
        this.otpRequestCount = 0;
    }

    // Check if the user has reached the max OTP request limit for the day
    if(this.otpRequestCount > MAX_LIMIT){
        throw new Error(429, "Maximum OTP request limit reached. Please try again later.");
    }

    // Check if the user is requesting OTP too soon after the last request
    if(this.otpLastRequest && currentTime - this.otpLastRequest.getTime() < OTP_REQUEST_TIMEOUT){
        throw new Error(429, "Please wait before requesting OTP again.");
    }

    // Generate the OTP and update request tracking 
    const otp = crypto.randomBytes(3).toString("hex");  // generate 6 character hex OTP
    const hashOTP = await bcrypt.hash(otp, 10); // hash OTP before save into database 
    this.otp = hashOTP;
    this.otpExpiry = Date.now() + 60 * 1000;    // OTP expiry time 
    this.otpRequestCount += 1;
    this.otpLastRequest = new Date();

    await this.save()
    return otp;
}

export const User = mongoose.model("User", userSchema)