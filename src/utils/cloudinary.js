import dotenv from "dotenv"
import {v2 as cloudinary} from "cloudinary"
import fs from "fs"

dotenv.config({
    path: './.env'
})

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
})

const uploadOnCloudinary = async (localFilePath)=>{
    try {
        if(!localFilePath) return null

        // upload the file on cloudinary
        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto"
        })

        // file has been uploaded successfully
        console.log("File is uploaded on cloudinary", response.url);
        // fs.unlinkSync(localFilePath)
        return response;
    } catch (error) {
        console.error("CLOUDINARY UPLOAD FAILED : ",error)
        fs.unlinkSync(localFilePath)
        return null
    }
}

const deleteFromCloudinary = async (publicId, resorceType = "auto") =>{
    try {
        const result = await cloudinary.uploader.destroy(publicId, {
            resource_type: resorceType
        })
        return result;

    } catch (error) {
        console.log(`Failed to delete ${resorceType} from Cloudinary : `, error);
        throw new ApiError(500, "Failed to delete image or video from Cloudinary")
    }
}

export { uploadOnCloudinary, deleteFromCloudinary } 