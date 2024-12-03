import dotenv from "dotenv"
import connectDB from "./DB/connection.js"
import { app } from "./app.js"

dotenv.config({
    path: './.env'
})

connectDB()
.then(()=>{
    app.on("error", (error) =>{
        console.log("ERROR: ", error);
        throw error
    })

    app.listen(process.env.PORT || 8800, ()=>{
        console.log(`SERVER IS RUNNING ON PORT : ${process.env.PORT || 5500}`);
    })
})
.catch((err)=>{
    console.log("MONGODB CONNECTION FAILED!!", err);
    
})