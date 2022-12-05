import mongoose from "mongoose";
import * as dotenv from 'dotenv'
dotenv.config()


const connection = mongoose.connect(process.env.MongodbServerLink);

export default connection;
