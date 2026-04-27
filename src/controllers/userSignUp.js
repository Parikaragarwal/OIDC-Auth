import db from "../ultils/db.config.js";
import bcrypt from "bcrypt";

export default async function userSignupController(name,email,password){
    const existingUser = await db.query.users.findFirst({
        where: {
            email: email,
        }
    });
    if(existingUser){
        throw new Error("Email already in use");
    }
    const passwordHash = await bcrypt.hash(password, 10);
    await db.users.insert({
        name,
        email,
        password_hash: passwordHash,
    });
} 