import db from "../ultils/db.config.js";
import bcrypt from "bcrypt";
import crypto from "node:crypto";

export default async function loginController(email,password){
    const User = await db.query.users.findFirst({
        where: {
            email: email
        }
    });
    if(!User){
        throw new Error("User with email not found");
    }
    const passwordMatch = await bcrypt.compare(password,User.password_hash);
    if(!passwordMatch){
        throw new Error("Invalid Username or password");
    }
    const session_id = crypto.randomUUID();
    await db.users.update({
        where: {
            id: User.id,
        },
        set: {
            session_id,
        }
    });
    return session_id;
}