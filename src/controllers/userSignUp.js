import db from "../ultils/db.config.js";
import bcrypt from "bcrypt";
import { eq } from "drizzle-orm";
import { users } from "../db/schema.js";

export default async function userSignupController(name,email,password){
    const existingUser = await db.query.users.findFirst({
        where: eq(users.email, email)
    });
    if(existingUser){
        throw new Error("Email already in use");
    }
    const passwordHash = await bcrypt.hash(password, 10);
    await db.insert(users).values({
        name,
        email,
        password_hash: passwordHash,
    });
} 