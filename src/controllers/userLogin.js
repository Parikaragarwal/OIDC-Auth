import db from "../ultils/db.config.js";
import bcrypt from "bcrypt";
import crypto from "node:crypto";
import { eq } from "drizzle-orm";
import { users } from "../db/schema.js";

export default async function loginController(email, password) {
    const user = await db.query.users.findFirst({
        where: eq(users.email, email)
    });

    if (!user) {
        throw new Error("User with email not found");
    }

    const passwordMatch = await bcrypt.compare(
        password,
        user.password_hash
    );

    if (!passwordMatch) {
        throw new Error("Invalid Username or password");
    }

    const session_id = crypto.randomUUID();

    await db.update(users)
        .set({ session_id })
        .where(eq(users.id, user.id));

    return session_id;
}