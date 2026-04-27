import db from "../ultils/db.config.js";
import crypto from "node:crypto";

export default async function authorizeController(client_id,req){
    const client = await db.query.clients.findFirst({
        where: {
            client_id: client_id,
        }
    });
    if(!client){
        throw new Error("Client not found");
    }
    
    const userSessionId = req.headers.cookie?.split(";").find(cookie => cookie.trim().startsWith("session_id="))?.split("=")[1];
    if(!userSessionId){
        throw new Error("User not authenticated");
    }
    const user = await db.query.users.findFirst({
        where: {
            session_id: userSessionId,
        }
    });
    if(!user){
        throw new Error("Invalid session. User not found");
    }
    const shortcode = crypto.randomBytes(16).toString("hex");
    await db.authorizationCodes.insert({
        code: shortcode,
        client_id: client.client_id,
        user_id: user.id,
        expires_at: new Date(Date.now() + 5 * 60 * 1000), // Code valid for 5 minutes
    });
    return {redirect_uri: client.redirect_uri, shortcode};
}