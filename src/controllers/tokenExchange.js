import db from "../ultils/db.config.js";
import bcrypt from "bcrypt";
import { signAccessToken } from "../utils/jwt.js";

export default async function tokenExchangeController(shortcode,clientId,clientSecret){
    const client = await db.query.clients.findFirst({
        where: {
            client_id: clientId,
        }
    });
    if(!client){
        throw new Error("Invalid client credentials");
    }
    const secretMatch = await bcrypt.compare(clientSecret,client.client_secret_hash);
    if(!secretMatch){
        throw new Error("Invalid client credentials");
    }
    const authCode = await db.query.authorizationCodes.findFirst({
        where: {
            code: shortcode,
            client_id: clientId,
            expires_at: {
                gt: new Date(),
            }
        }
    });
    if(!authCode){
        throw new Error("Invalid or expired authorization code");
    }
    if (authCode.used) {
   throw new Error("Authorization code already used");
   }
    const user  = (authCode.user_id) ? await db.query.users.findFirst({
        where: {
            id: authCode.user_id,
        }
    }): null;

    if(!user){
        throw new Error("User associated with authorization code not found");
    }

    await db.authorizationCodes.update({
        where: {
            id: authCode.id,
        },
        set: {
            used: true,
        }
    });


    const access_token = signAccessToken({
    sub: user.id,
    email: user.email,
    name: user.name,
    client_id: clientId
    });
    return { access_token };
}