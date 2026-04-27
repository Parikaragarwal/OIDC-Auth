import db from "../ultils/db.config.js";
import crypto from "node:crypto";
import bcrypt from "bcrypt";

export default async function clientSignupController(name, base_url, redirect_uri){
    const existingClient = await db.query.clients.findFirst({
        where: {
            name: name,
            base_url: base_url,
        }
    });
    if(existingClient){
        throw new Error("Client name already in use");
    }
    const client_id = crypto.randomUUID();
    const client_secret = crypto.randomUUID();
    const client_secret_hash = await bcrypt.hash(client_secret, 10);
    await db.clients.insert({
        name,
        base_url,
        redirect_uri,
        client_id,
        client_secret_hash
    });
    return { client_id, client_secret };
}