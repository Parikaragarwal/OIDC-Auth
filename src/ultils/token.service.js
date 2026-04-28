import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const privateKey = process.env.PRIVATE_KEY.replace(/\\n/g, "\n");
const publicKey = process.env.PUBLIC_KEY.replace(/\\n/g, "\n");

export function signAccessToken(payload) {
    return jwt.sign(payload, privateKey, {
        algorithm: "RS256",
        expiresIn: "2d",
        issuer: process.env.JWT_ISSUER
    });
}

export function verifyAccessToken(token) {
    return jwt.verify(token, publicKey, {
        algorithms: ["RS256"],
        issuer: process.env.JWT_ISSUER
    });
}