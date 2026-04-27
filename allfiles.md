import http from 'node:http';
import {URL} from 'node:url';
import * as routeHandlers from './src/routes.js'
import parseBody from './src/middlewares/body-parser.js';

const getRoutes ={
    "/.well-known/openid-configuration": routeHandlers.openidConfigurationHandler,
    "/public-keys": routeHandlers.publicKeysHandler,
};

const postRoutes = {
    "/token-exchange": routeHandlers.tokenExchangeHandler,
    "/client-signup": routeHandlers.clientSignupHandler,
    "/user-signup": routeHandlers.userSignupHandler,
    "/login": routeHandlers.loginHandler,
    "/logout": routeHandlers.logoutHandler,
    "/logout-all": routeHandlers.logoutAllHandler,
};

const deleteRoutes = {};

const server = http.createServer(async(req,res)=>{
    try{
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname;

    res.setHeader("Content-Type", "application/json");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
        res.writeHead(204);
        return res.end();
    }else if(req.method === 'GET' && path === '/'){
        res.writeHead(200);
        return res.end(JSON.stringify({message: "Welcome to the OIDC Authentication Server"}));
    }else if(req.method === "GET" && path.startsWith("/authorize/")){
        if(path.split("/").length !== 3){
            res.writeHead(400);
            return res.end(JSON.stringify({message: "Invalid client_id in path"}));
        }
        const clientId = path.split("/")[2];
        req.clientId = clientId;
        return await routeHandlers.authorizeHandler(req,res);
    }else if(req.method === 'GET' && getRoutes.hasOwnProperty(path)){
        return await getRoutes[path](req,res);
    }else if(req.method ==='POST' && postRoutes.hasOwnProperty(path)){
        req.body = await parseBody(req);
        return await postRoutes[path](req,res);
    }else if(req.method === 'DELETE' && deleteRoutes.hasOwnProperty(path)){
        return await deleteRoutes[path](req,res);
    }else{
        res.writeHead(404);
        return res.end(JSON.stringify({message: "Route not found"}));
    }
}catch(err){
    console.error("Error handling request:", err);
    res.writeHead(500);
    return res.end(JSON.stringify({message: "Internal Server Error"}));
}});

server.listen(process.env.PORT || 3371, ()=>{
    console.log(`Server is running on port ${process.env.PORT || 3371}`);
});


import {URL} from 'node:url';
import * as controllers from './controllers/index.js';

export async function userSignupHandler(req,res){
    const {name, email, password} = req.body;
    try{
        await controllers.signUpController(name,email,password);
        res.writeHead(201);
        return res.end(JSON.stringify({message: "User signup successful"}));
    }catch(err){
        res.writeHead(400);
        return res.end(JSON.stringify({message: err.message}));
    }
}

export async function loginHandler(req,res){
    const {email, password} = req.body;
    try{
        const session_id = await controllers.loginController(email,password);
        res.setHeader(
        "Set-Cookie",
        `session_id=${session_id}; HttpOnly; Path=/; SameSite=Strict`
        );
        res.writeHead(200);
        return res.end(JSON.stringify({message: "Login successful"}));
    }catch(err){
        res.writeHead(400);
        return res.end(JSON.stringify({message: err.message}));
    }
}

export async function clientSignupHandler(req,res){
    try{
    const {name,base_url,redirect_uri} = req.body;
    const {client_id, client_secret} = await controllers.clientSignupController(name,base_url,redirect_uri);
    res.writeHead(201);
    return res.end(JSON.stringify({message: "Client SignUp Successful", client_id, client_secret}));
    }catch(err){
        res.writeHead(400);
        return res.end(JSON.stringify({message: err.message}));
    }
}

export async function authorizeHandler(req,res){
    try {
    const clientId = req.clientId;
    const {redirect_uri,shortcode} = await controllers.authorizeController(clientId,req);
    res.writeHead(302, {
    Location: `${redirect_uri}?shortcode=${shortcode}`
    });
    return res.end();
    } catch (error) {
        res.writeHead(400);
        return res.end(JSON.stringify({message: error.message}));
    }
}

export async function tokenExchangeHandler(req,res){
    try{
        const {shortcode,clientId,clientSecret} = req.body;
        const {access_token} = await controllers.tokenExchangeController(shortcode,clientId,clientSecret);
        res.writeHead(200);
        return res.end(JSON.stringify({access_token}));
    }catch(err){
        res.writeHead(400);
        return res.end(JSON.stringify({message: err.message}));
    }
}

export function publicKeysHandler(req,res){
    res.writeHead(200);
    return res.end(JSON.stringify({
        public_key: process.env.PUBLIC_KEY.replace(/\\n/g, "\n")
    }));
}

export async function logoutHandler(req,res){
    res.setHeader(
        "Set-Cookie",
        `session_id=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0`
    );
    res.writeHead(200);
    return res.end(JSON.stringify({message: "Logout successful"}));
}

export async function logoutAllHandler(req,res){
    try {
    const userSessionId = req.headers.cookie?.split(";").find(cookie => cookie.trim().startsWith("session_id="))?.split("=")[1];
    if(!userSessionId){
        res.writeHead(400);
        return res.end(JSON.stringify({message: "User not authenticated"}));
    }
    await controllers.logoutAllController(userSessionId);
    res.setHeader(
        "Set-Cookie",
        `session_id=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0`
    );
    res.writeHead(200);
    return res.end(JSON.stringify({message: "Logout from all sessions successful"}));
    } catch (error) {
        res.writeHead(400);
        return res.end(JSON.stringify({message: error.message}));
    }
}

export async function openidConfigurationHandler(req,res){
    const issuer = `${req.headers.protocol || 'http:'}//${req.headers.host}`;
    const config = {
        issuer: issuer,
        authorization_endpoint: `${issuer}/authorize/{client_id}`,
        token_endpoint: `${issuer}/token-exchange`,
        jwks_uri: `${issuer}/public-keys`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"]
    };
    res.writeHead(200);
    return res.end(JSON.stringify(config));
}

export async function jwksHandler(req,res){
    const jwk = {
        kty: "RSA",
        use: "sig",
        alg: "RS256",
        kid: "1",
        n: Buffer.from(process.env.PUBLIC_KEY.replace(/\\n/g, "\n")).toString("base64"),
        e: "AQAB"
    };
    res.writeHead(200);
    return res.end(JSON.stringify({keys: [jwk]}));
}


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

import db from "../ultils/db.config.js";

export default async function logoutAllController(session_id){
    const user = await db.query.users.findFirst({
        where: {
            session_id: session_id,
        }
    });
    if(!user){
        throw new Error("Invalid session. User not found");
    }
    await db.users.update({
        where: {
            id: user.id,
        },
        set: {
            session_id: null,
        }
    });
    await userSessions.updateMany({
        where: {
            user_id: user.id,
        },
        set: {
            status: "revoked",
        }
    });
}


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


import db from "../ultils/db.config.js";
import bcrypt from "bcrypt";

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