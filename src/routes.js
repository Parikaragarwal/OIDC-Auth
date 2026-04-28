import {URL} from 'node:url';
import * as controllers from './controllers/index.js';
import { verify } from 'node:crypto';
import { verifyAccessToken } from './ultils/token.service.js';

// export {
//     userSignupController,
//     loginController,
//     clientSignupController,
//     authorizeController,
//     tokenExchangeController,
//     logoutAllController
// };

export async function userSignupHandler(req,res){
    const {name, email, password} = req.body;
    try{
        await controllers.userSignupController(name,email,password);
        res.writeHead(201);
        return res.end(JSON.stringify({message: "User signup successful"}));
    }catch(err){
        res.writeHead(400);
        console.error("Error in user signup:", err);
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
        console.error("Error in login:", err);
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
        console.error("Error in client signup:", err);
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
        console.error("Error in authorization:", error);
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
        console.error("Error in token exchange:", err);
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
        console.error("Error in token exchange:", err);
        res.writeHead(400);
        return res.end(JSON.stringify({message: error.message}));
    }
}

export async function openidConfigurationHandler(req,res){
    const issuer =`http://${req.headers.host}`;
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
        n: process.env.PUBLIC_KEY.replace(/\\n/g, "\n"),
        e: "AQAB"
    };
    res.writeHead(200);
    return res.end(JSON.stringify({keys: [jwk]}));
}

export async function userInfoHandler(req, res) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            res.writeHead(401);
            return res.end(JSON.stringify({ message: "Unauthorized" }));
        }

        const token = authHeader.split(" ")[1];

        const payload = verifyAccessToken(token);

        // Return only user-related claims
        const userInfo = {
            sub: payload.sub,
            email: payload.email,
            name: payload.name
        };

        res.writeHead(200);
        return res.end(JSON.stringify(userInfo));

    } catch (err) {
        console.error("Error in user info:", err);
        res.writeHead(401);
        return res.end(JSON.stringify({ message: "Unauthorized" }));
    }
}