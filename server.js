import http from 'node:http';
import {URL} from 'node:url';
import * as routeHandlers from './src/routes.js'
import parseBody from './src/middlewares/body-parser.js';

const getRoutes ={
    "/.well-known/openid-configuration": routeHandlers.openidConfigurationHandler,
    "/public-keys": routeHandlers.publicKeysHandler,
    "/userinfo": routeHandlers.userInfoHandler,
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