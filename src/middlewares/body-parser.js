import { parse } from "node:querystring";

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";

    req.on("data", chunk => {
      data += chunk;
    });

    req.on("end", () => {
      try {
        const body = data ? JSON.parse(data) : {};
        resolve(body);
      } catch (err) {
        reject(err);
      }
    });

    req.on("error", reject);
  });
}
function parseFormBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";

    req.on("data", chunk => data += chunk);

    req.on("end", () => {
      resolve(parse(data));
    });

    req.on("error", reject);
  });
}

export default async function parseBody(req) {
  const type = req.headers["content-type"] || "";

  if (type.includes("application/json")) {
    return await parseJsonBody(req);
  }

  if (type.includes("application/x-www-form-urlencoded")) {
    return await parseFormBody(req);
  }

  return {};
}