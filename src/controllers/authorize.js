import db from "../ultils/db.config.js";
import crypto from "node:crypto";
import { eq } from "drizzle-orm";
import {
  clients,
  users,
  authorizationCodes
} from "../db/schema.js";

export default async function authorizeController(
  client_id,
  req
) {
  const client = await db.query.clients.findFirst({
    where: eq(clients.client_id, client_id)
  });

  if (!client) {
    throw new Error("Client not found");
  }

  const userSessionId =
    req.headers.cookie
      ?.split(";")
      .find(cookie =>
        cookie.trim().startsWith("session_id=")
      )
      ?.split("=")[1];

  if (!userSessionId) {
    throw new Error("User not authenticated");
  }

  const user = await db.query.users.findFirst({
    where: eq(users.session_id, userSessionId)
  });

  if (!user) {
    throw new Error("Invalid session. User not found");
  }

  const shortcode =
    crypto.randomBytes(16).toString("hex");

  await db.insert(authorizationCodes).values({
    code: shortcode,
    client_id: client.client_id,
    user_id: user.id,
    expires_at: new Date(
      Date.now() + 5 * 60 * 1000
    )
  });

  return {
    redirect_uri: client.redirect_uri,
    shortcode
  };
}