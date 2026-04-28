import db from "../ultils/db.config.js";
import bcrypt from "bcrypt";
import crypto from "node:crypto";
import { and, eq } from "drizzle-orm";
import { clients } from "../db/schema.js";

export default async function clientSignupController(
  name,
  base_url,
  redirect_uri
) {
  const existingClient =
    await db.query.clients.findFirst({
      where: and(
        eq(clients.name, name),
        eq(clients.base_url, base_url)
      )
    });

  if (existingClient) {
    throw new Error("Client already exists");
  }

  const client_id = crypto.randomUUID();
  const client_secret =
    crypto.randomBytes(32).toString("hex");

  const client_secret_hash =
    await bcrypt.hash(client_secret, 10);

  await db.insert(clients).values({
    client_id,
    client_secret_hash,
    name,
    base_url,
    redirect_uri
  });

  return {
    client_id,
    client_secret
  };
}