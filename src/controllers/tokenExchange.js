import db from "../ultils/db.config.js";
import bcrypt from "bcrypt";
import { and, eq, gt } from "drizzle-orm";
import {
  clients,
  users,
  authorizationCodes
} from "../db/schema.js";

import {
  signAccessToken
} from "../ultils/token.service.js";

export default async function tokenExchangeController(
  shortcode,
  clientId,
  clientSecret
) {
  const client = await db.query.clients.findFirst({
    where: eq(clients.client_id, clientId)
  });

  if (!client) {
    throw new Error("Invalid client credentials");
  }

  const secretMatch =
    await bcrypt.compare(
      clientSecret,
      client.client_secret_hash
    );

  if (!secretMatch) {
    throw new Error("Invalid client credentials");
  }

  const authCode =
    await db.query.authorizationCodes.findFirst({
      where: and(
        eq(authorizationCodes.code, shortcode),
        eq(authorizationCodes.client_id, clientId),
        gt(
          authorizationCodes.expires_at,
          new Date()
        )
      )
    });

  if (!authCode) {
    throw new Error(
      "Invalid or expired authorization code"
    );
  }

  if (authCode.used) {
    throw new Error(
      "Authorization code already used"
    );
  }

  const user = await db.query.users.findFirst({
    where: eq(users.id, authCode.user_id)
  });

  if (!user) {
    throw new Error(
      "User associated with authorization code not found"
    );
  }

  await db.update(authorizationCodes)
    .set({ used: true })
    .where(eq(
      authorizationCodes.id,
      authCode.id
    ));

  const access_token = signAccessToken({
    sub: user.id,
    email: user.email,
    name: user.name,
    client_id: clientId
  });

  return { access_token };
}