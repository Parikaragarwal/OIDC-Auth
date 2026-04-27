import * as p from "drizzle-orm/pg-core";

export const sessionStatus = p.pgEnum("session_status", ["active", "revoked","expired"]);

export const users = p.pgTable("users", {
  id: p.integer().primaryKey().generatedAlwaysAsIdentity(),
  email: p.varchar().notNull().unique(),
  password_hash: p.varchar().notNull(),
  name: p.varchar().notNull(),
  session_id: p.varchar().unique(),
  created_at: p.timestamp().defaultNow(),
});

export const clients = p.pgTable("clients",{
  client_id: p.varchar().primaryKey(),
  client_secret_hash: p.varchar().notNull(),
  name: p.varchar().notNull(),
  base_url: p.varchar().notNull(),
  redirect_uri:p.varchar().notNull(),
  created_at: p.timestamp().defaultNow(),
});

export const userSessions = p.pgTable("user_sessions",{
  session_id: p.varchar().primaryKey(),
  user_id: p.integer().notNull().references(() => users.id),
  client_id: p.varchar().notNull().references(() => clients.client_id),
  created_at: p.timestamp().defaultNow(),
  expires_at: p.timestamp().notNull(),
  status: sessionStatus().notNull().default("active"),
});

export const authorizationCodes = p.pgTable("authorization_codes",{
  id:p.integer().primaryKey().generatedAlwaysAsIdentity(),
  code: p.varchar().notNull().unique(),
  client_id: p.varchar().notNull().references(() => clients.client_id),
  user_id: p.integer().notNull().references(() => users.id),
  used: p.boolean().default(false),
  expires_at: p.timestamp().notNull(),
});