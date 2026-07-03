#!/bin/bash

echo "Stopping and removing all explicit containers..."
docker stop shomei_postgres shomei_redis shomei_backend shomei_frontend || true
docker rm shomei_postgres shomei_redis shomei_backend shomei_frontend || true

echo "Removing old images to ensure fresh builds..."
docker rmi oidc-auth-shomei_frontend oidc-auth-shomei_backend shomei-auth-shomei_frontend shomei-auth-shomei_backend shomei-auth-shomei_postgres shomei-auth-shomei_redis -f || true

echo "Clearing dangling volumes and networks..."

echo "Rebuilding and starting services..."
docker compose build --no-cache
docker compose up -d

echo "Starting Drizzle Studio on https://local.drizzle.studio"

echo "System maintenance complete! All services restarted."
