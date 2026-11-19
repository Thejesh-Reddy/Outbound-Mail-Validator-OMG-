
# """
# MongoDB connection manager for OMG.
# Uses MONGODB_URI from the .env file.
# """

import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB = os.getenv("MONGODB_DB", "OMG_Database")

if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is missing from .env")

client = MongoClient(
    MONGODB_URI,
    serverSelectionTimeoutMS=10000
)

client.admin.command("ping")

db = client[MONGODB_DB]

users_collection = db["users"]
sessions_collection = db["auth_sessions"]
analysis_collection = db["email_analysis"]

# Replace the legacy index if it uses the same name for a different field.
session_indexes = {
    index["name"]: index
    for index in sessions_collection.list_indexes()
}
existing_session_jti_index = session_indexes.get("unique_session_jti")
if (
    existing_session_jti_index
    and (
        existing_session_jti_index.get("key") != {"jwt_token": 1}
        or existing_session_jti_index.get("unique") is not True
        or existing_session_jti_index.get("partialFilterExpression")
        != {"jwt_token": {"$exists": True}}
    )
):
    sessions_collection.drop_index("unique_session_jti")

# Create indexes safely using consistent names
users_collection.create_index(
    [("email", 1)],
    unique=True,
    name="unique_user_email"
)

sessions_collection.create_index(
    [("jwt_token", 1)],
    unique=True,
    partialFilterExpression={"jwt_token": {"$exists": True}},
    name="unique_session_jti"
)

sessions_collection.create_index(
    [("expires_at", 1)],
    expireAfterSeconds=0,
    name="session_expiry_ttl"
)

analysis_collection.create_index(
    [("account_id", 1), ("created_at", -1)],
    name="account_history_index"
)

def connect_to_mongodb():
    """Verify MongoDB connection."""
    client.admin.command("ping")
    print("MongoDB connected successfully")
    return db

def get_database():
    return db

print("MongoDB connected successfully")
