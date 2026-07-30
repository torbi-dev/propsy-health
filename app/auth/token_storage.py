"""Token storage service with field-level encryption."""
import logging
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app.core.encryption import encrypt, decrypt

logger = logging.getLogger(__name__)


class TokenStorageService:
    """
    Service for managing OAuth tokens in MongoDB with field-level encryption.
    
    Encrypted fields (within token object):
    - access_token
    - refresh_token
    - expires_at
    
    Plaintext fields (for querying/indexing):
    - legacy_id, health_id, client_id, status, scopes, token_type, timestamps
    """
    
    COLLECTION_NAME = "oauth_tokens"
    
    # Fields within 'token' that should be encrypted
    ENCRYPTED_TOKEN_FIELDS = {"access_token", "refresh_token", "expires_at"}
    
    # Top-level fields that must remain plaintext for queries/indexes
    PLAINTEXT_TOP_FIELDS = {"legacy_id", "health_id", "client_id", "status", 
                            "created_at", "updated_at", "revoked_at", "_id"}
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db[self.COLLECTION_NAME]
    
    # ========================================================================
    # FIELD-LEVEL ENCRYPTION METHODS
    # ========================================================================
    
    def _process_token_data(self, token_data: dict, mode: str) -> dict:
        """
        Encrypt or decrypt sensitive fields within the token object.
        
        Args:
            token_data: Dict with token information
            mode: Either "encrypt" or "decrypt"
            
        Returns:
            Dict with processed sensitive fields
        """
        result = token_data.copy()
        
        # Only process if token field exists and is a dict
        if "token" in result and isinstance(result["token"], dict):
            token = result["token"].copy()
            
            for field in self.ENCRYPTED_TOKEN_FIELDS:
                if field in token and isinstance(token[field], str) and token[field]:
                    is_encrypted = token[field].startswith("gAAAA")
                    
                    try:
                        if mode == "encrypt" and not is_encrypted:
                            token[field] = encrypt(token[field])
                            logger.debug(f"Encrypted {field} for legacy_id: {result.get('legacy_id')}")
                            
                        elif mode == "decrypt" and is_encrypted:
                            token[field] = decrypt(token[field])
                            logger.debug(f"Decrypted {field} for legacy_id: {result.get('legacy_id')}")
                            
                    except ValueError:
                        # During decryption, this means the field might be plaintext or corrupted
                        if mode == "decrypt":
                            logger.warning(f"Could not decrypt {field} (may be plaintext or corrupted)")
                        else:
                            logger.error(f"Failed to encrypt {field}: ValueError")
                            raise
                    except Exception as e:
                        logger.error(f"Failed to {mode} {field}: {e}")
                        raise
            
            result["token"] = token
        
        return result

    def _encrypt_token_data(self, token_data: dict) -> dict:
        """Encrypt sensitive fields within the token object."""
        return self._process_token_data(token_data, mode="encrypt")
    
    def _decrypt_token_data(self, token_data: dict) -> dict:
        """Decrypt sensitive fields within the token object."""
        return self._process_token_data(token_data, mode="decrypt")
    
    # ========================================================================
    # CRUD OPERATIONS
    # ========================================================================
    
    async def create_token(self, token_document: dict) -> ObjectId:
        """Store a new token document with field-level encryption."""
        encrypted_doc = self._encrypt_token_data(token_document.copy())
        
        now = datetime.now(timezone.utc).isoformat()
        encrypted_doc["created_at"] = now
        encrypted_doc["updated_at"] = now
        encrypted_doc.setdefault("status", "active")
        
        result = await self.collection.insert_one(encrypted_doc)
        logger.info(f"Token stored (encrypted fields) for legacy_id: {token_document.get('legacy_id')}")
        return result.inserted_id
    
    async def get_token_by_legacy_id(self, legacy_id: str) -> dict | None:
        """Retrieve and decrypt token document by legacy_id."""
        doc = await self.collection.find_one({"legacy_id": legacy_id})
        if doc is None:
            return None
        return self._decrypt_token_data(doc)
    
    async def get_token_by_health_id(self, health_id: str) -> dict | None:
        """Retrieve and decrypt token document by health_id."""
        doc = await self.collection.find_one({"health_id": health_id})
        if doc is None:
            return None
        return self._decrypt_token_data(doc)
    
    async def get_all_tokens(self, limit: int = 100) -> list[dict]:
        """List active tokens (excluding sensitive fields from list view)."""
        cursor = self.collection.find(
            {"status": "active"},
            {"token.access_token": 0, "token.refresh_token": 0, "token.expires_at": 0}
        ).limit(limit)
        
        tokens = []
        async for doc in cursor:
            # Return safe view with plaintext identifiers only
            tokens.append({
                "legacy_id": doc.get("legacy_id"),
                "health_id": doc.get("health_id"),
                "client_id": doc.get("client_id"),
                "token": {
                    "scopes": doc.get("token", {}).get("scopes", []),
                    "token_type": doc.get("token", {}).get("token_type"),
                } if doc.get("token") else {},
                "status": doc.get("status"),
                "created_at": doc.get("created_at"),
                "updated_at": doc.get("updated_at"),
            })
        return tokens
    
    async def get_token_with_details(self, legacy_id: str) -> dict | None:
        """Retrieve full token document with decrypted sensitive fields."""
        doc = await self.collection.find_one({"legacy_id": legacy_id})
        if doc is None:
            return None
        return self._decrypt_token_data(doc)
    
    async def update_token(self, legacy_id: str, updates: dict) -> bool:
        """Update token document with auto-encryption of sensitive fields."""
        updates = updates.copy()
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        # Auto-encrypt sensitive token fields if present
        if "token" in updates and isinstance(updates["token"], dict):
            updates["token"] = self._encrypt_token_data({"token": updates["token"]})["token"]
        
        result = await self.collection.update_one(
            {"legacy_id": legacy_id},
            {"$set": updates}
        )
        
        if result.modified_count > 0:
            logger.info(f"Token updated (encrypted fields) for legacy_id: {legacy_id}")
        return result.modified_count > 0
    
    async def delete_token(self, legacy_id: str) -> bool:
        """Soft-delete by setting status to revoked."""
        result = await self.collection.update_one(
            {"legacy_id": legacy_id},
            {"$set": {
                "status": "revoked",
                "revoked_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        logger.info(f"Token revoked for legacy_id: {legacy_id}")
        return result.modified_count > 0
    
    async def hard_delete_token(self, legacy_id: str) -> bool:
        """Permanently delete a token document."""
        result = await self.collection.delete_one({"legacy_id": legacy_id})
        logger.warning(f"Token permanently deleted for legacy_id: {legacy_id}")
        return result.deleted_count > 0
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    async def is_token_valid(self, legacy_id: str) -> bool:
        """Check if token exists and is active (without decryption)."""
        doc = await self.collection.find_one(
            {"legacy_id": legacy_id, "status": "active"},
            {"_id": 1}
        )
        return doc is not None
    
    async def get_expired_tokens(self, buffer_minutes: int = 5) -> list[dict]:
        """Find tokens that are expired or expiring soon."""
        from datetime import timedelta
        
        cursor = self.collection.find({"status": "active"})
        expiring = []
        
        async for doc in cursor:
            decrypted = self._decrypt_token_data(doc)
            token = decrypted.get("token", {})
            expires_at = token.get("expires_at")
            
            if expires_at:
                try:
                    expiry = datetime.fromisoformat(expires_at)
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    
                    buffer = timedelta(minutes=buffer_minutes)
                    if datetime.now(timezone.utc) + buffer >= expiry:
                        expiring.append({
                            "legacy_id": decrypted["legacy_id"],
                            "health_id": decrypted["health_id"],
                            "expires_at": expires_at
                        })
                except (ValueError, AttributeError):
                    expiring.append({
                        "legacy_id": decrypted["legacy_id"],
                        "health_id": decrypted["health_id"],
                        "expires_at": expires_at,
                        "error": "unparseable_expiry"
                    })
        
        return expiring