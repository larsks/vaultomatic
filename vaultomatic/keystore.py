from __future__ import annotations
import logging
import random
import threading
import time

import pydantic
import redis

LOG = logging.getLogger(__name__)


class VaultKeys(pydantic.BaseModel):
    unseal_keys_b64: list[str] = []
    unseal_keys_hex: list[str] = []
    unseal_shares: int
    unseal_threshold: int


#   recovery_keys_b64: list[str] = []
#   recovery_keys_hex: list[str] = []
#   recovery_keys_shares: int = 0
#   recovery_keys_threshold: int = 0
#   root_token: str | None = None


class Keystore:
    def __init__(self, redis_host, redis_port=6379):
        self._redis_host = redis_host
        self._redis_port = redis_port
        self._redis_connect()

        self._keys = None
        self._store_lock = threading.Lock()
        self._store_thread = None

    def _redis_connect(self):
        self._redis = redis.Redis(host=self._redis_host, port=self._redis_port)

    @property
    def keys(self):
        try:
            keys_json = self._redis.get("vault_keys")
            if keys_json:
                self._keys = VaultKeys.parse_raw(keys_json)
            else:
                self._keys = None
        except redis.exceptions.RedisError as err:
            LOG.error("failed to fetch keys from redis: %s", err)
        except pydantic.ValidationError as err:
            LOG.error("invalid keys in keystore: %s", err)

        return self._keys

    @keys.setter
    def keys(self, keys: VaultKeys):
        LOG.info("storing new keys")
        self._keys = keys

        if self._store_lock.acquire(blocking=False):
            self._store_thread = threading.Thread(
                target=self._retry_store_keys, daemon=True
            )
            self._store_thread.start()
        else:
            LOG.debug("store thread already active")

    @property
    def unseal_keys(self):
        if self._keys:
            return random.sample(self._keys.unseal_keys_hex, self.keys.unseal_threshold)

    def _retry_store_keys(self):
        try:
            while True:
                try:
                    LOG.debug("sending keys to redis")
                    self._redis.set("vault_keys", self._keys.json())
                    LOG.debug("successfully stored keys in redis")
                    break
                except redis.exceptions.RedisError as err:
                    LOG.error("failed to store keys (retrying): %s", err)

                time.sleep(2)
        finally:
            self._store_lock.release()


if __name__ == "__main__":
    logging.basicConfig(level="DEBUG")
    keys = VaultKeys(unseal_shares=5, unseal_threshold=3)
    keystore = Keystore("rfrm-vaultomatic-keystore")
