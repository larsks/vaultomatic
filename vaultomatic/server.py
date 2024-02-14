import logging

from fastapi import FastAPI

from .keystore import Keystore, VaultKeys
from .settings import SETTINGS
from .monitor import Monitor


logging.basicConfig(level=logging.INFO)


def create_app():
    app = FastAPI()
    keystore = Keystore(SETTINGS.redis_host, redis_port=SETTINGS.redis_port)
    monitor = Monitor(
        keystore,
        namespace=SETTINGS.vault_namespace,
        label_selector=SETTINGS.vault_selector,
    )

    @app.on_event("startup")
    def startup():
        monitor.start()

    @app.post("/keys")
    def update_keys(keys: VaultKeys):
        keystore.keys = keys
        return {"has_keys": True}

    @app.get("/status")
    def get_status():
        return {
            "keystore": bool(keystore.keys),
            "monitor": monitor.healthy,
        }

    return app
