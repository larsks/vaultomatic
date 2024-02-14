from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    class Config:
        env_prefix = "VOM_"

    redis_host: str
    redis_port: int = 6379
    vault_namespace: str = "vault"
    vault_selector: str = "app.kubernetes.io/name=vault,component=server"


SETTINGS = Settings()
