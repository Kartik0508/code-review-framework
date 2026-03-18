from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    # Database
    DATABASE_URL: str = "postgresql://sonar:sonar_secure_pass_2024@sonarqube-db:5432/sonar"

    # SonarQube
    SONARQUBE_URL: str = "http://sonarqube:9000"
    SONARQUBE_TOKEN: str = ""

    # GitHub
    GITHUB_TOKEN: str = ""
    GITHUB_WEBHOOK_SECRET: str = "changeme_random_secret"

    # JWT
    SECRET_KEY: str = "changeme_super_secret_key_for_jwt"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Grafana
    GRAFANA_ADMIN_USER: str = "admin"
    GRAFANA_ADMIN_PASSWORD: str = "grafana_secure_pass_2024"

    # App
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"


settings = Settings()
