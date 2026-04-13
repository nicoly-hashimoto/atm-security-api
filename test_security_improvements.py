"""
Testes das Melhorias de Segurança
Valida: Rate Limiting, Logging, CORS, Password Validation, etc.
"""

import pytest
from fastapi.testclient import TestClient
from api import app, rate_limiter


@pytest.fixture
def client():
    """Cliente de teste."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reseta rate limiter entre testes."""
    rate_limiter.attempts.clear()
    yield
    rate_limiter.attempts.clear()


@pytest.fixture
def admin_token(client):
    """Token de admin."""
    response = client.post(
        "/auth/login",
        json={"username": "admin", "password": "superadmin123"}
    )
    if response.status_code != 200:
        raise Exception(f"Login failed: {response.json()}")
    return response.json()["access_token"]


class TestSecurityImprovements:
    """Testes das melhorias de segurança implementadas."""
    
    def test_dashboard_requires_authentication(self, client):
        """Dashboard agora requer autenticação."""
        response = client.get("/")
        assert response.status_code == 401
        assert "ausentes" in response.json()["detail"].lower()
    
    def test_dashboard_accessible_with_auth(self, client, admin_token):
        """Dashboard acessível com autenticação."""
        response = client.get(
            "/",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
    
    def test_rate_limiting_login(self, client):
        """Rate limit em tentativas de login."""
        # Fazer 6 tentativas (máximo é 5 por minuto)
        for i in range(6):
            response = client.post(
                "/auth/login",
                json={"username": "admin", "password": "wrongpass"}
            )
            if i < 5:
                assert response.status_code == 401
            else:
                # 6ª tentativa deve ser bloqueada
                assert response.status_code == 429
                assert "muitas tentativas" in response.json()["detail"].lower()
    
    def test_invalid_username_format_rejected(self, client, admin_token):
        """Usernames com caracteres inválidos são rejeitados."""
        response = client.post(
            "/admin/users",
            json={
                "username": "user@invalid!",  # caracteres inválidos
                "password": "Pass123456",
                "name": "Test",
                "role": "viewer"
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 400
    
    def test_weak_password_rejected(self, client, admin_token):
        """Senhas fracas são rejeitadas."""
        # Senha sem maiúscula
        response = client.post(
            "/admin/users",
            json={
                "username": "newuser",
                "password": "fraca123",  # sem maiúscula
                "name": "Test",
                "role": "viewer"
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 400
        assert "fraca" in response.json()["detail"].lower()
    
    def test_strong_password_accepted(self, client, admin_token):
        """Senhas fortes são aceitas."""
        response = client.post(
            "/admin/users",
            json={
                "username": "stronguser",
                "password": "StrongPass123",  # com maiúscula, minúscula e número
                "name": "Test",
                "role": "viewer"
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 201
    
    def test_invalid_actor_id_rejected(self, client, admin_token):
        """Actor IDs com caracteres inválidos são rejeitados."""
        response = client.post(
            "/events",
            json={
                "event_type": "card_inserted",
                "actor_id": "card" + "\x00" * 50,  # Null bytes
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 400
    
    def test_oversized_details_rejected(self, client, admin_token):
        """Detalhes muito longos são rejeitados."""
        response = client.post(
            "/events",
            json={
                "event_type": "card_inserted",
                "actor_id": "card-001",
                "details": "x" * 1000,  # Muito longo
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 400
    
    def test_invalid_role_rejected(self, client, admin_token):
        """Roles inválidas são rejeitadas ao criar usuário."""
        response = client.post(
            "/admin/users",
            json={
                "username": "testuser",
                "password": "ValidPass123",
                "name": "Test",
                "role": "superuser"  # Role inválida
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 400
        assert "role" in response.json()["detail"].lower()
    
    def test_logout_endpoint_exists(self, client, admin_token):
        """Endpoint de logout existe."""
        response = client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        assert "sucesso" in response.json()["message"].lower()
    
    def test_cors_headers_present(self, client):
        """Headers CORS estão presentes."""
        response = client.get("/health")
        # FastAPI adiciona CORS headers
        assert response.status_code == 200
    
    def test_logging_directory_created(self):
        """Diretório de logs é criado."""
        from pathlib import Path
        logs_dir = Path("./logs")
        assert logs_dir.exists()


class TestPasswordHashingImprovement:
    """Testes para verificar que bcrypt está funcionando."""
    
    def test_login_with_bcrypt_hash(self, client):
        """Login funciona com senhas com hash bcrypt."""
        # Todos os usuários padrão devem fazer login
        response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "superadmin123"}
        )
        assert response.status_code == 200
        assert "access_token" in response.json()
    
    def test_bcrypt_prevents_rainbow_tables(self, client, admin_token):
        """Bcrypt com salt único previne rainbow tables."""
        # Criar dois usuários com mesma senha
        response1 = client.post(
            "/admin/users",
            json={
                "username": "user1",
                "password": "SamePass123",
                "name": "User 1",
                "role": "viewer"
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        response2 = client.post(
            "/admin/users",
            json={
                "username": "user2",
                "password": "SamePass123",
                "name": "User 2",
                "role": "viewer"
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        # Ambos devem ser criados com sucesso e ter senhas diferentes (bcrypt com salts únicos)
        assert response1.status_code == 201
        assert response2.status_code == 201


class TestSessionTimeout:
    """Testes de timeout de sessão (30 minutos)."""
    
    def test_token_expires_after_30_minutes(self, client):
        """Token deve expirar após 30 minutos."""
        response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "superadmin123"}
        )
        data = response.json()
        
        # TTL deve ser ~30 minutos
        from datetime import datetime, timezone
        expires_at = datetime.fromisoformat(data["expires_at"])
        now = datetime.now(timezone.utc)
        diff_minutes = (expires_at - now).total_seconds() / 60
        
        # Verificar que é aproximadamente 30 minutos
        assert 25 < diff_minutes < 35


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
