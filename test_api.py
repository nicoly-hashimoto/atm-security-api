"""
Suite de testes para ATM Security API
Testa autenticação, autorização e endpoints protegidos.
"""

import pytest
from fastapi.testclient import TestClient
from api import app, rate_limiter


@pytest.fixture
def client():
    """Instancia o cliente de teste para a API."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reseta rate limiter entre testes."""
    rate_limiter.attempts.clear()
    yield
    rate_limiter.attempts.clear()


@pytest.fixture
def viewer_token(client):
    """Autentica como viewer e retorna o token."""
    response = client.post(
        "/auth/login",
        json={"username": "viewer", "password": "viewer123"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture
def operator_token(client):
    """Autentica como operator e retorna o token."""
    response = client.post(
        "/auth/login",
        json={"username": "operator", "password": "admin123"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture
def admin_token(client):
    """Autentica como admin e retorna o token."""
    response = client.post(
        "/auth/login",
        json={"username": "admin", "password": "superadmin123"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


class TestPublicEndpoints:
    """Testes para endpoints públicos que não requerem autenticação."""

    def test_health_endpoint(self, client):
        """GET /health deve retornar status ok sem autenticação."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_dashboard_endpoint(self, client, viewer_token):
        """GET / deve servir o dashboard com autenticação."""
        response = client.get(
            "/",
            headers={"Authorization": f"Bearer {viewer_token}"}
        )
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert len(response.text) > 0


class TestAuthentication:
    """Testes de autenticação e login."""

    def test_login_viewer_success(self, client):
        """Login com credenciais válidas de viewer deve retornar token."""
        response = client.post(
            "/auth/login",
            json={"username": "viewer", "password": "viewer123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["username"] == "viewer"
        assert data["role"] == "viewer"
        assert "dashboard:view" in data["permissions"]

    def test_login_operator_success(self, client):
        """Login com credenciais válidas de operator deve retornar token."""
        response = client.post(
            "/auth/login",
            json={"username": "operator", "password": "admin123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "operator"
        assert data["role"] == "operator"
        assert "dashboard:view" in data["permissions"]
        assert "events:write" in data["permissions"]

    def test_login_admin_success(self, client):
        """Login com credenciais válidas de admin deve retornar token."""
        response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "superadmin123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "admin"
        assert data["role"] == "admin"
        assert "dashboard:view" in data["permissions"]
        assert "events:write" in data["permissions"]
        assert "engine:reset" in data["permissions"]
        assert "users:manage" in data["permissions"]

    def test_login_invalid_username(self, client):
        """Login com username inválido deve retornar 401."""
        response = client.post(
            "/auth/login",
            json={"username": "invalido", "password": "qualquer123"}
        )
        assert response.status_code == 401
        assert "invalidos" in response.json()["detail"].lower()

    def test_login_invalid_password(self, client):
        """Login com senha inválida deve retornar 401."""
        response = client.post(
            "/auth/login",
            json={"username": "viewer", "password": "wrongpass"}
        )
        assert response.status_code == 401
        assert "invalidos" in response.json()["detail"].lower()

    def test_login_returns_token_type(self, client):
        """Token deve incluir data de expiração."""
        response = client.post(
            "/auth/login",
            json={"username": "viewer", "password": "viewer123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "expires_at" in data
        assert "operator_name" in data


class TestProtectedEndpoints:
    """Testes para endpoints que requerem autenticação."""

    def test_auth_me_without_token(self, client):
        """GET /auth/me sem token deve retornar 401."""
        response = client.get("/auth/me")
        assert response.status_code == 401
        assert "ausentes" in response.json()["detail"].lower()

    def test_auth_me_with_valid_token(self, client, viewer_token):
        """GET /auth/me com token válido deve retornar informações do usuário."""
        response = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {viewer_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "viewer"
        assert data["role"] == "viewer"
        assert data["name"] == "Monitoring Viewer"

    def test_auth_me_with_invalid_token(self, client):
        """GET /auth/me com token inválido deve retornar 401."""
        response = client.get(
            "/auth/me",
            headers={"Authorization": "Bearer invalid.token.here"}
        )
        assert response.status_code == 401
        assert "invalida" in response.json()["detail"].lower()

    def test_get_snapshot_without_token(self, client):
        """GET /snapshot sem token não requer autenticação."""
        response = client.get("/snapshot")
        assert response.status_code == 200
        data = response.json()
        assert "state" in data
        assert "risk_level" in data
        assert "alerts" in data
        assert "recent_events" in data

    def test_get_state_without_token(self, client):
        """GET /state sem token não requer autenticação."""
        response = client.get("/state")
        assert response.status_code == 200
        data = response.json()
        assert "pin_failures" in data
        assert "network_online" in data
        assert "maintenance_mode" in data

    def test_get_alerts_without_token(self, client):
        """GET /alerts sem token não requer autenticação."""
        response = client.get("/alerts")
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestAuthorizationByRole:
    """Testes de autorização e controle de acesso por role."""

    def test_process_event_requires_events_write_permission(self, client, viewer_token):
        """POST /events com viewer (sem events:write) deve retornar 403."""
        response = client.post(
            "/events",
            json={
                "event_type": "card_inserted",
                "actor_id": "card-001"
            },
            headers={"Authorization": f"Bearer {viewer_token}"}
        )
        assert response.status_code == 403
        assert "permissao" in response.json()["detail"].lower()

    def test_process_event_allowed_for_operator(self, client, operator_token):
        """POST /events com operator (com events:write) deve funcionar."""
        response = client.post(
            "/events",
            json={
                "event_type": "card_inserted",
                "actor_id": "card-001"
            },
            headers={"Authorization": f"Bearer {operator_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "processed_event" in data
        assert "generated_alerts" in data
        assert "state" in data

    def test_process_event_allowed_for_admin(self, client, admin_token):
        """POST /events com admin (com events:write) deve funcionar."""
        response = client.post(
            "/events",
            json={
                "event_type": "pin_failed",
                "actor_id": "card-001"
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "processed_event" in data

    def test_reset_engine_requires_engine_reset_permission(self, client, viewer_token):
        """POST /reset com viewer (sem engine:reset) deve retornar 403."""
        response = client.post(
            "/reset",
            headers={"Authorization": f"Bearer {viewer_token}"}
        )
        assert response.status_code == 403
        assert "permissao" in response.json()["detail"].lower()

    def test_reset_engine_requires_engine_reset_permission_operator(self, client, operator_token):
        """POST /reset com operator (sem engine:reset) deve retornar 403."""
        response = client.post(
            "/reset",
            headers={"Authorization": f"Bearer {operator_token}"}
        )
        assert response.status_code == 403
        assert "permissao" in response.json()["detail"].lower()

    def test_reset_engine_allowed_for_admin(self, client, admin_token):
        """POST /reset com admin (com engine:reset) deve funcionar."""
        response = client.post(
            "/reset",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "pin_failures" in data

    def test_list_operators_requires_users_manage(self, client, viewer_token):
        """GET /admin/users com viewer (sem users:manage) deve retornar 403."""
        response = client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {viewer_token}"}
        )
        assert response.status_code == 403
        assert "permissao" in response.json()["detail"].lower()

    def test_list_operators_allowed_for_admin(self, client, admin_token):
        """GET /admin/users com admin (com users:manage) deve funcionar."""
        response = client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "operators" in data
        assert isinstance(data["operators"], list)

    def test_create_operator_requires_users_manage(self, client, operator_token):
        """POST /admin/users com operator (sem users:manage) deve retornar 403."""
        response = client.post(
            "/admin/users",
            json={
                "username": "newuser",
                "password": "StrongPass123",
                "name": "Nova Pessoa",
                "role": "viewer"
            },
            headers={"Authorization": f"Bearer {operator_token}"}
        )
        assert response.status_code == 403
        assert "permissao" in response.json()["detail"].lower()

    def test_create_operator_allowed_for_admin(self, client, admin_token):
        """POST /admin/users com admin deve criar novo operador."""
        response = client.post(
            "/admin/users",
            json={
                "username": "testuser",
                "password": "StrongPass123",  # Senha forte (maiúscula, minúscula, número)
                "name": "Test User",
                "role": "viewer"
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "testuser"
        assert data["role"] == "viewer"
        assert data["name"] == "Test User"


class TestTokenValidation:
    """Testes de validação de tokens."""

    def test_invalid_token_format(self, client):
        """Token com formato inválido deve retornar 401."""
        response = client.get(
            "/auth/me",
            headers={"Authorization": "Bearer notavalidtoken"}
        )
        assert response.status_code == 401
        assert "invalido" in response.json()["detail"].lower()

    def test_missing_bearer_prefix(self, client, viewer_token):
        """Header sem "Bearer" deve retornar 401."""
        response = client.get(
            "/auth/me",
            headers={"Authorization": viewer_token}
        )
        assert response.status_code == 401

    def test_wrong_auth_scheme(self, client, viewer_token):
        """Usando "Basic" em vez de "Bearer" deve retornar 401."""
        response = client.get(
            "/auth/me",
            headers={"Authorization": f"Basic {viewer_token}"}
        )
        assert response.status_code == 401


class TestEventProcessing:
    """Testes de processamento de eventos."""

    def test_process_card_inserted_event(self, client, operator_token):
        """Processar evento de cartão inserido deve retornar sucesso."""
        response = client.post(
            "/events",
            json={
                "event_type": "card_inserted",
                "actor_id": "card-001",
                "details": "Cartão inserido normalmente"
            },
            headers={"Authorization": f"Bearer {operator_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "Evento processado" in data["message"]
        assert data["processed_event"]["event_type"] == "card_inserted"

    def test_process_pin_failed_event(self, client, operator_token):
        """Processar evento de PIN falhado deve retornar sucesso."""
        response = client.post(
            "/events",
            json={
                "event_type": "pin_failed",
                "actor_id": "card-001"
            },
            headers={"Authorization": f"Bearer {operator_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["processed_event"]["event_type"] == "pin_failed"

    def test_multiple_pin_failures_generate_alert(self, client, operator_token):
        """Múltiplas falhas de PIN devem gerar alerta."""
        # Enviar 3 falhas de PIN
        for _ in range(3):
            client.post(
                "/events",
                json={
                    "event_type": "pin_failed",
                    "actor_id": "card-001"
                },
                headers={"Authorization": f"Bearer {operator_token}"}
            )
        
        # Verificar se há alertas
        response = client.get("/alerts")
        assert response.status_code == 200
        alerts = response.json()
        pin_alerts = [a for a in alerts if "PIN" in a["title"]]
        assert len(pin_alerts) > 0


class TestOperatorManagement:
    """Testes de gerenciamento de operadores."""

    def test_get_operator_profile(self, client, viewer_token):
        """GET /auth/me retorna perfil do operador autenticado."""
        response = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {viewer_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "viewer"
        assert data["role"] == "viewer"
        assert "permissions" in data

    def test_list_all_operators_as_admin(self, client, admin_token):
        """Admin pode listar todos os operadores."""
        response = client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        operators = data["operators"]
        assert len(operators) >= 3  # viewer, operator, admin
        usernames = [op["username"] for op in operators]
        assert "viewer" in usernames
        assert "operator" in usernames
        assert "admin" in usernames

    def test_update_operator_password_as_admin(self, client, admin_token):
        """Admin pode atualizar senha de outro operador."""
        # Atualizar password do viewer
        response = client.put(
            "/admin/users/viewer",
            json={"password": "NewPass456"},  # Senha forte
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        
        # Tentar fazer login com nova senha
        login_response = client.post(
            "/auth/login",
            json={"username": "viewer", "password": "NewPass456"}
        )
        assert login_response.status_code == 200

    def test_update_operator_role_as_admin(self, client, admin_token):
        """Admin pode atualizar role de outro operador."""
        # Criar novo usuário
        client.post(
            "/admin/users",
            json={
                "username": "user_to_update",
                "password": "StrongPass789",  # Senha forte
                "name": "User",
                "role": "viewer"
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        # Atualizar role
        response = client.put(
            "/admin/users/user_to_update",
            json={"role": "operator"},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        assert response.json()["role"] == "operator"
        assert "events:write" in response.json()["permissions"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
