"""
Configuração compartilhada dos testes via conftest.py
"""

import pytest
from fastapi.testclient import TestClient
from api import app


@pytest.fixture(scope="session")
def test_app():
    """Retorna a instância da aplicação FastAPI para testes."""
    return app


@pytest.fixture(scope="function")
def client():
    """Retorna um cliente de teste para cada teste."""
    return TestClient(app)
