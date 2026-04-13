"""
Script de teste rápido para validar autenticação
Executa os testes mais importantes de forma isolada
"""

import subprocess
import sys
from pathlib import Path


def run_tests(filter_pattern: str = None, verbose: bool = True) -> int:
    """
    Executa os testes com pytest.
    
    Args:
        filter_pattern: Padrão para filtrar testes (ex: "authentication")
        verbose: Se deve usar output verboso (-v)
    
    Returns:
        Código de saída do pytest
    """
    cmd = ["pytest", "test_api.py"]
    
    if verbose:
        cmd.append("-v")
    
    if filter_pattern:
        cmd.extend(["-k", filter_pattern])
    
    return subprocess.run(cmd).returncode


def main():
    """Menu interativo de testes."""
    print("\n" + "=" * 60)
    print("ATM Security API - Suite de Testes")
    print("=" * 60 + "\n")
    
    options = {
        "1": ("Todos os testes", None),
        "2": ("Testes de Autenticação", "Authentication"),
        "3": ("Testes de Autorização", "Authorization"),
        "4": ("Testes de Endpoints Públicos", "public"),
        "5": ("Testes de Processamento de Eventos", "EventProcessing"),
        "6": ("Testes de Gerenciamento de Operadores", "OperatorManagement"),
        "7": ("Apenas testes que falharam", "--lf"),
        "8": ("Testes com cobertura", "coverage"),
    }
    
    print("Opções disponíveis:")
    for key, (label, _) in options.items():
        print(f"  {key}. {label}")
    print("  0. Sair\n")
    
    choice = input("Escolha uma opção (0-8): ").strip()
    
    if choice == "0":
        print("Saindo...")
        return 0
    
    if choice not in options:
        print("Opção inválida!")
        return 1
    
    label, pattern = options[choice]
    print(f"\nExecutando: {label}\n")
    
    if pattern == "coverage":
        # Instalar e executar com cobertura
        subprocess.run(["pip", "install", "-q", "pytest-cov"], check=False)
        return subprocess.run(
            ["pytest", "test_api.py", "--cov=.", "--cov-report=html", "-v"]
        ).returncode
    elif pattern == "--lf":
        # Últimos testes que falharam
        return subprocess.run(["pytest", "test_api.py", "--lf", "-v"]).returncode
    else:
        return run_tests(pattern)


if __name__ == "__main__":
    sys.exit(main())
