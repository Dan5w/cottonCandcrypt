"""Inicializa la base de datos y tablas del catalogo. Seguro de ejecutar multiples veces."""
from app import init_catalog

if __name__ == "__main__":
    print("Conectando a MySQL...")
    init_catalog()
    print("Base de datos inicializada correctamente.")
