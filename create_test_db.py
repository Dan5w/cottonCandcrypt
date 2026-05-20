import sqlite3, os

db_path = os.path.join(os.path.dirname(__file__), "test_sqlite.db")
conn = sqlite3.connect(db_path)
c = conn.cursor()

c.execute("""CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    department TEXT,
    salary REAL,
    hire_date TEXT
)""")

c.execute("""CREATE TABLE IF NOT EXISTS departments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    location TEXT
)""")

departments = [
    ("Engineering", "Floor 3"),
    ("Marketing", "Floor 1"),
    ("Sales", "Floor 2"),
]
c.executemany("INSERT INTO departments (name, location) VALUES (?, ?)", departments)

employees = [
    ("Ana Garcia", "Engineering", 75000, "2023-01-15"),
    ("Carlos Lopez", "Marketing", 55000, "2023-03-20"),
    ("Maria Torres", "Sales", 60000, "2022-11-01"),
    ("Pedro Ruiz", "Engineering", 80000, "2021-06-10"),
    ("Laura Diaz", "Marketing", 52000, "2024-02-28"),
]
c.executemany("INSERT INTO employees (name, department, salary, hire_date) VALUES (?, ?, ?, ?)", employees)

conn.commit()

c.execute("SELECT COUNT(*) FROM employees")
emp_count = c.fetchone()[0]
c.execute("SELECT COUNT(*) FROM departments")
dep_count = c.fetchone()[0]

conn.close()
size = os.path.getsize(db_path)
print(f"Database created: {db_path}")
print(f"  Tables: employees ({emp_count} rows), departments ({dep_count} rows)")
print(f"  Size: {size} bytes")
