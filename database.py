# database.py
import sqlite3
import os
from typing import Optional
from contextlib import contextmanager
import re

DATABASE_FILE = os.getenv("RELOADAI_DB", "reloadai.db")

# Whitelist para nomes de tabelas e colunas
ALLOWED_TABLES = [
    'users', 'subscriptions', 'analysis_results', 'analysis_logs',
    'exploit_listings', 'purchases', 'exploit_access', 'api_keys',
    'rate_limits', 'usage_reports'
]

ALLOWED_COLUMNS = {
    'users': ['id', 'email', 'name', 'stripe_customer_id', 'created_at'],
    'subscriptions': ['user_id', 'stripe_subscription_id', 'plan', 'status', 'created_at', 'updated_at'],
    'analysis_results': ['id', 'user_id', 'status', 'results', 'error', 'created_at', 'completed_at', 'task_id'],
    # ... adicionar outras tabelas e colunas
}

@contextmanager
def get_db():
    """Get database connection with proper cleanup"""
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON")
    
    try:
        yield conn
    finally:
        conn.close()

class Database:
    def __init__(self):
        self.conn = sqlite3.connect(DATABASE_FILE)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        
    def _validate_table_name(self, table: str) -> bool:
        """Valida nome de tabela contra whitelist"""
        return table in ALLOWED_TABLES
    
    def _validate_column_name(self, table: str, column: str) -> bool:
        """Valida nome de coluna contra whitelist"""
        return table in ALLOWED_COLUMNS and column in ALLOWED_COLUMNS[table]
    
    def execute(self, query: str, params: tuple = None):
        """Execute a query with parameters"""
        # Verifica se a query está usando parâmetros adequadamente
        if '?' not in query and params:
            raise ValueError("Query contains parameters but no placeholders")
        
        cursor = self.conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        self.conn.commit()
        return cursor
    
    def close(self):
        """Close the database connection"""
        self.conn.close()

def init_db():
    """Initialize the database schema"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                name TEXT,
                stripe_customer_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Subscriptions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                user_id TEXT PRIMARY KEY,
                stripe_subscription_id TEXT,
                plan TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Analysis results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                status TEXT NOT NULL,
                task_id TEXT,
                results JSON,
                error TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Analysis logs table for analytics
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                analysis_type TEXT NOT NULL,
                binary_size INTEGER,
                duration_seconds FLOAT,
                success BOOLEAN,
                features_used JSON,
                api_cost FLOAT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Exploit listings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exploit_listings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                product_id TEXT UNIQUE,
                price_id TEXT UNIQUE,
                title TEXT NOT NULL,
                description TEXT,
                type TEXT,
                price FLOAT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Purchases table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS purchases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                product_id TEXT NOT NULL,
                session_id TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (product_id) REFERENCES exploit_listings(product_id)
            )
        """)
        
        # Exploit access table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exploit_access (
                user_id TEXT NOT NULL,
                product_id TEXT NOT NULL,
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, product_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (product_id) REFERENCES exploit_listings(product_id)
            )
        """)
        
        # API keys table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                key TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP,
                active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Rate limiting table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                user_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                count INTEGER DEFAULT 1,
                PRIMARY KEY (user_id, endpoint, timestamp),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Usage reports table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usage_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                report_data JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Create indexes for better query performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_user ON analysis_results(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_status ON analysis_results(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_logs_user ON analysis_logs(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_listings_user ON exploit_listings(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_purchases_user ON purchases(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)")
        
        conn.commit()
        print("Database initialized successfully!")

def seed_test_data():
    """Seed the database with test data"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Create test user
        cursor.execute("""
            INSERT OR IGNORE INTO users (id, email, name)
            VALUES (?, ?, ?)
        """, ('test_user_1', 'test@reloadai.com', 'Test User'))
        
        # Create subscription for test user
        cursor.execute("""
            INSERT OR IGNORE INTO subscriptions (user_id, plan, status)
            VALUES (?, ?, ?)
        """, ('test_user_1', 'pro', 'active'))
        
        # Create test exploit listing
        cursor.execute("""
            INSERT OR IGNORE INTO exploit_listings (
                user_id, product_id, price_id, title, description, type, price, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            'test_user_1', 'prod_test1', 'price_test1',
            'Test Buffer Overflow Exploit',
            'A comprehensive buffer overflow exploit for educational purposes',
            'buffer_overflow', 99.99, 'active'
        ))
        
        conn.commit()
        print("Test data seeded successfully!")

def get_user_subscription(user_id: str) -> Optional[dict]:
    """Get user's active subscription"""
    with get_db() as conn:
        # Usa query parametrizada para prevenir SQL injection
        result = conn.execute("""
            SELECT s.*, u.email
            FROM subscriptions s
            JOIN users u ON s.user_id = u.id
            WHERE s.user_id = ? AND s.status = ?
        """, (user_id, 'active')).fetchone()
        
        return dict(result) if result else None

def get_user_analysis_stats(user_id: str) -> dict:
    """Get user's analysis statistics"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Total analyses
        total = cursor.execute("""
            SELECT COUNT(*) as count
            FROM analysis_logs
            WHERE user_id = ?
        """, (user_id,)).fetchone()['count']
        
        # Successful analyses
        successful = cursor.execute("""
            SELECT COUNT(*) as count
            FROM analysis_logs
            WHERE user_id = ? AND success = 1
        """, (user_id,)).fetchone()['count']
        
        # Monthly analyses
        monthly = cursor.execute("""
            SELECT COUNT(*) as count
            FROM analysis_logs
            WHERE user_id = ? AND timestamp >= datetime('now', 'start of month')
        """, (user_id,)).fetchone()['count']
        
        return {
            'total_analyses': total,
            'successful_analyses': successful,
            'success_rate': (successful / total * 100) if total > 0 else 0,
            'monthly_analyses': monthly
        }

def check_rate_limit(user_id: str, endpoint: str, limit: int, window_seconds: int) -> bool:
    """Check if user has exceeded rate limit"""
    with get_db() as conn:
        # Clean old entries
        conn.execute("""
            DELETE FROM rate_limits
            WHERE timestamp < datetime('now', ?)
        """, (f'-{window_seconds} seconds',))
        
        # Count recent requests
        count = conn.execute("""
            SELECT SUM(count) as total
            FROM rate_limits
            WHERE user_id = ? AND endpoint = ?
            AND timestamp >= datetime('now', ?)
        """, (user_id, endpoint, f'-{window_seconds} seconds')).fetchone()['total'] or 0
        
        # Record this request
        conn.execute("""
            INSERT INTO rate_limits (user_id, endpoint, timestamp, count)
            VALUES (?, ?, datetime('now'), 1)
            ON CONFLICT(user_id, endpoint, timestamp) DO UPDATE SET count = count + 1
        """, (user_id, endpoint))
        
        conn.commit()
        
        return count < limit

if __name__ == "__main__":
    # Initialize the database and seed test data
    init_db()
    seed_test_data()
    
    # Test queries
    with get_db() as conn:
        users = conn.execute("SELECT * FROM users").fetchall()
        print(f"Total users: {len(users)}")
        
        for user in users:
            print(f"User: {user['email']}")
            stats = get_user_analysis_stats(user['id'])
            print(f"  Stats: {stats}")
            subscription = get_user_subscription(user['id'])
            print(f"  Subscription: {subscription['plan'] if subscription else 'None'}")
