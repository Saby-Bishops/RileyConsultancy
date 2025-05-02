from contextlib import contextmanager
from mysql.connector import pooling

class DBConnector:
    """
    Manages a MySQL connection pool and provides cursor context managers.
    """
    def __init__(self, conn_settings: dict, pool_name: str = 'mypool', pool_size: int = 5):
        # Initialize a connection pool
        self.pool = pooling.MySQLConnectionPool(
            pool_name=pool_name,
            pool_size=pool_size,
            **conn_settings
        )

    @contextmanager
    def cursor(self):
        """
        Context manager that yields a cursor from the pool,
        commits on success and rolls back on exception.
        """
        conn = None
        cur = None
        try:
            conn = self.pool.get_connection()
            cur = conn.cursor(dictionary=True)
            yield cur
            conn.commit()
        except Exception:
            if conn:
                conn.rollback()
            raise
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()