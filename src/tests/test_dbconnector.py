import unittest
import os
import sys
from unittest.mock import patch, MagicMock
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db.db_connector import DBConnector

class TestDBConnector(unittest.TestCase):

    @patch('db.db_connector.pooling.MySQLConnectionPool')
    def setUp(self, mock_pool_class):
        # Mock the connection pool
        self.mock_pool = MagicMock()
        mock_pool_class.return_value = self.mock_pool
        
        # Initialize DBConnector with mocked pool
        conn_settings = {'host': 'localhost', 'user': 'test', 'password': 'test', 'database': 'testdb'}
        self.db = DBConnector(conn_settings)
        
    def test_pool_initialized_correctly(self):
        """Test that the connection pool is initialized with the right parameters."""
        self.db.pool.pool_name = 'mypool'
        self.assertEqual(self.db.pool, self.mock_pool)

    def test_cursor_context_manager_success(self):
        """Test that cursor context manager commits on success."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        
        # Setup mock pool to return mock connection
        self.db.pool.get_connection.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        with self.db.cursor() as cur:
            self.assertEqual(cur, mock_cursor)
            cur.execute('SELECT 1')  # simulate some operation

        mock_conn.commit.assert_called_once()
        mock_cursor.close.assert_called_once()
        mock_conn.close.assert_called_once()

    def test_cursor_context_manager_exception(self):
        """Test that cursor context manager rolls back on exception."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        
        self.db.pool.get_connection.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        class CustomError(Exception):
            pass

        def fail_execute():
            raise CustomError("DB Failure!")

        with self.assertRaises(CustomError):
            with self.db.cursor() as cur:
                cur.execute = fail_execute  # Force failure
                cur.execute()

        mock_conn.rollback.assert_called_once()
        mock_cursor.close.assert_called_once()
        mock_conn.close.assert_called_once()

    def test_cursor_always_closes(self):
        """Ensure cursor and connection are closed even if an exception happens."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()

        self.db.pool.get_connection.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        # Make the cursor creation itself fail
        mock_conn.cursor.side_effect = Exception("Cursor creation failed!")

        with self.assertRaises(Exception):
            with self.db.cursor():
                pass

        # Connection should still be closed even if cursor creation fails
        mock_conn.close.assert_called_once()

if __name__ == '__main__':
    unittest.main()
