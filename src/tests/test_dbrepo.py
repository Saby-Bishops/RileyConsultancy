import unittest
from unittest.mock import MagicMock
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db.db_repo import DBRepository

class TestDBRepository(unittest.TestCase):

    def setUp(self):
        self.mock_connector = MagicMock()
        self.mock_cursor = MagicMock()

        # Define a side effect for cursor() that returns a context manager
        def mock_cursor_context():
            yield self.mock_cursor

        self.mock_connector.cursor.return_value.__enter__.return_value = self.mock_cursor
        self.mock_connector.cursor.return_value.__exit__.return_value = None
        self.mock_connector.cursor.side_effect = mock_cursor_context
        self.repository = DBRepository(self.mock_connector, 'users')
        self.test_data = {'name': 'Alice', 'email': 'alice@example.com'}

    def test_get_cursor(self):
        with self.repository.get_cursor() as cursor:
            self.assertEqual(cursor, self.mock_cursor)
        self.mock_connector.cursor.assert_called_once()

    def test_save_insert(self):
        self.mock_cursor.lastrowid = 123
        result = self.repository.save(self.test_data)
        self.assertEqual(result, 123)
        self.mock_cursor.execute.assert_called_once_with(
            "INSERT INTO users (name, email) VALUES (%s, %s)", ('Alice', 'alice@example.com')
        )

    def test_save_update(self):
        self.mock_cursor.fetchall.return_value = [{'id': 1, 'name': 'Bob', 'email': 'bob@example.com'}]
        self.mock_cursor.rowcount = 1
        result = self.repository.save({'id': 1, 'email': 'bob.new@example.com'}, unique_fields=['id'])
        self.assertEqual(result, 1)
        self.mock_cursor.execute.assert_any_call(
            "SELECT * FROM users WHERE id = %s LIMIT 1", (1,)
        )
        self.mock_cursor.execute.assert_any_call(
            "UPDATE users SET email = %s WHERE id = %s", ('bob.new@example.com', 1)
        )

    def test_save_no_data(self):
        with self.assertRaises(ValueError) as context:
            self.repository.save({})
        self.assertEqual(str(context.exception), "No data provided to save")
        self.mock_cursor.execute.assert_not_called()

    def test_insert(self):
        self.mock_cursor.lastrowid = 456
        result = self.repository.insert(self.test_data)
        self.assertEqual(result, 456)
        self.mock_cursor.execute.assert_called_once_with(
            "INSERT INTO users (name, email) VALUES (%s, %s)", ('Alice', 'alice@example.com')
        )

    def test_insert_no_data(self):
        with self.assertRaises(ValueError) as context:
            self.repository.insert({})
        self.assertEqual(str(context.exception), "No data provided to insert")
        self.mock_cursor.execute.assert_not_called()

    def test_update(self):
        self.mock_cursor.rowcount = 2
        result = self.repository.update({'email': 'alice.new@example.com'}, name='Alice')
        self.assertEqual(result, 2)
        self.mock_cursor.execute.assert_called_once_with(
            "UPDATE users SET email = %s WHERE name = %s", ('alice.new@example.com', 'Alice')
        )

    def test_update_no_data(self):
        with self.assertRaises(ValueError) as context:
            self.repository.update({}, name='Alice')
        self.assertEqual(str(context.exception), "No data provided to update")
        self.mock_cursor.execute.assert_not_called()

    def test_update_no_conditions(self):
        with self.assertRaises(ValueError) as context:
            self.repository.update({'email': 'test@example.com'})
        self.assertEqual(str(context.exception), "No conditions provided for update - this would update all records")
        self.mock_cursor.execute.assert_not_called()

    def test_delete(self):
        self.mock_cursor.rowcount = 1
        result = self.repository.delete(email='alice@example.com')
        self.assertEqual(result, 1)
        self.mock_cursor.execute.assert_called_once_with(
            "DELETE FROM users WHERE email = %s", ('alice@example.com',)
        )

    def test_delete_no_conditions(self):
        with self.assertRaises(ValueError) as context:
            self.repository.delete()
        self.assertEqual(str(context.exception), "No conditions provided for delete - this would delete all records")
        self.mock_cursor.execute.assert_not_called()

    def test_find(self):
        mock_results = [
            {'id': 1, 'name': 'Alice', 'email': 'alice@example.com'},
            {'id': 2, 'name': 'Bob', 'email': 'bob@example.com'}
        ]
        self.mock_cursor.fetchall.return_value = mock_results
        result = self.repository.find(name='Alice')
        self.assertEqual(result, mock_results)
        self.mock_cursor.execute.assert_called_once_with(
            "SELECT * FROM users WHERE name = %s", ('Alice',)
        )

    def test_find_with_limit_offset_order_by(self):
        mock_results = [{'id': 3, 'name': 'Charlie', 'email': 'charlie@example.com'}]
        self.mock_cursor.fetchall.return_value = mock_results
        result = self.repository.find(limit=1, offset=2, order_by=('name', 'DESC'), email='c@example.com')
        self.assertEqual(result, mock_results)
        self.mock_cursor.execute.assert_called_once_with(
            "SELECT * FROM users WHERE email = %s ORDER BY name DESC LIMIT 1 OFFSET 2", ('c@example.com',)
        )

    def test_find_all(self):
        mock_results = [
            {'id': 1, 'name': 'Alice', 'email': 'alice@example.com'},
            {'id': 2, 'name': 'Bob', 'email': 'bob@example.com'}
        ]
        self.mock_cursor.fetchall.return_value = mock_results
        result = self.repository.find()
        self.assertEqual(result, mock_results)
        self.mock_cursor.execute.assert_called_once_with(
            "SELECT * FROM users WHERE 1=1", ()
        )

    def test_find_one_found(self):
        mock_result = [{'id': 1, 'name': 'Alice', 'email': 'alice@example.com'}]
        self.mock_cursor.fetchall.return_value = mock_result
        result = self.repository.find_one(name='Alice')
        self.assertEqual(result, mock_result[0])
        self.mock_cursor.execute.assert_called_once_with(
            "SELECT * FROM users WHERE name = %s LIMIT 1", ('Alice',)
        )

    def test_find_one_not_found(self):
        self.mock_cursor.fetchall.return_value = []
        result = self.repository.find_one(name='NonExistent')
        self.assertIsNone(result)
        self.mock_cursor.execute.assert_called_once_with(
            "SELECT * FROM users WHERE name = %s LIMIT 1", ('NonExistent',)
        )

    def test_count(self):
        self.mock_cursor.fetchone.return_value = {'count': 3}
        result = self.repository.count(email__like='%example.com%')
        self.assertEqual(result, 3)
        self.mock_cursor.execute.assert_called_once_with(
            "SELECT COUNT(*) as count FROM users WHERE email__like = %s", ('%example.com%',)
        )

    def test_count_all(self):
        self.mock_cursor.fetchone.return_value = {'count': 5}
        result = self.repository.count()
        self.assertEqual(result, 5)
        self.mock_cursor.execute.assert_called_once_with(
            "SELECT COUNT(*) as count FROM users WHERE 1=1", ()
        )

    def test_execute_raw_select(self):
        mock_results = [(1, 'Data1'), (2, 'Data2')]
        self.mock_cursor.fetchall.return_value = mock_results
        query = "SELECT id, value FROM data_table WHERE status = %s"
        params = ('active',)
        result = self.repository.execute_raw(query, params)
        self.assertEqual(result, mock_results)
        self.mock_cursor.execute.assert_called_once_with(query, params)

    def test_execute_raw_insert(self):
        self.mock_cursor.rowcount = 1
        query = "INSERT INTO logs (message) VALUES (%s)"
        params = ('User logged in',)
        result = self.repository.execute_raw(query, params)
        self.assertEqual(result, 1)
        self.mock_cursor.execute.assert_called_once_with(query, params)

    def test_execute_raw_update(self):
        self.mock_cursor.rowcount = 3
        query = "UPDATE items SET quantity = quantity + 1 WHERE category = %s"
        params = ('books',)
        result = self.repository.execute_raw(query, params)
        self.assertEqual(result, 3)
        self.mock_cursor.execute.assert_called_once_with(query, params)

    def test_execute_raw_delete(self):
        self.mock_cursor.rowcount = 2
        query = "DELETE FROM events WHERE timestamp < %s"
        params = ('2025-04-28',)
        result = self.repository.execute_raw(query, params)
        self.assertEqual(result, 2)
        self.mock_cursor.execute.assert_called_once_with(query, params)

if __name__ == '__main__':
    unittest.main()