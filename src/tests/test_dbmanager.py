import unittest
from unittest.mock import MagicMock
import datetime
from werkzeug.security import generate_password_hash
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.db_connector import DBConnector
from db.db_repo import DBRepository
from db.db_manager import DBManager

class TestDBManager(unittest.TestCase):

    def setUp(self):
        self.mock_connector = MagicMock(spec=DBConnector)
        self.mock_cursor = MagicMock()

        def mock_cursor_context():
            yield self.mock_cursor

        self.mock_connector.cursor.side_effect = mock_cursor_context
        self.db_manager = DBManager(self.mock_connector)

        # Reset mock call counts before each test
        self.mock_cursor.reset_mock()
        self.mock_connector.cursor.reset_mock()

    def test_initialization_and_table_creation(self):
        # Verify that the _ensure_tables_exist method was called during initialization
        self.mock_cursor.execute.assert_any_call("""
                CREATE TABLE IF NOT EXISTS employees (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    first_name VARCHAR(255) NOT NULL,
                    last_name VARCHAR(255) NOT NULL,
                    domain VARCHAR(255)
                );
            """)
        self.mock_cursor.execute.assert_any_call("""
                CREATE TABLE IF NOT EXISTS email_results (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    employee_id INT,
                    email VARCHAR(255),
                    score DOUBLE,
                    FOREIGN KEY (employee_id) REFERENCES employees (id)
                );
            """)
        self.mock_cursor.execute.assert_any_call("""
                CREATE TABLE IF NOT EXISTS account_findings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    employee_id INT,
                    username VARCHAR(255),
                    site_name VARCHAR(255),
                    url VARCHAR(2083),
                    category VARCHAR(255),
                    http_status INT,
                    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (employee_id) REFERENCES employees (id)
                );
            """)
        self.mock_cursor.execute.assert_any_call('''
                CREATE TABLE IF NOT EXISTS phishing_urls (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    url VARCHAR(2083) NOT NULL,
                    timestamp DATE NOT NULL
                );
            ''')
        self.mock_cursor.execute.assert_any_call('''
                CREATE TABLE IF NOT EXISTS gvm_scan_sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    task_id VARCHAR(255) NOT NULL,
                    timestamp DATETIME NOT NULL,
                    total_vulnerabilities INT NOT NULL,
                    critical_count INT NOT NULL,
                    high_count INT NOT NULL,
                    medium_count INT NOT NULL,
                    low_count INT NOT NULL
                );
            ''')
        self.mock_cursor.execute.assert_any_call('''
                CREATE TABLE IF NOT EXISTS gvm_vulnerabilities (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    session_id INT NOT NULL,
                    vuln_id VARCHAR(255) NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    host VARCHAR(255) NOT NULL,
                    port VARCHAR(255) NOT NULL,
                    severity VARCHAR(255) NOT NULL,
                    severity_value DOUBLE NOT NULL,
                    description TEXT,
                    cvss_base VARCHAR(255),
                    timestamp DATETIME NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES gvm_scan_sessions(id)
                );
            ''')
        self.mock_cursor.execute.assert_any_call('''
                CREATE TABLE IF NOT EXISTS nids_alerts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    source_ip VARCHAR(45),
                    destination_ip VARCHAR(45),
                    source_port INT,
                    destination_port INT,
                    protocol INT,
                    threat_type VARCHAR(255),
                    severity VARCHAR(255),
                    description TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            ''')
        self.mock_cursor.execute.assert_any_call('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE,
                    role VARCHAR(50) DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL
                );
            ''')
        self.assertEqual(self.mock_cursor.execute.call_count, 8)

    def test_get_cursor(self):
        with self.db_manager.get_cursor() as cursor:
            self.assertEqual(cursor, self.mock_cursor)
        self.mock_connector.cursor.assert_called_once()

    def test_get_repository(self):
        repo1 = self.db_manager.get_repository('employees')
        self.assertIsInstance(repo1, DBRepository)
        self.assertEqual(repo1.table_name, 'employees')
        self.assertEqual(repo1.connector, self.mock_connector)

        repo2 = self.db_manager.get_repository('employees')
        self.assertEqual(repo1, repo2) # Should return the same instance

        repo3 = self.db_manager.get_repository('tasks')
        self.assertNotEqual(repo1, repo3)
        self.assertEqual(repo3.table_name, 'tasks')

    def test_convenience_methods(self):
        self.assertIsInstance(self.db_manager.employees(), DBRepository)
        self.assertEqual(self.db_manager.employees().table_name, 'employees')

        self.assertIsInstance(self.db_manager.email_results(), DBRepository)
        self.assertEqual(self.db_manager.email_results().table_name, 'email_results')

        self.assertIsInstance(self.db_manager.account_findings(), DBRepository)
        self.assertEqual(self.db_manager.account_findings().table_name, 'account_findings')

        self.assertIsInstance(self.db_manager.phishing_urls(), DBRepository)
        self.assertEqual(self.db_manager.phishing_urls().table_name, 'phishing_urls')

        self.assertIsInstance(self.db_manager.gvm_scan_sessions(), DBRepository)
        self.assertEqual(self.db_manager.gvm_scan_sessions().table_name, 'gvm_scan_sessions')

        self.assertIsInstance(self.db_manager.gvm_vulnerabilities(), DBRepository)
        self.assertEqual(self.db_manager.gvm_vulnerabilities().table_name, 'gvm_vulnerabilities')

        self.assertIsInstance(self.db_manager.nids_alerts(), DBRepository)
        self.assertEqual(self.db_manager.nids_alerts().table_name, 'nids_alerts')

        self.assertIsInstance(self.db_manager.users(), DBRepository)
        self.assertEqual(self.db_manager.users().table_name, 'users')

    def test_save_email_result_insert(self):
        mock_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['email_results'] = mock_repo
        mock_repo.save.return_value = 123
        result = self.db_manager.save_email_result(1, 'test@example.com', 0.9)
        self.assertEqual(result, 123)
        mock_repo.save.assert_called_once_with(
            {'employee_id': 1, 'email': 'test@example.com', 'score': 0.9},
            unique_fields=['employee_id']
        )

    def test_save_email_result_update(self):
        mock_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['email_results'] = mock_repo
        mock_repo.save.return_value = 1
        result = self.db_manager.save_email_result(1, 'new@example.com', 0.7)
        self.assertEqual(result, 1)
        mock_repo.save.assert_called_once_with(
            {'employee_id': 1, 'email': 'new@example.com', 'score': 0.7},
            unique_fields=['employee_id']
        )

    def test_save_account_finding(self):
        mock_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['account_findings'] = mock_repo
        mock_repo.insert.return_value = 456
        result = self.db_manager.save_account_finding(1, 'user1', 'siteA', 'http://sitea.com', 'login', 200)
        self.assertEqual(result, 456)
        mock_repo.insert.assert_called_once_with({
            'employee_id': 1,
            'username': 'user1',
            'site_name': 'siteA',
            'url': 'http://sitea.com',
            'category': 'login',
            'http_status': 200
        })

    def test_save_gvm_results(self):
        mock_gvm_repo = MagicMock(spec=DBRepository)
        mock_vuln_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['gvm_scan_sessions'] = mock_gvm_repo
        self.db_manager._repositories['gvm_vulnerabilities'] = mock_vuln_repo

        mock_gvm_repo.insert.return_value = 789
        gvm_results = {
            'total': 2,
            'summary': {'Critical': 1, 'High': 0, 'Medium': 1, 'Low': 0},
            'results': [
                {'id': 'vuln1', 'name': 'Critical Vuln', 'host': 'hostA', 'port': '80', 'severity': 'Critical', 'severity_value': 9.0, 'description': '...', 'cvss_base': '...', 'timestamp': '...'},
                {'id': 'vuln2', 'name': 'Medium Vuln', 'host': 'hostB', 'port': '443', 'severity': 'Medium', 'severity_value': 5.0, 'description': '...', 'cvss_base': '...', 'timestamp': '...'}
            ]
        }
        session_id = self.db_manager.save_gvm_results('task123', gvm_results)
        self.assertEqual(session_id, 789)

        mock_gvm_repo.insert.assert_called_once()
        call_args_session = mock_gvm_repo.insert.call_args[0][0]
        self.assertEqual(call_args_session['task_id'], 'task123')
        self.assertIsInstance(datetime.datetime.strptime(call_args_session['timestamp'], "%Y-%m-%d %H:%M:%S"), datetime.datetime)
        self.assertEqual(call_args_session['total_vulnerabilities'], 2)
        self.assertEqual(call_args_session['critical_count'], 1)
        self.assertEqual(call_args_session['high_count'], 0)
        self.assertEqual(call_args_session['medium_count'], 1)
        self.assertEqual(call_args_session['low_count'], 0)

        self.assertEqual(mock_vuln_repo.insert.call_count, 2)
        call_args_vuln1 = mock_vuln_repo.insert.call_args_list[0][0][0]
        self.assertEqual(call_args_vuln1['session_id'], 789)
        self.assertEqual(call_args_vuln1['vuln_id'], 'vuln1')
        self.assertEqual(call_args_vuln1['name'], 'Critical Vuln')
        call_args_vuln2 = mock_vuln_repo.insert.call_args_list[1][0][0]
        self.assertEqual(call_args_vuln2['session_id'], 789)
        self.assertEqual(call_args_vuln2['vuln_id'], 'vuln2')
        self.assertEqual(call_args_vuln2['name'], 'Medium Vuln')

    def test_save_alert(self):
        mock_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['nids_alerts'] = mock_repo
        mock_repo.insert.return_value = 901
        alert_data = {'source_ip': '1.2.3.4', 'destination_ip': '5.6.7.8', 'threat_type': 'Malicious'}
        result = self.db_manager.save_alert(alert_data)
        self.assertEqual(result, 901)
        mock_repo.insert.assert_called_once()
        inserted_data = mock_repo.insert.call_args[0][0]
        self.assertEqual(inserted_data['source_ip'], '1.2.3.4')
        self.assertEqual(inserted_data['destination_ip'], '5.6.7.8')
        self.assertEqual(inserted_data['threat_type'], 'Malicious')
        self.assertIsInstance(datetime.datetime.strptime(inserted_data['timestamp'], "%Y-%m-%d %H:%M:%S"), datetime.datetime)

    def test_save_phishing_data(self):
        mock_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['phishing_urls'] = mock_repo
        mock_repo.insert.side_effect = [101, 102]
        timestamp = datetime.date(2025, 4, 28)
        urls = ['http://phishing1.com', 'http://phishing2.net']
        ids = self.db_manager.save_phishing_data(urls, timestamp)
        self.assertEqual(ids, [101, 102])
        self.assertEqual(mock_repo.insert.call_count, 2)
        mock_repo.insert.assert_any_call({'url': 'http://phishing1.com', 'timestamp': timestamp})
        mock_repo.insert.assert_any_call({'url': 'http://phishing2.net', 'timestamp': timestamp})

    def test_show_phishing_urls(self):
        mock_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['phishing_urls'] = mock_repo
        mock_repo.find.return_value = [{'id': 1, 'url': 'phish.com', 'timestamp': datetime.date(2025, 4, 28)}]
        result = self.db_manager.show_phishing_urls()
        self.assertEqual(result, [{'id': 1, 'url': 'phish.com', 'timestamp': datetime.date(2025, 4, 28)}])
        mock_repo.find.assert_called_once()

    def test_get_gvm_results_found(self):
        mock_session_repo = MagicMock(spec=DBRepository)
        mock_vuln_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['gvm_scan_sessions'] = mock_session_repo
        self.db_manager._repositories['gvm_vulnerabilities'] = mock_vuln_repo

        mock_session_repo.find_one.return_value = {
            'id': 1, 'task_id': 'task123', 'timestamp': '2025-04-28 10:00:00',
            'total_vulnerabilities': 2, 'critical_count': 1, 'high_count': 0, 'medium_count': 1, 'low_count': 0
        }
        mock_vuln_repo.find.return_value = [
            {'id': 1, 'session_id': 1, 'vuln_id': 'vuln1', 'name': 'Critical', 'host': 'hostA', 'port': '80', 'severity': 'Critical', 'severity_value': 9.0, 'description': '...', 'cvss_base': '...', 'timestamp': '2025-04-28 10:01:00'},
            {'id': 2, 'session_id': 1, 'vuln_id': 'vuln2', 'name': 'Medium', 'host': 'hostB', 'port': '443', 'severity': 'Medium', 'severity_value': 5.0, 'description': '...', 'cvss_base': '...', 'timestamp': '2025-04-28 10:02:00'}
        ]

        results = self.db_manager.get_gvm_results('task123')
        self.assertEqual(results, {
            'results': [
                {'id': 'vuln1', 'name': 'Critical', 'host': 'hostA', 'port': '80', 'severity': 'Critical', 'severity_value': 9.0, 'description': '...', 'cvss_base': '...', 'timestamp': '2025-04-28 10:01:00'},
                {'id': 'vuln2', 'name': 'Medium', 'host': 'hostB', 'port': '443', 'severity': 'Medium', 'severity_value': 5.0, 'description': '...', 'cvss_base': '...', 'timestamp': '2025-04-28 10:02:00'}
            ],
            'summary': {'Critical': 1, 'High': 0, 'Medium': 1, 'Low': 0},
            'total': 2
        })
        mock_session_repo.find_one.assert_called_once_with({'id': 'task123'})
        mock_vuln_repo.find.assert_called_once_with({'session_id': 1})

    def test_get_gvm_results_not_found(self):
        mock_session_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['gvm_scan_sessions'] = mock_session_repo
        mock_session_repo.find_one.return_value = None
        results = self.db_manager.get_gvm_results('nonexistent_task')
        self.assertIsNone(results)
        mock_session_repo.find_one.assert_called_once_with({'id': 'nonexistent_task'})

    def test_get_user_by_username_found(self):
        mock_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['users'] = mock_repo
        mock_repo.find_one.return_value = {'id': 1, 'username': 'testuser', 'password_hash': 'hashed', 'email': 'test@user.com', 'role': 'admin'}
        user = self.db_manager.get_user_by_username('testuser')
        self.assertEqual(user, {'id': 1, 'username': 'testuser', 'password_hash': 'hashed', 'email': 'test@user.com', 'role': 'admin'})
        mock_repo.find_one.assert_called_once_with(username='testuser')

    def test_get_user_by_username_not_found(self):
        mock_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['users'] = mock_repo
        mock_repo.find_one.return_value = None
        user = self.db_manager.get_user_by_username('nonexistent')
        self.assertIsNone(user)
        mock_repo.find_one.assert_called_once_with(username='nonexistent')

    def test_get_user_by_id_found(self):
        mock_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['users'] = mock_repo
        mock_repo.find_one.return_value = {'id': 2, 'username': 'anotheruser', 'password_hash': 'hashed2', 'email': 'another@user.com', 'role': 'user'}
        user = self.db_manager.get_user_by_id(2)
        self.assertEqual(user, {'id': 2, 'username': 'anotheruser', 'password_hash': 'hashed2', 'email': 'another@user.com', 'role': 'user'})
        mock_repo.find_one.assert_called_once_with(id=2)

    def test_get_user_by_id_not_found(self):
        mock_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['users'] = mock_repo
        mock_repo.find_one.return_value = None
        user = self.db_manager.get_user_by_id(99)
        self.assertIsNone(user)
        mock_repo.find_one.assert_called_once_with(id=99)

    def test_create_user_success(self):
        mock_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['users'] = mock_repo
        mock_repo.insert.return_value = 3
        result = self.db_manager.create_user('newuser', 'password123', 'new@user.com', 'editor')
        self.assertEqual(result, {"success": True, "user_id": 3})
        mock_repo.insert.assert_called_once()
        inserted_data = mock_repo.insert.call_args[0][0]
        self.assertEqual(inserted_data['username'], 'newuser')
        self.assertTrue(inserted_data['password_hash'].startswith('pbkdf2:'))
        self.assertEqual(inserted_data['email'], 'new@user.com')
        self.assertEqual(inserted_data['role'], 'editor')

    def test_create_user_failure(self):
        mock_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['users'] = mock_repo
        mock_repo.insert.side_effect = Exception("Database error")
        result = self.db_manager.create_user('failuser', 'securepass', 'fail@user.com')
        self.assertEqual(result, {"success": False, "error": "Database error"})
        mock_repo.insert.assert_called_once()

    def test_update_last_login(self):
        mock_repo = MagicMock(spec=DBRepository)
        self.db_manager._repositories['users'] = mock_repo
        mock_repo.update.return_value = 1
        user_id = 5
        result = self.db_manager.update_last_login(user_id)
        self.assertEqual(result, 1)
        mock_repo.update.assert_called_once()
        call_args = mock_repo.update.call_args[0]
        self.assertEqual(call_args[0], user_id)
        self.assertIn('last_login', call_args[1])
        self.assertIsInstance(datetime.datetime.strptime(call_args[1]['last_login'], "%Y-%m-%d %H:%M:%S"), datetime.datetime)

if __name__ == '__main__':
    unittest.main()