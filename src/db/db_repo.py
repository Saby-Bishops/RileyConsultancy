from contextlib import contextmanager

class DBRepository:
    """
    A generic repository class for database operations on a specific table.
    Combines Repository Pattern with Query Builder approach.
    """
    
    def __init__(self, connector, table_name):
        """
        Initialize repository for a specific table
        
        Args:
            conn_settings: Database connection parameters dict
            table_name: Name of the table this repository manages
        """
        self.connector = connector
        self.table_name = table_name
    
    @contextmanager
    def get_cursor(self):
        """
        Proxy to pooled cursor from DBConnector
        """
        with self.connector.cursor() as cursor:
            yield cursor
    
    def save(self, data, unique_fields=None):
        """
        Save data to the database - automatically determines insert or update
        
        Args:
            data: Dict containing column-value pairs
            unique_fields: List of fields to check for existing records (for update)
            
        Returns:
            Record ID if insert, number of affected rows if update
        """
        if not data:
            raise ValueError("No data provided to save")
            
        # If unique fields provided, check if record exists
        if unique_fields:
            conditions = {field: data.get(field) for field in unique_fields if field in data}
            if conditions:
                existing = self.find_one(**conditions)
                if existing:
                    # Record exists, do update
                    update_data = {k: v for k, v in data.items() if k not in unique_fields}
                    return self.update(update_data, **conditions)
        
        # No unique fields or record doesn't exist, do insert
        return self.insert(data)
            
    def insert(self, data):
        """
        Insert a new record
        
        Args:
            data: Dict containing column-value pairs
            
        Returns:
            ID of the inserted record
        """
        if not data:
            raise ValueError("No data provided to insert")
            
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['%s'] * len(data))
        values = tuple(data.values())
        
        with self.get_cursor() as cursor:
            query = f"INSERT INTO {self.table_name} ({columns}) VALUES ({placeholders})"
            cursor.execute(query, values)
            return cursor.lastrowid
    
    def update(self, data, **conditions):
        """
        Update records matching conditions
        
        Args:
            data: Dict containing column-value pairs to update
            **conditions: Field=value pairs for WHERE clause
            
        Returns:
            Number of rows affected
        """
        if not data:
            raise ValueError("No data provided to update")
        if not conditions:
            raise ValueError("No conditions provided for update - this would update all records")
            
        set_clause = ', '.join([f"{key} = %s" for key in data.keys()])
        where_clause = ' AND '.join([f"{key} = %s" for key in conditions.keys()])
        
        # Values for SET clause followed by values for WHERE clause
        values = tuple(list(data.values()) + list(conditions.values()))
        
        with self.get_cursor() as cursor:
            query = f"UPDATE {self.table_name} SET {set_clause} WHERE {where_clause}"
            cursor.execute(query, values)
            return cursor.rowcount
    
    def delete(self, **conditions):
        """
        Delete records matching conditions
        
        Args:
            **conditions: Field=value pairs for WHERE clause
            
        Returns:
            Number of rows deleted
        """
        if not conditions:
            raise ValueError("No conditions provided for delete - this would delete all records")
            
        where_clause = ' AND '.join([f"{key} = %s" for key in conditions.keys()])
        values = tuple(conditions.values())
        
        with self.get_cursor() as cursor:
            query = f"DELETE FROM {self.table_name} WHERE {where_clause}"
            cursor.execute(query, values)
            return cursor.rowcount
    
    def find(self, limit=None, offset=None, order_by=None, **conditions):
        """
        Find records matching conditions
        
        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            order_by: String or tuple for ORDER BY clause
            **conditions: Field=value pairs for WHERE clause
            
        Returns:
            List of matching records as dicts
        """
        where_clause = ' AND '.join([f"{key} = %s" for key in conditions.keys()]) if conditions else '1=1'
        values = tuple(conditions.values()) if conditions else ()
        
        query = f"SELECT * FROM {self.table_name} WHERE {where_clause}"
        
        if order_by:
            if isinstance(order_by, tuple):
                field, direction = order_by
                query += f" ORDER BY {field} {direction}"
            else:
                query += f" ORDER BY {order_by}"
                
        if limit:
            query += f" LIMIT {int(limit)}"
            
        if offset:
            query += f" OFFSET {int(offset)}"
        
        with self.get_cursor() as cursor:
            cursor.execute(query, values)
            return cursor.fetchall()
    
    def find_one(self, **conditions):
        """
        Find a single record matching conditions
        
        Args:
            **conditions: Field=value pairs for WHERE clause
            
        Returns:
            Single record as dict or None if not found
        """
        results = self.find(limit=1, **conditions)
        return results[0] if results else None
    
    def count(self, **conditions):
        """
        Count records matching conditions
        
        Args:
            **conditions: Field=value pairs for WHERE clause
            
        Returns:
            Number of matching records
        """
        where_clause = ' AND '.join([f"{key} = %s" for key in conditions.keys()]) if conditions else '1=1'
        values = tuple(conditions.values()) if conditions else ()
        
        with self.get_cursor() as cursor:
            query = f"SELECT COUNT(*) as count FROM {self.table_name} WHERE {where_clause}"
            cursor.execute(query, values)
            result = cursor.fetchone()
            return result['count'] if result else 0
    
    def execute_raw(self, query, params=None):
        """
        Execute a raw SQL query
        
        Args:
            query: SQL query string
            params: Parameters for the query
            
        Returns:
            Query results or affected row count
        """
        with self.get_cursor() as cursor:
            cursor.execute(query, params or ())
            if query.strip().upper().startswith(('SELECT', 'SHOW')):
                return cursor.fetchall()
            return cursor.rowcount