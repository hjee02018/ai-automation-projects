from config import DATABASE_CONFIG
import cx_Oracle


def get_db_connection():
    try:
        connection = cx_Oracle.connect(
            DATABASE_CONFIG['user'],
            DATABASE_CONFIG['password'],
            DATABASE_CONFIG['dsn']
        )
        return connection
    except cx_Oracle.DatabaseError as e:
        error, = e.args
        print(f"Error connecting to Oracle: {error.message}")
        return None
    
def execute_query(query, params=None):
    """ 데이터를 조회하는 일반적인 SQL 쿼리 함수 """
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute(query, params or {})
            result = cursor.fetchall()
            cursor.close()
            connection.close()
            return result
        except cx_Oracle.DatabaseError as e:
            error, = e.args
            print(f"Error executing query: {error.message}")
            return None
    return None
