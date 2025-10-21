

class Config:
    """ Flask 애플리케이션의 설정 클래스 """

    ORACLE_USER = 'dbadmin'
    ORACLE_PASSWORD = 'HyundaiSol2023!'
    ORACLE_DSN = 'OHMXDB'

DATABASE_CONFIG = {
    'user': Config.ORACLE_USER,
    'password': Config.ORACLE_PASSWORD,
    'dsn': Config.ORACLE_DSN
}