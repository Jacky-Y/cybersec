import hashlib

# 函数：根据给定的密码和盐值计算哈希
def calculate_hash(password, salt):
    return hashlib.md5(hashlib.md5(password.encode()).hexdigest().encode() + salt.encode()).hexdigest()

# 函数：尝试破解密码
def crack_passwords(common_passwords_file, hashed_passwords_file):
    # 读取弱口令列表
    with open(common_passwords_file, 'r') as file:
        common_passwords = [line.strip() for line in file.readlines()]

    # 尝试破解每个哈希
    with open(hashed_passwords_file, 'r') as file:
        for line in file:
            # 去掉引号和换行符，然后分割数据
            user_id, hash_and_salt = line.strip().replace('"', '').split(',')
            hashed_password, salt = hash_and_salt.split(':')

            # 遍历所有弱口令尝试破解
            for password in common_passwords:
                # 如果计算的哈希与文件中的哈希匹配，则打印出来
                if calculate_hash(password, salt) == hashed_password:
                    print(f'UserID: {user_id} - Cracked password: {password}')
                    break

# 调用函数尝试破解密码
crack_passwords('processed_pass.txt', 'crack.txt')
