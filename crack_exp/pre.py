def process_password_file(input_file, output_file):
    with open(input_file, 'r') as file:
        lines = file.readlines()
    
    processed_lines = [line.split()[0] + '\n' for line in lines if line.strip()]

    with open(output_file, 'w') as file:
        file.writelines(processed_lines)

# 使用这个函数
process_password_file('pass.txt', 'processed_pass.txt')
