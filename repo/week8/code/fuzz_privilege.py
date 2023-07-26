import json
import requests
from requests.auth import HTTPBasicAuth

# 载入Swagger JSON文件
with open('swagger_edit.json') as f:
    data = json.load(f)

base_url = "http://127.0.0.1:7001"  # 你需要根据实际情况修改这个URL

# cookies = {
#     'JSESSIONID': 'WIOSLAnKr4AZPxPOrbR96R0D7KkvsFv2T4rL6bJagB7mimGYXLD5!1557517524'
# }

headers = {
    "X-Requested-By": "test",
}

username = "test2"
password = "12345678"

def format_url(url, version="latest", name="testing"):
    if '{version}' in url:
        url = url.replace('{version}', version)
    if '{name}' in url:
        url = url.replace('{name}', name)
    return url

http_methods = {'get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'}

with open('results3.txt', 'w') as f:
    # 遍历所有路径
    for path, path_data in data['paths'].items():
        url = base_url + path
        url = format_url(url)

        # 遍历路径下的所有方法（如get, post）
        for method, method_data in path_data.items():
            if method not in http_methods:
                continue  # 如果当前的键不是HTTP方法，那么就跳过

            if method == 'post':  # 当前请求方法为post时处理参数
                body = {}
                # for param_data in method_data.get('parameters', []):
                #     if param_data.get('in') == 'body':
                #         schema = param_data.get('schema', {}).get('properties', {})
                #         for param_name, param_info in schema.items():
                #             param_value = 'your_default_value'  # 提供一个默认值
                #             body[param_name] = param_value
                response = requests.post(url, json=body,headers=headers,auth=HTTPBasicAuth(username, password))
            else:
                response = requests.get(url,auth=HTTPBasicAuth(username, password))

            f.write(f"URL: {url}\nMethod: {method.upper()}\nResponse: {response.status_code}\n")
            f.write(f"Response status code: {response.text}\n\n")

            # # 打印请求结果
            # print(f"URL: {url}\nMethod: {method.upper()}\nResponse: {response.status_code}\n")
            # print(f"Response status code: {response.text}")






