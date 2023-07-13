import json
import base64

def decode_body(b64_body):
    decoded_body = base64.b64decode(b64_body).decode('utf-8')
    return decoded_body

def main():
    with open('output_post_requests.json', 'r') as f:
        data = json.load(f)

    post_bodies = []
    seen_parameters = set()

    for item in data:
        if item.get('Method') == 'POST':
            decoded_body = decode_body(item['b64_body'])
            if decoded_body not in seen_parameters:
                seen_parameters.add(decoded_body)
                post_bodies.append({
                    'URL': item['URL'],
                    'Body': decoded_body
                })

    for post_body in post_bodies:
        print(f"URL: {post_body['URL']}")
        print(f"Body: {post_body['Body']}")
        print("----------------------")

if __name__ == "__main__":
    main()
