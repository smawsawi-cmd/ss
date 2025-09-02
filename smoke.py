import requests

# Replace this with your webhook URL
WEBHOOK_URL = "https://discord.com/api/webhooks/1412339726417006592/vhnSS2XVIYTAtaNMjO2jCp_Plg4fixjjKwzFy6J1wknomLMG2fZl9uHw42lH1lJyld1w"

def send_message(content: str):
    data = {
        "content": content
    }
    response = requests.post(WEBHOOK_URL, json=data)
    
    if response.status_code == 204:
        print("Message sent successfully!")
    else:
        print(f"Failed to send message: {response.status_code}")
        print(response.text)

# Example usage
send_message("Hello from my Python test script! 🚀")
