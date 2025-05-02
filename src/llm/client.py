import requests
import json

class LLMClient:
    """Client for interacting with the LLM server."""
    
    def __init__(self, server_url):
        """Initialize the client with the server URL."""
        self.server_url = server_url
        # Make sure the URL ends with a slash
        if not self.server_url.endswith('/'):
            self.server_url += '/'
    
    def generate(self, prompt, max_length=100, temperature=0.7, top_p=0.9):
        """Generate text from the LLM using the provided prompt."""
        # Prepare the request data
        data = {
            'prompt': prompt,
            'max_length': max_length,
            'temperature': temperature,
            'top_p': top_p
        }
        
        try:
            # Send the request to the server
            response = requests.post(
                f"{self.server_url}generate",
                json=data,
                headers={'Content-Type': 'application/json'}
            )
            
            # Check if the request was successful
            if response.status_code == 200:
                return response.json()
            else:
                error_message = f"Error: {response.status_code}"
                try:
                    error_data = response.json()
                    if 'error' in error_data:
                        error_message += f" - {error_data['error']}"
                except:
                    error_message += f" - {response.text}"
                
                return {'error': error_message}
        
        except Exception as e:
            return {'error': f"Connection error: {str(e)}"}


# Example usage
if __name__ == "__main__":
    # Create a client instance
    client = LLMClient("YOUR_SERVER_URL_HERE")
    
    # Generate text
    prompt = "Once upon a time in a distant galaxy"
    result = client.generate(
        prompt=prompt,
        max_length=150,
        temperature=0.8
    )
    
    # Print the result
    if 'error' in result:
        print(f"Error: {result['error']}")
    else:
        print("Prompt:", result['prompt'])
        print("\nGenerated Text:", result['generated_text'])
        print("\nParameters:", json.dumps(result['parameters'], indent=2))