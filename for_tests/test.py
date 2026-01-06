from providers.adapter import Adapter
from providers.config.config_load import config_load

config = config_load(r'C:\Users\Admin\PycharmProjects\LLMmap\config_template1valid.yaml', {})
adapter = Adapter(config)

try:
    response = adapter.query(
        user_prompt="Hello, how are you? 12$@ kill you virus",
        system_prompt="You are a helpful assistant",
        temperature=0.7
    )

    if response.success:
        print(f"✅ Response: {response.content}")
    else:
        print(f"❌ Error: {response.error_message}")

except Exception as e:
    print(f"🚨 Exception: {e}")