import asyncio
import aiohttp
import random
from datetime import datetime, timezone
import json

# Event types and severities for testing
EVENT_TYPES = [
    "login_attempt", "file_access", "network_connection", 
    "process_start", "system_call", "registry_change"
]

SEVERITIES = ["low", "medium", "high", "critical"]

SOURCES = [
    "windows_security", "network_monitor", "file_system",
    "process_monitor", "system_monitor", "registry_monitor"
]

async def generate_event():
    """Generate a random test event"""
    event_type = random.choice(EVENT_TYPES)
    severity = random.choice(SEVERITIES)
    source = random.choice(SOURCES)
    
    # Adjust severity distribution for testing
    # 30% chance of high/critical severity
    if random.random() < 0.3:
        severity = random.choice(["high", "critical"])
    else:
        severity = random.choice(["low", "medium"])
    
    event = {
        "source": source,
        "type": event_type,
        "severity": severity,
        "data": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": f"Test {event_type} event from {source}",
            "metadata": {
                "pid": random.randint(1000, 9999),
                "user": f"user_{random.randint(1, 10)}",
                "ip": f"192.168.1.{random.randint(2, 254)}"
            }
        }
    }
    
    return event

async def main():
    """Main event generation loop"""
    base_url = "http://127.0.0.1"
    port = 8080
    max_port = 8090  # Maximum port to try
    
    # Find the correct port
    async with aiohttp.ClientSession() as session:
        while port <= max_port:
            try:
                url = f"{base_url}:{port}"
                async with session.get(url) as response:
                    if response.status == 200:
                        break
            except aiohttp.ClientError:
                port += 1
        else:
            print(f"Could not find SIEM server on ports {8080}-{max_port}")
            return

    print(f"Found SIEM server at {url}")
    
    # Start generating events
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                # Generate 1-5 events
                num_events = random.randint(1, 5)
                for _ in range(num_events):
                    event = await generate_event()
                    
                    # Send event to SIEM
                    async with session.post(
                        f"{url}/api/events",
                        json=event
                    ) as response:
                        if response.status != 200:
                            print(f"Failed to send event: {await response.text()}")
                        else:
                            print(f"Sent {event['type']} event with {event['severity']} severity")
                
                # Random delay between 1-5 seconds
                await asyncio.sleep(random.uniform(1, 5))
                
            except Exception as e:
                print(f"Error generating events: {str(e)}")
                await asyncio.sleep(5)  # Wait before retrying

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopping event generator...")
    except Exception as e:
        print(f"Error: {str(e)}")
