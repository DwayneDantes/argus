# test_notification.py

from plyer import notification
import time

print("Attempting to send a test notification...")

try:
    notification.notify(
        title='Argus Test Notification',
        message=f'If you can see this, the plyer library is working correctly on your system.\nTimestamp: {time.strftime("%H:%M:%S")}',
        app_name='Argus Test',
        timeout=15  # Notification will stay for 15 seconds
    )
    print("Notification request sent successfully to the OS.")
    print("Check your system's notification area.")

except Exception as e:
    print("\n--- ERROR ---")
    print(f"Failed to send notification. Error: {e}")
    print("\nThis likely means a required backend library is missing on your operating system.")
    print("If you are on Linux, try running: sudo apt-get install libnotify-bin")