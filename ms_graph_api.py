import msal
import requests
from datetime import datetime, timedelta
from gliner import GLiNER
from termcolor import colored  # For color-coded output
import sqlite3
from tqdm import tqdm  # For progress bar
import matplotlib.pyplot as plt
import time
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Replace these with your Azure AD app registration details
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TENANT_ID = os.getenv("TENANT_ID")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

# MS Graph API endpoint and scope
GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"
SCOPE = ["https://graph.microsoft.com/.default"]

# Initialize GLiNER for PII detection
PII_LABELS = [
    "person", "email", "phone number", "address", "Social Security Number",
    "credit card number", "passport number", "driver licence", "company"
]
gliner_model = GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")

# Pre-filtering rules
ALLOWED_FILE_TYPES = [".docx", ".pdf", ".txt"]  # Only scan these file types
MAX_FILE_SIZE_MB = 10  # Skip files larger than 10 MB
DATE_RANGE_DAYS = 30  # Only scan files created in the last 30 days

def get_access_token(client_id, client_secret, authority, scope):
    """Obtain an access token using MSAL."""
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret
    )
    result = app.acquire_token_for_client(scopes=scope)
    if "access_token" in result:
        return result["access_token"]
    else:
        raise Exception("Failed to obtain access token")

def make_graph_call(url, pagination=True, headers=None):
    """Make a call to the Microsoft Graph API."""
    token = get_access_token(CLIENT_ID, CLIENT_SECRET, AUTHORITY, SCOPE)
    headers = headers or {}
    headers.update({
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    })
    if pagination:
        all_data = []
        while url:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                all_data.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
            else:
                raise Exception(f"API call failed: {response.status_code} - {response.text}")
        return all_data
    else:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()  # Return the single object
        else:
            raise Exception(f"API call failed: {response.status_code} - {response.text}")

def detect_pii(text):
    """Detect PII in text using GLiNER."""
    entities = gliner_model.predict_entities(text, PII_LABELS)
    return entities

def pre_filter_file(file):
    """Pre-filter files based on rules."""
    file_name = file.get("name", "").lower()
    file_size = file.get("size", 0) / (1024 * 1024)  # Convert bytes to MB
    created_date = datetime.strptime(file.get("createdDateTime"), "%Y-%m-%dT%H:%M:%SZ")

    # Check file type
    if not any(file_name.endswith(ext) for ext in ALLOWED_FILE_TYPES):
        return False

    # Check file size
    if file_size > MAX_FILE_SIZE_MB:
        return False

    # Check date range
    if datetime.utcnow() - created_date > timedelta(days=DATE_RANGE_DAYS):
        return False

    return True

def scan_files(files):
    """Scan files for PII based on pre-filtering rules."""
    results = []
    for file in files:
        if pre_filter_file(file):
            file_name = file.get("name")
            file_id = file.get("id")
            print(colored(f"Scanning file: {file_name} (ID: {file_id})", "cyan"))

            # Download file content (example for OneDrive/SharePoint)
            download_url = file.get("@microsoft.graph.downloadUrl")
            if download_url:
                response = requests.get(download_url)
                if response.status_code == 200:
                    text = response.text
                    pii_entities = detect_pii(text)
                    if pii_entities:
                        results.append({
                            "file_name": file_name,
                            "file_id": file_id,
                            "pii_entities": pii_entities
                        })
                        print(colored(f"Found PII in {file_name}: {pii_entities}", "red"))
    return results

def check_onedrive_access(user_id):
    """Check if the user has a OneDrive."""
    try:
        drives_url = f"{GRAPH_ENDPOINT}/users/{user_id}/drives"
        drives = make_graph_call(drives_url)
        return len(drives) > 0
    except Exception as e:
        print(colored(f"Failed to check OneDrive access for user {user_id}: {e}", "red"))
        return False

def scan_emails(user_id):
    """Scan emails for PII."""
    try:
        # Fetch emails with pagination
        emails_url = f"{GRAPH_ENDPOINT}/users/{user_id}/messages"
        emails = make_graph_call(emails_url, pagination=True)
        results = []
        total_emails = len(emails)
        print(colored(f"Found {total_emails} emails for user {user_id}.", "blue"))

        for email in tqdm(emails, desc="Scanning Emails", unit="email"):
            email_id = email.get("id")
            if is_item_scanned(user_id, "email", email_id):
                print(colored(f"Skipping already scanned email (ID: {email_id})", "yellow"))
                continue

            if not pre_filter_email(email):
                continue  # Skip emails that don't meet the criteria

            # Extract email body
            body = email.get("body", {}).get("content", "")
            subject = email.get("subject", "No Subject")

            # Detect PII in email body
            pii_entities = detect_pii(body)
            if pii_entities:
                results.append({
                    "email_id": email_id,
                    "subject": subject,
                    "pii_entities": pii_entities
                })
                print(colored(f"Found PII in email {subject}: {pii_entities}", "red"))
            
            # Save result to database (even if no PII is found)
            save_scan_result(user_id, "email", email_id, pii_entities if pii_entities else "[]")
        return results
    except Exception as e:
        print(colored(f"Failed to scan emails for user {user_id}: {e}", "red"))
        return []

def pre_filter_email(email):
    """Pre-filter emails based on rules."""
    return True  # Disable pre-filtering for now

def scan_teams_messages(user_id):
    """Scan Teams messages for PII."""
    try:
        # Fetch chats with pagination
        chats_url = f"{GRAPH_ENDPOINT}/users/{user_id}/chats"
        chats = make_graph_call(chats_url, pagination=True)
        results = []
        total_chats = len(chats)
        print(colored(f"Found {total_chats} chats for user {user_id}.", "blue"))

        # Track total messages across all chats
        total_messages = 0
        for chat in tqdm(chats, desc="Scanning Chats", unit="chat"):
            chat_id = chat.get("id")
            messages_url = f"{GRAPH_ENDPOINT}/users/{user_id}/chats/{chat_id}/messages"
            messages = make_graph_call(messages_url, pagination=True)
            total_messages += len(messages)

        # Reset progress bar for messages
        print(colored(f"Found {total_messages} messages across all chats for user {user_id}.", "blue"))
        for chat in tqdm(chats, desc="Scanning Chats", unit="chat"):
            chat_id = chat.get("id")
            messages_url = f"{GRAPH_ENDPOINT}/users/{user_id}/chats/{chat_id}/messages"
            messages = make_graph_call(messages_url, pagination=True)
            for message in tqdm(messages, desc="Scanning Messages", unit="message"):
                message_id = message.get("id")
                if is_item_scanned(user_id, "teams", message_id):
                    print(colored(f"Skipping already scanned Teams message (ID: {message_id})", "yellow"))
                    continue

                body = message.get("body", {}).get("content", "")
                sender_info = message.get("from")
                if sender_info is None:  # Skip messages with no sender
                    print(colored(f"Skipping message with no sender (ID: {message_id})", "yellow"))
                    continue

                sender_user = sender_info.get("user", {})
                sender = sender_user.get("displayName", "Unknown")

                # Debug: Print Teams message body
                print(colored(f"Teams Message (ID: {message_id}, Sender: {sender}):\n{body}\n", "green"))

                # Detect PII in message body
                pii_entities = detect_pii(body)
                if pii_entities:
                    results.append({
                        "chat_id": chat_id,
                        "message_id": message_id,
                        "sender": sender,
                        "pii_entities": pii_entities
                    })
                    print(colored(f"Found PII in Teams message {message_id}: {pii_entities}", "red"))
                
                # Save result to database (even if no PII is found)
                save_scan_result(user_id, "teams", message_id, pii_entities if pii_entities else "[]")
        return results
    except Exception as e:
        print(colored(f"Failed to scan Teams messages for user {user_id}: {e}", "red"))
        return []

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect("pii_scan_history.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            service_type TEXT,
            item_id TEXT,
            pii_entities TEXT,
            status TEXT DEFAULT 'scanned',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# Save scan results to the database
def save_scan_result(user_id, service_type, item_id, pii_entities):
    conn = sqlite3.connect("pii_scan_history.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_history (user_id, service_type, item_id, pii_entities)
        VALUES (?, ?, ?, ?)
    """, (user_id, service_type, item_id, str(pii_entities)))
    conn.commit()
    conn.close()

def visualize_pii_results():
    """Visualize PII results from the database."""
    conn = sqlite3.connect("pii_scan_history.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT pii_entities FROM scan_history
    """)
    results = cursor.fetchall()
    conn.close()

    # Count PII types
    pii_counts = {}
    for result in results:
        pii_entities = eval(result[0])  # Convert string back to list
        for entity in pii_entities:
            label = entity["label"]
            pii_counts[label] = pii_counts.get(label, 0) + 1

    # Plot the results
    if pii_counts:
        plt.bar(pii_counts.keys(), pii_counts.values())
        plt.xlabel("PII Type")
        plt.ylabel("Count")
        plt.title("Detected PII Types")
        plt.show()
    else:
        print(colored("No PII data found to visualize.", "yellow"))

def is_item_scanned(user_id, service_type, item_id):
    """Check if an item has already been scanned."""
    conn = sqlite3.connect("pii_scan_history.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id FROM scan_history
        WHERE user_id = ? AND service_type = ? AND item_id = ?
    """, (user_id, service_type, item_id))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def track_progress(users):
    """Track overall progress across all users."""
    start_time = time.time()
    total_users = len(users)
    processed_users = 0

    # Initialize global progress counters
    total_items = 0
    processed_items = 0

    for user in users:
        user_id = user["id"]
        user_name = user.get("displayName", "Unknown")
        print(colored(f"Scanning data for user: {user_name} (ID: {user_id})", "blue"))

        # Count total items for the user
        user_total_items = 0

        # Check OneDrive access
        try:
            if check_onedrive_access(user_id):
                files_url = f"{GRAPH_ENDPOINT}/users/{user_id}/drive/root/children"
                files = make_graph_call(files_url)
                user_total_items += len(files)
            else:
                print(colored(f"OneDrive not found for user {user_name}.", "yellow"))
        except Exception as e:
            print(colored(f"OneDrive not accessible for user {user_name}: {e}", "red"))

        # Count emails (skip if mailbox is inaccessible)
        try:
            emails_url = f"{GRAPH_ENDPOINT}/users/{user_id}/messages"
            emails = make_graph_call(emails_url, pagination=True)
            user_total_items += len(emails)
        except Exception as e:
            print(colored(f"Mailbox not accessible for user {user_name}: {e}", "red"))
            continue  # Skip this user

        # Count Teams messages
        try:
            chats_url = f"{GRAPH_ENDPOINT}/users/{user_id}/chats"
            chats = make_graph_call(chats_url, pagination=True)
            for chat in chats:
                chat_id = chat.get("id")
                messages_url = f"{GRAPH_ENDPOINT}/users/{user_id}/chats/{chat_id}/messages"
                messages = make_graph_call(messages_url, pagination=True)
                user_total_items += len(messages)
        except Exception as e:
            print(colored(f"Failed to fetch Teams messages for user {user_name}: {e}", "red"))

        # Update total items
        total_items += user_total_items
        print(colored(f"Found {user_total_items} items for user {user_name}.", "blue"))

    # Reset progress bar for items
    print(colored(f"Found {total_items} items across all users.", "blue"))
    with tqdm(total=total_items, desc="Overall Progress", unit="item") as pbar:
        for user in users:
            user_id = user["id"]
            user_name = user.get("displayName", "Unknown")

            # Scan OneDrive (skip if inaccessible)
            try:
                if check_onedrive_access(user_id):
                    files_url = f"{GRAPH_ENDPOINT}/users/{user_id}/drive/root/children"
                    files = make_graph_call(files_url)
                    for file in files:
                        if pre_filter_file(file):
                            file_name = file.get("name")
                            file_id = file.get("id")
                            print(colored(f"Scanning file: {file_name} (ID: {file_id})", "cyan"))

                            # Download file content
                            download_url = file.get("@microsoft.graph.downloadUrl")
                            if download_url:
                                response = requests.get(download_url)
                                if response.status_code == 200:
                                    text = response.text
                                    pii_entities = detect_pii(text)
                                    if pii_entities:
                                        print(colored(f"Found PII in {file_name}: {pii_entities}", "red"))
                            pbar.update(1)
                else:
                    print(colored(f"OneDrive not found for user {user_name}.", "yellow"))
            except Exception as e:
                print(colored(f"OneDrive not accessible for user {user_name}: {e}", "red"))

            # Scan Emails (skip if mailbox is inaccessible)
            try:
                emails_url = f"{GRAPH_ENDPOINT}/users/{user_id}/messages"
                emails = make_graph_call(emails_url, pagination=True)
                for email in emails:
                    email_id = email.get("id")
                    if is_item_scanned(user_id, "email", email_id):
                        print(colored(f"Skipping already scanned email (ID: {email_id})", "yellow"))
                        pbar.update(1)
                        continue

                    if not pre_filter_email(email):
                        pbar.update(1)
                        continue

                    body = email.get("body", {}).get("content", "")
                    subject = email.get("subject", "No Subject")

                    # Detect PII in email body
                    pii_entities = detect_pii(body)
                    if pii_entities:
                        print(colored(f"Found PII in email {subject}: {pii_entities}", "red"))
                    pbar.update(1)
            except Exception as e:
                print(colored(f"Mailbox not accessible for user {user_name}: {e}", "red"))
                continue  # Skip this user

            # Scan Teams Messages
            try:
                chats_url = f"{GRAPH_ENDPOINT}/users/{user_id}/chats"
                chats = make_graph_call(chats_url, pagination=True)
                for chat in chats:
                    chat_id = chat.get("id")
                    messages_url = f"{GRAPH_ENDPOINT}/users/{user_id}/chats/{chat_id}/messages"
                    messages = make_graph_call(messages_url, pagination=True)
                    for message in messages:
                        message_id = message.get("id")
                        if is_item_scanned(user_id, "teams", message_id):
                            print(colored(f"Skipping already scanned Teams message (ID: {message_id})", "yellow"))
                            pbar.update(1)
                            continue

                        body = message.get("body", {}).get("content", "")
                        sender_info = message.get("from")
                        if sender_info is None:  # Skip messages with no sender
                            print(colored(f"Skipping message with no sender (ID: {message_id})", "yellow"))
                            continue

                        sender_user = sender_info.get("user", {})
                        sender = sender_user.get("displayName", "Unknown")

                        # Detect PII in message body
                        pii_entities = detect_pii(body)
                        if pii_entities:
                            print(colored(f"Found PII in Teams message {message_id}: {pii_entities}", "red"))
                        pbar.update(1)
            except Exception as e:
                print(colored(f"Failed to fetch Teams messages for user {user_name}: {e}", "red"))

            # Update user progress
            processed_users += 1
            elapsed_time = time.time() - start_time
            avg_time_per_user = elapsed_time / processed_users
            estimated_time_left = avg_time_per_user * (total_users - processed_users)
            print(colored(f"Progress: {processed_users}/{total_users} users processed. Estimated time left: {estimated_time_left:.2f} seconds.", "cyan"))

    # Visualize results
    visualize_pii_results()

# Example: Query data from multiple services
if __name__ == "__main__":
    # Initialize database
    init_db()

    # Get the list of users
    users_url = f"{GRAPH_ENDPOINT}/users"
    users = make_graph_call(users_url)
    if users:
        track_progress(users)
    else:
        print(colored("No users found.", "red")) 