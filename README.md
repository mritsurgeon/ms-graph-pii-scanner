# Microsoft Graph API PII Scanner

This script scans Microsoft 365 services (OneDrive, SharePoint, Teams, Emails) for Personally Identifiable Information (PII) using the Microsoft Graph API and GLiNER for PII detection.

## Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/ms-graph-pii-scanner.git
   cd ms-graph-pii-scanner
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**:
   - Create a `.env` file in the root directory:
     ```plaintext
     CLIENT_ID=your_client_id
     CLIENT_SECRET=your_client_secret
     TENANT_ID=your_tenant_id
     ```

4. **Run the script**:
   ```bash
   python ms_graph_api.py
   ```

## Features
- Scan OneDrive/SharePoint files for PII.
- Scan Emails for PII.
- Scan Teams messages for PII.
- Save scan results to a SQLite database.
- Visualize detected PII types.

## Database
The script creates a SQLite database (`pii_scan_history.db`) to store scan results. You can query the database to view historical PII data.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details. 