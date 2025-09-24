# KISS Inventory App (Updated)

A **Streamlit-based inventory management system** with role-based access, multilingual UI, and safety-first features.  
This fork (“kissupdated”) upgrades authentication and restores workflows for better security and reliability.

---

## 🚀 Features

- **Secure login**
  - Uses `bcrypt` for password hashing (legacy SHA-256 hashes auto-upgrade on login).
- **Role-based menus**
  - **Admin**: manage users, view logs, restore/backup DB.
  - **Hub Manager**: manage hub inventory, shipments, counts.
  - **Retail**: retail-level operations.
  - **Supplier**: shipments & supplier functions.
- **Safe restore**
  - CSV restore now shows a **preview**, validates schema, and **creates a timestamped DB backup** before applying.
- **Admin CLI** (`admin_tools.py`)
  - Manage users from the command line with full audit logging.
- **Audit logging**
  - Admin actions (list, delete, reset) are recorded in the `logs` table.
- **Multilingual support**
  - English / 中文 toggle in UI.

---

## 🛠️ Setup

### Requirements
- Python 3.9+
- Streamlit, Pandas, Bcrypt

### Installation

```bash
# Clone the repo
git clone https://github.com/bigsmooth/kissupdated.git
cd kissupdated

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # macOS/Linux
# .venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py
