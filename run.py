import os

from app import app, log_mongodb_connection


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5001"))
    log_mongodb_connection()
    app.run(host=host, port=port, debug=True)
