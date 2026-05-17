import os

from app import app


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    app.run(debug=True, port=port)

