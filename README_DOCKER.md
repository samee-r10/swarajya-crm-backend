# 🐳 Backend Docker Quickstart

You can build and run the backend and Redis directly from inside the `swarajya-crm-backend` directory.

### Quick Start:
```bash
# 1. Start Backend and Redis containers
docker compose up --build -d

# 2. Check health and logs
docker compose ps
docker compose logs -f backend

# 3. Stop containers
docker compose down
```

### Services Started:
* **`backend`**: Runs Flask on `http://localhost:5001` (with live code syncing).
* **`redis`**: Runs Redis 7 on `localhost:6379`.

