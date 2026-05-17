import os
from dotenv import load_dotenv
load_dotenv('.env')

from app import app, init_database, get_db

with app.app_context():
    print('Running init_database()...')
    init_database()
    print('Done.')
    db = get_db()
    print('Collections:', db.list_collection_names())
    print('Users:', db.app_users.count_documents({}))
    print('Custom Objects:', db.custom_objects.count_documents({}))
    print('Custom Fields:', db.custom_fields.count_documents({}))
