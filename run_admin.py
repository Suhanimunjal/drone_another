import os
os.environ["INSTANCE_TYPE"] = "analyst"
os.environ["PORT"] = "5001"
from backend_server import app, UPLOAD_DIR
print(f"Admin instance starting on http://0.0.0.0:5001")
app.run(host="0.0.0.0", port=5001, debug=True, threaded=True, use_reloader=False)
