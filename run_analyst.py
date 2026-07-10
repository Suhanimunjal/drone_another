import os
os.environ["INSTANCE_TYPE"] = "analyst"
os.environ["PORT"] = "5002"
from backend_server import app, UPLOAD_DIR
print(f"Analyst instance starting on http://0.0.0.0:5002")
app.run(host="0.0.0.0", port=5002, debug=True, threaded=True, use_reloader=False)
