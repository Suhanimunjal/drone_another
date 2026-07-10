import os
os.environ["INSTANCE_TYPE"] = "public"
os.environ["PORT"] = "5000"
from backend_server import app, UPLOAD_DIR
print(f"Public instance starting on http://0.0.0.0:5000")
app.run(host="0.0.0.0", port=5000, debug=True, threaded=True, use_reloader=False)
