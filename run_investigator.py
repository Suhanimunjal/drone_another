import os
os.environ["INSTANCE_TYPE"] = "investigator"
os.environ["PORT"] = "5003"
from backend_server import app, UPLOAD_DIR
print(f"Investigator instance starting on http://0.0.0.0:5003")
app.run(host="0.0.0.0", port=5003, debug=True, threaded=True, use_reloader=False)
