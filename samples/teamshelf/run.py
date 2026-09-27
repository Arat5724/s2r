import argparse
import os

import uvicorn

parser = argparse.ArgumentParser(description="Run the local TeamShelf demo")
parser.add_argument("--port", type=int, default=8010)
parser.add_argument("--profile", choices=["baseline", "hardened"], default="baseline")
parser.add_argument("--reports", action="store_true")
args = parser.parse_args()
os.environ["TEAMSHELF_PROFILE"] = args.profile
os.environ["TEAMSHELF_ENABLE_REPORTS"] = "1" if args.reports else "0"
uvicorn.run("app.main:create_app", factory=True, host="127.0.0.1", port=args.port,
            access_log=False, server_header=False)
