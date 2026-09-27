"""Start TechLab on loopback only."""

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local TechLab catalog")
    parser.add_argument("--port", type=int, default=8010)
    args = parser.parse_args()
    uvicorn.run("app.main:create_app", factory=True, host="127.0.0.1", port=args.port,
                access_log=False, server_header=False)


if __name__ == "__main__":
    main()
