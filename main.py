from storage.db import init_db
from frontend.app import run_app

def main():
    init_db()
    run_app()

if __name__ == "__main__":
    main()