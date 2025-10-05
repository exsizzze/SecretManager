import argparse
from backend.manager import SecretManager

def main():
    mgr = SecretManager()
    if not mgr.initialized():
        print("No master password found. Create one.")
        mgr.create_master()
    else:
        mgr.ask_master()

    parser = argparse.ArgumentParser(description="SecretManager CLI (WIP)")
    parser.add_argument("--list", action="store_true", help="List secrets")
    parser.add_argument("--view", type=int, help="View secret by id")
    parser.add_argument("--genpass", type=int, help="Generate password length N")
    parser.add_argument("--add", nargs=2, metavar=("NAME","PASSWORD"), help="Add simple secret NAME with PASSWORD")
    args = parser.parse_args()

    if args.list:
        for sid, name, created in mgr.list():
            print(f"{sid}\t{name}\t{created}")
    if args.view:
        try:
            d = mgr.view(args.view)
            for k,v in d.items():
                print(f"{k}: {v}")
        except Exception as e:
            print("Error:", e)
    if args.genpass:
        print(mgr.generate_password(args.genpass))
    if args.add:
        name, password = args.add
        data = {"password": password}
        sid = mgr.add(name, data)
        print("Added id", sid)

if __name__ == "__main__":
    main()