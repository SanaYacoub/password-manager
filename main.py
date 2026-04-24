from passwordManager import passwordManager
def main():

    pm= passwordManager()

    print("""What do you want to do ?
        (1) Create a new key
        (2) Load an existing key
        (3) Create new database
        (4) Load existing database
        (5) Add a new password
        (6) Get a password
        (7) Show all passwords
        (8) Update a password
        (9) Delete a password
        (q) Quit
          """)
    done = False
    
    while not done:
        try:
            choice = input("Enter your choice: ")

            if choice == "1":
                path = input("Enter the key file path: ")
                pm.create_key(path)
            elif choice == "2":
                path = input("Enter the key file path: ")
                pm.load_key(path)
            elif choice == "3":
                path = input("Enter the database path: ")
                pm.create_database(path)
            elif choice == "4":
                path = input("Enter the database path: ")
                pm.load_database(path)
            elif choice == "5":
                site = input("Enter the site: ").strip().lower()
                pwd = input("Enter the password: ")
                pm.add_password(site, pwd)
            elif choice == "6":
                site = input("What site do you want: ")
                print(f"Password for {site} is {pm.get_password(site)}")
            elif choice == "7":
                pm.show_all_passwords()
            elif choice == "8":
                site = input("Enter the site to update: ").strip().lower()
                new_pwd = input("Enter the new password: ")
                pm.update_password(site, new_pwd)
                print("[INFO] Password updated successfully")
            elif choice == "9":
                site = input("Enter the site to delete: ").strip().lower()
                confirm = input(f"Are you sure you want to delete '{site}'? (y/n): ").strip().lower()

                if confirm == "y":
                    pm.delete_password(site)
                    print("[INFO] Password deleted successfully")
                else:
                    print("[INFO] Deletion cancelled")
            elif choice == "q":
                done = True
                print("Bye")
            else:
                print("Invalid choice!")   

        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")


        

if __name__ == "__main__":
    main() 