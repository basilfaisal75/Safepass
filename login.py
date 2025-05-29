import tkinter as tk
from tkinter import messagebox


from db_manager import DatabaseManager

# import functions to launch the password generator and viewer windows
from password_generator import open_password_generator
from viewpassword import open_view_passwords

class LoginUI:

    def __init__(self, master):
        self.master = master
        master.title("SafePass Login")
        master.geometry("300x250")

        # opens/creates safepass_app.db
        self.db = DatabaseManager()

        # username label and text entry
        tk.Label(master, text="Username").pack(pady=5)
        self.user = tk.Entry(master)
        self.user.pack(pady=5)

        # password label and text entry
        tk.Label(master, text="Password").pack(pady=5)
        self.pw = tk.Entry(master, show="*")
        self.pw.pack(pady=5)

        # Login button triggers handle_login()
        tk.Button(master, text="Login", command=self.handle_login).pack(pady=10)
        # Register button triggers handle_register()
        tk.Button(master, text="Register", command=self.handle_register).pack()

    def handle_login(self):

        # retrieve entered credentials, validate, then attempt to log in. . if validated open main menu

        username = self.user.get().strip()    # trim whitespace
        password = self.pw.get().strip()

        # ensure both fields are filled
        if not username or not password:
            messagebox.showerror("Error", "Please fill in both fields.")
            return

        # check credentials against the users table using bycrypt
        user_id = self.db.login_user(username, password)
        if user_id:
            messagebox.showinfo("Success", "Login successful!")
            # open the main menu, passing the db , user ID, and master password
            open_main_menu(self.db, user_id, password)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def handle_register(self):
        # retrieve entered credentials, validate, then attempt to register a new user account

        username = self.user.get().strip()
        password = self.pw.get().strip()

        # ensure both fields are filled
        if not username or not password:
            messagebox.showerror("Error", "Please fill in both fields.")
            return

        # attempt to insert new user
        if self.db.register_user(username, password):
            messagebox.showinfo("Success", "Account registered!")
        else:
            messagebox.showerror("Error", "Username already exists.")


class MainMenuUI:
    # after login main menu offering password generation, viewing, or logout
    def __init__(self, master, db, user_id, master_password):
        self.db = db
        self.user_id = user_id
        self.master_password = master_password

        master.title("SafePass Main Menu")
        master.geometry("300x200")

        # heading
        tk.Label(master, text="Main Menu", font=("Helvetica", 14, "bold")).pack(pady=10)

        # button to open the password generator
        # passes the database, user ID, and master password for aes encryption
        tk.Button(
            master,
            text="Generate Password",
            width=25,
            command=lambda: open_password_generator(self.db, self.user_id, self.master_password)
        ).pack(pady=5)

        # button to open the saved-password viewer
        # Passes same parameters for decryption
        tk.Button(
            master,
            text="View Saved Passwords",
            width=25,
            command=lambda: open_view_passwords(self.db, self.user_id, self.master_password)
        ).pack(pady=5)

        # logout button closes this window
        tk.Button(master, text="Logout", width=25, command=master.destroy).pack(pady=5)


def open_main_menu(db, user_id, master_password):

    # helper function to launch the main menu in a new top level window
    # keeps the login window open in the background.

    menu_win = tk.Toplevel()  # new window instance
    MainMenuUI(menu_win, db, user_id, master_password)
    menu_win.mainloop()



if __name__ == "__main__":
    # create the root login window and start the event loop
    root = tk.Tk()
    LoginUI(root)
    root.mainloop()
