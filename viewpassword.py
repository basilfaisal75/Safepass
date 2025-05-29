import tkinter as tk
from encryption_utils import decrypt_password

def open_view_passwords(db, uid, mpw):
    """
    opens a window listing all passwords saved for the given user
    each password is decrypted on the-fly using the master password
    """
    # create a new top level window for the password viewer
    w = tk.Toplevel()
    w.title("View Saved Passwords")
    w.geometry("400x400")

    # header label
    tk.Label(
        w,
        text="Your Saved Passwords:",
        font=("Helvetica", 12, "bold")
    ).pack(pady=10)

    # fetch stored records: each record is (encrypted_blob, strength)
    # get_passwords must accept the master password to perform decryption
    recs = db.get_passwords(uid, mpw)

    # if no passwords exist, let the user know
    if not recs:
        tk.Label(w, text="No passwords found.").pack(pady=10)
    else:
        # otherwise, create a scrollable listbox to display them
        lb = tk.Listbox(w, width=50)
        lb.pack(pady=10, fill=tk.BOTH, expand=True)

        for encrypted_blob, strength in recs:
            try:
                # decrypt each blob in-memory
                plain_pw = decrypt_password(encrypted_blob, mpw)
            except Exception:
                # if decryption fails, show an error placeholder
                plain_pw = "[Decryption Failed]"

            # insert a line: "decrypted_password  (strength)"
            lb.insert(tk.END, f"{plain_pw}  ({strength})")

    # dtart the event loop for this window
    w.mainloop()
