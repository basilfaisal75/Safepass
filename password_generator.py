import tkinter as tk
from tkinter import messagebox
import secrets, string
from random import shuffle

# We need our encryption helper to lock down the password before saving
from encryption_utils import encrypt_password


class PasswordGenerator:

    def generate_password(self, answers):
        # stitch together pieces of each answer
        # first 2 chars of Q1, last 2 of Q2, underscore,
        # first 3 of Q3, last 2 of Q4
        raw = f"{answers[0][:2]}{answers[1][-2:]}_" \
              f"{answers[2][:3]}{answers[3][-2:]}{answers[4]}"

        # if it's too short (<10), pad with random letters
        while len(raw) < 10:
            raw += secrets.choice(string.ascii_letters)

        # if too long (>12), chop off the excess
        if len(raw) > 12:
            raw = raw[:12]

        # break into a list so we can tweak individual characters
        lst = list(raw)

        # ensure at least one uppercase letter
        if not any(c.isupper() for c in lst):
            idx = secrets.choice(range(len(lst)))
            lst[idx] = secrets.choice(string.ascii_uppercase)

        #  ensure at least one digit
        if not any(c.isdigit() for c in lst):
            idx = secrets.choice(range(len(lst)))
            lst[idx] = secrets.choice(string.digits)

        # ensure at least one punctuation symbol
        if not any(c in string.punctuation for c in lst):
            idx = secrets.choice(range(len(lst)))
            lst[idx] = secrets.choice(string.punctuation)

        # shuffle to remove any predictable pattern
        shuffle(lst)

        # return the final password string
        return ''.join(lst)

    def check_strength(self, pw):

        score = 0
        # +1 if length ≥ 10
        if len(pw) >= 10:
            score += 1
        # +1 if length ≥ 12
        if len(pw) >= 12:
            score += 1
        # +1 if both lowercase & uppercase
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
            score += 1
        # +1 if contains a digit
        if any(c.isdigit() for c in pw):
            score += 1
        # +1 if contains punctuation
        if any(c in string.punctuation for c in pw):
            score += 1

        # map the score to a descriptive label
        if score >= 5:
            return "Very Strong"
        elif score == 4:
            return "Strong"
        elif score == 3:
            return "Moderate"
        else:
            return "Weak"


class PasswordGeneratorUI:

    def __init__(self, master, db, user_id, master_pw):
        self.db = db                # database manager instance
        self.uid = user_id          # logged-in user's ID
        self.mpw = master_pw        # their login password (for encryption)
        self.gen = PasswordGenerator()

        master.title("Generate Password")
        master.geometry("400x500")

        # the five personal questions
        qs = [
            "What is your favorite color?",
            "What is your pet's name?",
            "What is your mother's name?",
            "What city were you born in?",
            "What is the year you were born in?"
        ]

        # create label + entry for each question
        self.entries = []
        for q in qs:
            tk.Label(master, text=q).pack(pady=2)
            e = tk.Entry(master, width=40)
            e.pack(pady=2)
            self.entries.append(e)

        # button to kick off generation
        tk.Button(
            master,
            text="Generate Password",
            command=self.generate_password
        ).pack(pady=10)

        # labels to display the results
        self.pw_lbl = tk.Label(master, font=("Helvetica", 12, "bold"))
        self.pw_lbl.pack(pady=10)

        self.str_lbl = tk.Label(master, font=("Helvetica", 10))
        self.str_lbl.pack(pady=10)

    def generate_password(self):
        # gather trimmed answers from the entry fields
        ans = [e.get().strip() for e in self.entries]

        # if any answer is empty, show an error and abort
        if any(not a for a in ans):
            messagebox.showerror("Error", "Please answer all questions.")
            return

        # create the password and check its strength
        pw = self.gen.generate_password(ans)
        st = self.gen.check_strength(pw)

        # update the GUI to show the new password + strength
        self.pw_lbl.config(text=f"Generated Password:\n{pw}")
        self.str_lbl.config(text=f"Password Strength: {st}")

        # encrypt & save it in the DB (AES-GCM), using the user's login pw
        encrypted = encrypt_password(pw, self.mpw)
        self.db.save_password(self.uid, encrypted, st, self.mpw)

        # let the user know we saved it successfully
        messagebox.showinfo("Success", "Password generated and saved!")


def open_password_generator(db, uid, mpw):

    w = tk.Toplevel()
    PasswordGeneratorUI(w, db, uid, mpw)
    w.mainloop()
