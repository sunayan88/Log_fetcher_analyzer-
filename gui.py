# gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from auth import User, Activity
from database import init_db
from log import LOG_SOURCES, get_time_filter, fetch_logs, analyze_logs
import mysql.connector
from config import DB_CONFIG

class LogAnalyzerGUI:
    COMMON_ERRORS = ["error", "failed", "denied", "warning", "critical"]

    def __init__(self, root):
        self.root = root
        self.root.title("Log Analyzer GUI")
        self.root.geometry("1000x700")

        # Auto-initialize database
        init_db()

        # Current user (None if not logged in)
        self.current_user = None

        # Store logs
        self.current_logs = []   # Original logs from fetch/open
        self.displayed_logs = [] # Possibly filtered logs

        # Show login window first
        self.create_login_window()

    # -----------------------------
    #         LOGIN
    # -----------------------------
    def create_login_window(self):
        self.login_frame = ttk.Frame(self.root)
        self.login_frame.pack(pady=50)

        ttk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        login_btn = ttk.Button(self.login_frame, text="Login", command=self.handle_login)
        login_btn.grid(row=2, column=0, pady=10)

        register_btn = ttk.Button(self.login_frame, text="Register", command=self.create_register_window)
        register_btn.grid(row=2, column=1, pady=10)

    def handle_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        user = User.authenticate(username, password)
        if user:
            self.current_user = user
            # Log this login
            Activity.log(user.id, "LOGIN", "auth")
            messagebox.showinfo("Success", f"Welcome, {user.username}!")
            self.login_frame.destroy()
            self.create_main_interface()
        else:
            messagebox.showerror("Error", "Invalid credentials")

    def create_register_window(self):
        self.register_window = tk.Toplevel(self.root)
        self.register_window.title("Register")

        ttk.Label(self.register_window, text="New Username:").grid(row=0, column=0, padx=5, pady=5)
        self.reg_username_entry = ttk.Entry(self.register_window)
        self.reg_username_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.register_window, text="New Password:").grid(row=1, column=0, padx=5, pady=5)
        self.reg_password_entry = ttk.Entry(self.register_window, show="*")
        self.reg_password_entry.grid(row=1, column=1, padx=5, pady=5)

        reg_btn = ttk.Button(self.register_window, text="Register", command=self.handle_register)
        reg_btn.grid(row=2, column=0, columnspan=2, pady=10)

    def handle_register(self):
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return

        success = User.register(username, password)
        if success:
            messagebox.showinfo("Success", "User registered successfully!")
            self.register_window.destroy()
        else:
            messagebox.showerror("Error", "Registration failed. Username may already exist.")

    # -----------------------------
    #        MAIN INTERFACE
    # -----------------------------
    def create_main_interface(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Log Type
        ttk.Label(self.main_frame, text="Log Type:").grid(row=0, column=0, sticky="w")
        self.log_type_var = tk.StringVar(value="Select Log Type")
        types = list(LOG_SOURCES.keys()) + ["Custom Range"]
        self.log_type_cb = ttk.Combobox(self.main_frame, textvariable=self.log_type_var,
                                        values=types, state="readonly")
        self.log_type_cb.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Time Range
        ttk.Label(self.main_frame, text="Time Range:").grid(row=1, column=0, sticky="w")
        self.time_range_var = tk.StringVar(value="Select Time Range")
        timevals = ["Last 15 minutes", "Last 1 hour", "Last 24 hours", "Custom Range"]
        self.time_range_cb = ttk.Combobox(self.main_frame, textvariable=self.time_range_var,
                                          values=timevals, state="readonly")
        self.time_range_cb.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Buttons row
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=5)

        fetch_btn = ttk.Button(btn_frame, text="Fetch Logs", command=self.fetch_and_display_analysis)
        fetch_btn.pack(side="left", padx=5)

        self.save_btn = ttk.Button(btn_frame, text="Save Logs", command=self.save_logs, state="disabled")
        self.save_btn.pack(side="left", padx=5)

        self.view_raw_btn = ttk.Button(btn_frame, text="View Raw Logs", command=self.view_raw_logs, state="disabled")
        self.view_raw_btn.pack(side="left", padx=5)

        open_file_btn = ttk.Button(btn_frame, text="Open Log File", command=self.open_log_file)
        open_file_btn.pack(side="left", padx=5)

        # Logout button
        logout_btn = ttk.Button(btn_frame, text="Logout", command=self.handle_logout)
        logout_btn.pack(side="left", padx=5)

        # Admin-only: View user history
        if self.current_user.role == "admin":
            history_btn = ttk.Button(btn_frame, text="View User History", command=self.view_user_history)
            history_btn.pack(side="left", padx=5)

        # Filtering row
        filter_frame = ttk.Frame(self.main_frame)
        filter_frame.grid(row=3, column=0, columnspan=2, pady=5)

        ttk.Label(filter_frame, text="Filter by keyword:").pack(side="left", padx=5)
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=20)
        self.filter_entry.pack(side="left", padx=5)

        self.apply_filter_btn = ttk.Button(filter_frame, text="Apply Filter",
                                           command=self.apply_filter, state="disabled")
        self.apply_filter_btn.pack(side="left", padx=5)

        self.clear_filter_btn = ttk.Button(filter_frame, text="Clear Filter",
                                           command=self.clear_filter, state="disabled")
        self.clear_filter_btn.pack(side="left", padx=5)

        # Display area
        self.display_area = scrolledtext.ScrolledText(self.main_frame, width=110, height=20)
        self.display_area.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    def handle_logout(self):
        """
        Logs the user out, records a LOGOUT event, and returns to the login screen.
        """
        if self.current_user:
            Activity.log(self.current_user.id, "LOGOUT", "auth")
        messagebox.showinfo("Goodbye", "You have been logged out.")
        self.main_frame.destroy()
        self.current_user = None
        self.create_login_window()

    def view_user_history(self):
        """
        Opens a new window showing all records in 'activities', sorted by ID desc.
        Admin only.
        """
        if self.current_user.role != "admin":
            messagebox.showerror("Permission Denied", "Only admin can view user history.")
            return

        history_window = tk.Toplevel(self.root)
        history_window.title("User History")
        history_window.geometry("800x400")

        cols = ("ID", "UserID", "Action", "LogType", "Timestamp")
        tree = ttk.Treeview(history_window, columns=cols, show="headings")
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=120)
        tree.pack(fill="both", expand=True)

        # Fetch from DB
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor()
            cursor.execute("SELECT id, user_id, action, log_type, timestamp FROM activities ORDER BY id DESC")
            rows = cursor.fetchall()
            for row in rows:
                tree.insert("", tk.END, values=row)
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()

    # -----------------------------
    #       FETCH & ANALYSIS
    # -----------------------------
    def fetch_and_display_analysis(self):
        log_type = self.log_type_var.get()
        time_range = self.time_range_var.get()

        if log_type not in LOG_SOURCES and log_type != "Custom Range":
            messagebox.showwarning("Warning", "Please select a valid log type.")
            return
        if time_range not in ["Last 15 minutes", "Last 1 hour", "Last 24 hours", "Custom Range"]:
            messagebox.showwarning("Warning", "Please select a valid time range.")
            return

        # Handle custom range if selected
        if time_range == "Custom Range" or log_type == "Custom Range":
            custom = self.get_custom_range()
            if not custom:  # user canceled
                return
            since, until = custom
            # If log type was "Custom Range," fallback to System Logs
            if log_type == "Custom Range":
                messagebox.showwarning(
                    "Warning",
                    "No known command for 'Custom Range' log type.\nUsing 'System Logs' as default."
                )
                log_type = "System Logs"
        else:
            since, until = get_time_filter(time_range)

        # Actually fetch logs
        source_cmd = LOG_SOURCES[log_type]["command"] if log_type in LOG_SOURCES else ""
        logs = fetch_logs(source_cmd, since, until)
        self.current_logs = logs[:]
        self.displayed_logs = logs[:]

        if not logs:
            self.display_area.delete("1.0", tk.END)
            self.display_area.insert(tk.END, "No logs found.\n")
            self.save_btn.config(state="disabled")
            self.view_raw_btn.config(state="disabled")
            self.apply_filter_btn.config(state="disabled")
            self.clear_filter_btn.config(state="disabled")
            return

        # Log the activity
        Activity.log(self.current_user.id, f"Fetched {log_type} for {time_range}", log_type)

        # Analyze & display summary
        analysis = analyze_logs(logs, log_type)
        summary = self.generate_analysis_report(analysis, logs)

        self.display_area.delete("1.0", tk.END)
        self.display_area.insert(tk.END, summary)

        self.save_btn.config(state="normal")
        self.view_raw_btn.config(state="normal")
        self.apply_filter_btn.config(state="normal")
        self.clear_filter_btn.config(state="disabled")

    def get_custom_range(self):
        """
        Popup to get user-defined start/end times.
        Returns (since, until) or None if canceled.
        """
        popup = tk.Toplevel(self.root)
        popup.title("Custom Time Range")
        popup.geometry("300x150")

        tk.Label(popup, text="Start time (YYYY-MM-DD HH:MM:SS):").pack(pady=5)
        since_var = tk.StringVar()
        since_entry = ttk.Entry(popup, textvariable=since_var)
        since_entry.pack()

        tk.Label(popup, text="End time (YYYY-MM-DD HH:MM:SS) or 'now':").pack(pady=5)
        until_var = tk.StringVar(value="now")
        until_entry = ttk.Entry(popup, textvariable=until_var)
        until_entry.pack()

        result = []

        def on_confirm():
            s = since_var.get().strip()
            u = until_var.get().strip()
            if not s:
                messagebox.showwarning("Warning", "Please enter a valid start time.")
                return
            if not u:
                u = "now"
            result.append((s, u))
            popup.destroy()

        def on_cancel():
            result.append(None)
            popup.destroy()

        bf = ttk.Frame(popup)
        bf.pack(pady=10)
        confirm_btn = ttk.Button(bf, text="Confirm", command=on_confirm)
        confirm_btn.pack(side="left", padx=5)
        cancel_btn = ttk.Button(bf, text="Cancel", command=on_cancel)
        cancel_btn.pack(side="left", padx=5)

        popup.grab_set()
        self.root.wait_window(popup)
        return result[0] if result else None

    def generate_analysis_report(self, analysis, logs):
        """
        Build a text summary from the 'analysis' dict,
        plus counts of common error keywords.
        """
        report_lines = []
        # Subcategory + severity counts
        for subcat, sev_dict in analysis.items():
            report_lines.append(f"Subcategory: {subcat}")
            for sev, lines_list in sev_dict.items():
                report_lines.append(f"  {sev}: {len(lines_list)} log(s)")
            report_lines.append("")

        # Common error keywords
        common_counts = self.count_common_errors(logs)
        report_lines.append("Common Error Keywords:")
        any_found = False
        for kw, cnt in common_counts.items():
            if cnt > 0:
                report_lines.append(f"  '{kw}': {cnt} occurrence(s)")
                any_found = True
        if not any_found:
            report_lines.append("  (No common error keywords found)")
        report_lines.append("")

        return "\n".join(report_lines).strip()

    def count_common_errors(self, logs):
        """
        Count occurrences of a few known keywords in the logs.
        """
        counts = {k: 0 for k in self.COMMON_ERRORS}
        for line in logs:
            l = line.lower()
            for k in self.COMMON_ERRORS:
                if k in l:
                    counts[k] += 1
        return counts

    # -----------------------------
    #         FILTERING
    # -----------------------------
    def apply_filter(self):
        """
        Filter self.current_logs by a keyword, re-run analysis, update display.
        """
        kw = self.filter_var.get().strip().lower()
        if not kw:
            messagebox.showwarning("Warning", "Please enter a keyword to filter.")
            return

        filtered = [ln for ln in self.current_logs if kw in ln.lower()]
        self.displayed_logs = filtered

        if not filtered:
            self.display_area.delete("1.0", tk.END)
            self.display_area.insert(tk.END, f"No logs found matching '{kw}'.\n")
            self.view_raw_btn.config(state="disabled")
            self.clear_filter_btn.config(state="normal")
            return

        # Re-analyze with the same log type
        log_type = self.log_type_var.get()
        if log_type not in LOG_SOURCES:
            log_type = "System Logs"

        analysis = analyze_logs(filtered, log_type)
        summary = self.generate_analysis_report(analysis, filtered)
        self.display_area.delete("1.0", tk.END)
        self.display_area.insert(tk.END, summary)

        self.view_raw_btn.config(state="normal")
        self.clear_filter_btn.config(state="normal")

    def clear_filter(self):
        """
        Restore the unfiltered logs.
        """
        self.displayed_logs = self.current_logs[:]
        log_type = self.log_type_var.get()
        if log_type not in LOG_SOURCES:
            log_type = "System Logs"

        analysis = analyze_logs(self.displayed_logs, log_type)
        summary = self.generate_analysis_report(analysis, self.displayed_logs)
        self.display_area.delete("1.0", tk.END)
        self.display_area.insert(tk.END, summary)

        self.clear_filter_btn.config(state="disabled")
        self.filter_var.set("")

    # -----------------------------
    #     RAW VIEW & SAVE
    # -----------------------------
    def view_raw_logs(self):
        """
        Opens a new window showing the raw log lines (displayed_logs),
        plus a button to save them directly from that window.
        """
        if not self.displayed_logs:
            messagebox.showinfo("Info", "No logs to display.")
            return

        raw_window = tk.Toplevel(self.root)
        raw_window.title("Raw Logs")
        raw_window.geometry("900x500")

        top_frame = ttk.Frame(raw_window)
        top_frame.pack(fill="both", expand=True)

        raw_text = scrolledtext.ScrolledText(top_frame, width=110, height=25)
        raw_text.pack(side="top", fill="both", expand=True)

        for line in self.displayed_logs:
            raw_text.insert(tk.END, line + "\n")

        def save_raw_from_window():
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
            )
            if file_path:
                try:
                    with open(file_path, "w") as f:
                        f.write("\n".join(self.displayed_logs))
                    messagebox.showinfo("Success", f"Logs saved to {file_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save logs: {e}")

        save_button = ttk.Button(raw_window, text="Save These Logs", command=save_raw_from_window)
        save_button.pack(side="bottom", pady=5)

    def save_logs(self):
        """
        Saves self.displayed_logs to a file.
        """
        if not self.displayed_logs:
            messagebox.showinfo("Info", "No logs to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files","*.txt"), ("All Files","*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write("\n".join(self.displayed_logs))
                messagebox.showinfo("Success", f"Logs saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {e}")

    # -----------------------------
    #        OPEN LOG FILE
    # -----------------------------
    def open_log_file(self):
        """
        Let the user pick a local .log or .txt file to analyze.
        """
        file_path = filedialog.askopenfilename(
            filetypes=[("Log Files","*.log *.txt"),("All Files","*.*")]
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = [ln.rstrip("\n") for ln in f]
                self.current_logs = lines[:]
                self.displayed_logs = lines[:]
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open file: {e}")
                return

            # We'll treat it like "Application Logs"
            log_type = "Application Logs"
            analysis = analyze_logs(self.displayed_logs, log_type)
            summary = self.generate_analysis_report(analysis, self.displayed_logs)

            self.display_area.delete("1.0", tk.END)
            self.display_area.insert(tk.END, summary)

            self.save_btn.config(state="normal")
            self.view_raw_btn.config(state="normal")
            self.apply_filter_btn.config(state="normal")
            self.clear_filter_btn.config(state="disabled")

            # Record this activity
            Activity.log(self.current_user.id, f"Opened local log file: {file_path}", "File")


if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerGUI(root)
    root.mainloop()
