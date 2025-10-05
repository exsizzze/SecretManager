import os
import re
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from typing import Optional
from datetime import datetime

from backend.manager import SecretManager
from storage.export import export_json, import_json
from storage.db import DB_FILE, init_db

ENTRY_FONT = ("Segoe UI", 14)
LABEL_FONT = ("Segoe UI", 12, "bold")
BTN_FONT = ("Segoe UI", 11)
TITLE_FONT = ("Segoe UI", 20, "bold")


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SecretManager - Secure Password Manager")
        self.root.geometry("900x560")
        self.root.minsize(700, 480)
        self.root.resizable(True, True)

        # Авто-блокировка
        self.inactivity_timeout = 300
        self.last_activity = datetime.now()
        self.setup_activity_tracking()

        self._init_style()
        init_db()
        self.mgr = SecretManager()

        self.container = ttk.Frame(self.root)
        self.container.pack(fill="both", expand=True, padx=12, pady=12)

        self.login_frame = ttk.Frame(self.container)
        self.main_frame = ttk.Frame(self.container)
        self.locked_frame = ttk.Frame(self.container)

        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, anchor="w")
        self.status_bar.pack(fill="x", side="bottom", ipady=4)

        self._build_login()
        self._build_main()
        self._build_locked_screen()

        if self.mgr.initialized():
            self._show_login("login")
        else:
            self._show_login("create")

    # ---------------- Activity Tracking ----------------
    def setup_activity_tracking(self):
        self.root.bind('<Button-1>', self._record_activity)
        self.root.bind('<KeyPress>', self._record_activity)
        self.root.bind('<Motion>', self._record_activity)
        self._start_inactivity_timer()

    def _record_activity(self, event=None):
        self.last_activity = datetime.now()

    def _start_inactivity_timer(self):
        def check_inactivity():
            while True:
                time.sleep(10)
                if (datetime.now() - self.last_activity).total_seconds() > self.inactivity_timeout:
                    if hasattr(self, 'mgr') and self.mgr.master.key and not self.mgr.master.locked:
                        self.root.after(0, self._auto_lock)
        thread = threading.Thread(target=check_inactivity, daemon=True)
        thread.start()

    def _auto_lock(self):
        if hasattr(self, 'main_frame') and self.main_frame.winfo_ismapped():
            self.mgr.master.lock()
            self._show_locked_screen()
            self._set_status("Приложение заблокировано из-за бездействия")

    # ---------------- Style ----------------
    def _init_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        bg = "#181818"
        fg = "#e8e8e8"
        entry_bg = "#232323"
        accent = "#0a84ff"
        warning = "#ff9500"

        style.configure(".", background=bg, foreground=fg)
        style.configure("TLabel", background=bg, foreground=fg, font=LABEL_FONT)
        style.configure("TButton", background=accent, foreground="#ffffff", font=BTN_FONT, padding=6)
        style.map("TButton", background=[("active", "#0666d6")])
        style.configure("Warning.TButton", background=warning, foreground="#ffffff")
        style.map("Warning.TButton", background=[("active", "#cc7700")])
        style.configure("TEntry", fieldbackground=entry_bg, foreground=fg, font=ENTRY_FONT)
        style.configure("Treeview", background="#202020", fieldbackground="#202020", foreground=fg, font=ENTRY_FONT)
        style.configure("Treeview.Heading", background="#2a2a2a", foreground=fg, font=LABEL_FONT)
        self.root.configure(bg=bg)

    # ---------------- Locked Screen ----------------
    def _build_locked_screen(self):
        f = self.locked_frame
        card = ttk.Frame(f, padding=24)
        card.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Label(card, text="🔒 SecretManager заблокирован", font=TITLE_FONT).pack(pady=(0, 8))
        ttk.Label(card, text="Приложение было автоматически заблокировано из-за бездействия",
                  font=("Segoe UI", 11)).pack(pady=(0, 12))

        self.lock_pw_var = tk.StringVar()
        pw_entry = ttk.Entry(card, textvariable=self.lock_pw_var, show="*", width=36, font=ENTRY_FONT)
        pw_entry.pack(pady=8)
        pw_entry.bind('<Return>', lambda e: self._unlock_app())

        ttk.Button(card, text="Разблокировать", command=self._unlock_app).pack(pady=4)

    def _show_locked_screen(self):
        self.login_frame.pack_forget()
        self.main_frame.pack_forget()
        self.locked_frame.pack(fill="both", expand=True)
        self.lock_pw_var.set("")

    def _unlock_app(self):
        password = self.lock_pw_var.get()
        if self.mgr.master.unlock(password):
            self.locked_frame.pack_forget()
            self._show_main()
            self._record_activity()
            self._set_status("Приложение разблокировано")
        else:
            self._set_status("Неверный пароль")

    # ---------------- Login ----------------
    def _build_login(self):
        f = self.login_frame
        card = ttk.Frame(f, padding=24)
        card.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Label(card, text="SecretManager", font=TITLE_FONT).pack(pady=(0, 8))
        self.subtitle_var = tk.StringVar()
        ttk.Label(card, textvariable=self.subtitle_var, font=("Segoe UI", 11)).pack(pady=(0, 12))

        # Password field
        self.strength_var = tk.StringVar(value="")
        self.strength_label = ttk.Label(card, textvariable=self.strength_var, font=("Segoe UI", 9))
        self.strength_label.pack(pady=(0, 6))

        pw_frame = ttk.Frame(card)
        pw_frame.pack(fill="x", pady=6)
        self.pw_var = tk.StringVar()
        self.pw_entry = ttk.Entry(pw_frame, textvariable=self.pw_var, show="*", width=36)
        self.pw_entry.pack(side="left", fill="x", expand=True)
        self.pw_entry.bind("<KeyRelease>", self._on_pw_typing)

        self.show_pw_btn = ttk.Button(pw_frame, text="Показать", width=12, command=self._toggle_pw)
        self.show_pw_btn.pack(side="left", padx=(8, 0))

        self.confirm_var = tk.StringVar()
        self.confirm_label = ttk.Label(card, text="Повторите пароль:", font=("Segoe UI", 10))
        self.confirm_entry = ttk.Entry(card, textvariable=self.confirm_var, show="*", width=36)
        self.confirm_visible = False

        # Buttons
        btns = ttk.Frame(card)
        btns.pack(fill="x", pady=(12, 0))
        self.primary_btn = ttk.Button(btns, text="Войти", command=self._on_login)
        self.primary_btn.pack(side="left", padx=4, fill="x", expand=True)
        ttk.Button(btns, text="Сброс данных", command=self._reset_data).pack(side="left", padx=4, fill="x", expand=True)

    def _show_login(self, mode: str):
        self.main_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)
        self.pw_var.set("")
        self.confirm_var.set("")
        if mode == "login":
            self.subtitle_var.set("Введите мастер-пароль")
            self.primary_btn.config(text="Войти")
            if self.confirm_visible:
                self._hide_confirm()
        else:
            self.subtitle_var.set("Создайте мастер-пароль")
            self.primary_btn.config(text="Создать")

    def _on_pw_typing(self, _evt):
        val = self.pw_var.get()
        if val and not self.mgr.initialized():
            is_strong, message = self.mgr.master.check_password_strength(val)
            if is_strong:
                self.strength_var.set("✓ Надёжный пароль")
                self.strength_label.configure(foreground="#00ff00")
            else:
                self.strength_var.set(f"⚠ {message}")
                self.strength_label.configure(foreground="#ff9500")
        else:
            self.strength_var.set("")

        if val and not self.confirm_visible and not self.mgr.initialized():
            self._show_confirm()
        elif not val and self.confirm_visible:
            self._hide_confirm()

    def _show_confirm(self):
        self.confirm_label.pack(pady=(6, 0))
        self.confirm_entry.pack(pady=(4, 0))
        self.confirm_visible = True

    def _hide_confirm(self):
        self.confirm_label.pack_forget()
        self.confirm_entry.pack_forget()
        self.confirm_visible = False

    def _toggle_pw(self):
        if self.pw_entry.cget("show") == "":
            self.pw_entry.config(show="*")
            self.confirm_entry.config(show="*")
            self.show_pw_btn.config(text="Показать")
        else:
            self.pw_entry.config(show="")
            self.confirm_entry.config(show="")
            self.show_pw_btn.config(text="Скрыть")

    def _on_login(self):
        pw = self.pw_var.get().strip()
        if not pw:
            self._set_status("Введите пароль.")
            return

        if self.mgr.initialized():
            try:
                master = self.mgr.master
                key = master._derive(pw, master.salt)
                master.key = key
                self._show_main()
            except Exception:
                self._set_status("Неверный мастер-пароль.")
        else:
            conf = self.confirm_var.get().strip()
            if not conf:
                self._set_status("Повторите пароль.")
                return
            if pw != conf:
                self._set_status("Пароли не совпадают.")
                return
            self.mgr.master.force_set_from_password(pw)
            self._show_main()

    def _reset_data(self):
        if not messagebox.askyesno("Сброс", "Удалить все данные?"):
            return
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
        init_db()
        self.mgr = SecretManager()
        self._show_login("create")
        self._set_status("Все данные удалены.")

    # ---------------- Main ----------------
    def _build_main(self):
        f = self.main_frame
        left = ttk.Frame(f, width=360)
        left.pack(side="left", fill="y", padx=(0, 8))

        search_fr = ttk.Frame(left)
        search_fr.pack(fill="x", pady=(0, 6))
        self.search_var = tk.StringVar()
        ent = ttk.Entry(search_fr, textvariable=self.search_var, font=ENTRY_FONT)
        ent.pack(side="left", fill="x", expand=True)
        ent.bind("<Return>", lambda e: self._refresh_list())
        ttk.Button(search_fr, text="Найти", command=self._refresh_list).pack(side="left", padx=6)

        cols = ("id", "name", "created")
        self.tree = ttk.Treeview(left, columns=cols, show="headings")
        for c, w in zip(cols, (60, 220, 160)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=6)
        ttk.Button(btns, text="Добавить", command=self._clear_fields).pack(side="left", padx=4, fill="x", expand=True)
        ttk.Button(btns, text="Удалить", command=self._delete_selected).pack(side="left", padx=4, fill="x", expand=True)
        ttk.Button(btns, text="🔒 Блокировать", command=self._manual_lock,
                   style="Warning.TButton").pack(side="left", padx=4, fill="x", expand=True)

        center = ttk.Frame(f)
        center.pack(side="left", fill="both", expand=True, padx=(0, 8))

        ttk.Label(center, text="Название:", font=LABEL_FONT).pack(anchor="w")
        self.name_var = tk.StringVar()
        ttk.Entry(center, textvariable=self.name_var, font=ENTRY_FONT).pack(fill="x", pady=8)

        ttk.Label(center, text="Username/Email/URL:", font=LABEL_FONT).pack(anchor="w")
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(center, textvariable=self.username_var, font=ENTRY_FONT)
        username_entry.pack(fill="x", pady=6)
        username_entry.bind("<KeyRelease>", self._validate_username)

        self.username_valid_var = tk.StringVar(value="")
        self.username_valid_label = ttk.Label(center, textvariable=self.username_valid_var, font=("Segoe UI", 9))
        self.username_valid_label.pack(anchor="w")

        ttk.Label(center, text="Password:", font=LABEL_FONT).pack(anchor="w")
        pw_row = ttk.Frame(center)
        pw_row.pack(fill="x", pady=6)
        self.detail_pw_var = tk.StringVar()
        self.detail_pw_entry = ttk.Entry(pw_row, textvariable=self.detail_pw_var, font=ENTRY_FONT, show="*")
        self.detail_pw_entry.pack(side="left", fill="x", expand=True)
        self.detail_pw_entry.bind("<KeyRelease>", lambda e: self._update_strength())
        ttk.Button(pw_row, text="Показать", width=12, command=self._toggle_detail_pw).pack(side="left", padx=(8, 0))

        self.strength_var = tk.StringVar(value="Надёжность: -")
        self.strength_lbl = ttk.Label(center, textvariable=self.strength_var, font=("Segoe UI", 10))
        self.strength_lbl.pack(anchor="w", pady=(0, 8))

        action_row = ttk.Frame(center)
        action_row.pack(fill="x", pady=(10, 0))
        ttk.Button(action_row, text="Сохранить", command=self._save_detail).pack(side="left", padx=6, fill="x", expand=True)
        ttk.Button(action_row, text="Скопировать пароль", command=self._copy_password).pack(side="left", padx=6, fill="x", expand=True)
        ttk.Button(action_row, text="Генерировать", command=self._gen_password).pack(side="left", padx=6, fill="x", expand=True)

        export_row = ttk.Frame(center)
        export_row.pack(fill="x", pady=(12, 0))
        ttk.Button(export_row, text="Экспорт JSON", command=self._export_json).pack(side="left", padx=6, fill="x", expand=True)
        ttk.Button(export_row, text="Импорт JSON", command=self._import_json).pack(side="left", padx=6, fill="x", expand=True)

        self.current_id: Optional[int] = None

    # ---------------- Main Methods ----------------
    def _show_main(self):
        self.login_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)
        self._refresh_list()
        self._set_status("Готово")

    def _refresh_list(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        q = self.search_var.get().strip() or None
        for sid, name, created in self.mgr.list(q):
            try:
                dt = datetime.strptime(created, "%Y-%m-%d %H:%M:%S")
                created_fmt = dt.strftime("%d.%m.%Y, %H:%M")
            except Exception:
                created_fmt = created
            self.tree.insert("", "end", values=(sid, name, created_fmt))

    def _on_select(self, _evt):
        sel = self.tree.selection()
        if not sel:
            return
        sid = int(self.tree.item(sel[0])["values"][0])
        try:
            data = self.mgr.view(sid)
            self.current_id = sid
            self.name_var.set(self.tree.item(sel[0])["values"][1])
            self.username_var.set(data.get("username", ""))
            self.detail_pw_var.set(data.get("password", ""))
            self._update_strength()
        except Exception:
            self._set_status("Ошибка при расшифровке")

    def _on_double_click(self, _evt):
        if self.detail_pw_entry.cget("show") == "":
            self.detail_pw_entry.config(show="*")
        else:
            self.detail_pw_entry.config(show="")

    def _clear_fields(self):
        self.current_id = None
        self.name_var.set("")
        self.username_var.set("")
        self.detail_pw_var.set("")
        self.strength_var.set("Надёжность: -")
        self.tree.selection_remove(self.tree.selection())

    def _save_detail(self):
        name = self.name_var.get().strip()
        if not name:
            self._set_status("Введите название.")
            return
        data = {"username": self.username_var.get(), "password": self.detail_pw_var.get()}
        try:
            if self.current_id:
                self.mgr.update(self.current_id, data)
            else:
                self.mgr.add(name, data)
            self._refresh_list()
            self._set_status("Сохранено.")
        except Exception as e:
            self._set_status(f"Ошибка: {e}")

    def _delete_selected(self):
        if not self.current_id:
            self._set_status("Нет выбора.")
            return
        if not messagebox.askyesno("Удалить", "Удалить выбранную запись?"):
            return
        self.mgr.remove(self.current_id)
        self._clear_fields()
        self._refresh_list()
        self._set_status("Удалено.")

    def _toggle_detail_pw(self):
        if self.detail_pw_entry.cget("show") == "":
            self.detail_pw_entry.config(show="*")
        else:
            self.detail_pw_entry.config(show="")

    def _copy_password(self):
        pw = self.detail_pw_var.get()
        if pw:
            self.mgr.copy_with_timeout(self.root, pw)
            self._set_status("Пароль скопирован (15 сек).")

    def _gen_password(self):
        pw = self.mgr.generate_password(16)
        self.detail_pw_var.set(pw)
        self._update_strength()
        self._set_status("Пароль сгенерирован.")

    def _update_strength(self):
        pw = self.detail_pw_var.get()
        score = 0
        if len(pw) >= 8:
            score += 1
        if any(c.isupper() for c in pw):
            score += 1
        if any(c.isdigit() for c in pw):
            score += 1
        if any(c in "!@#$%^&*()-_=+[]{};:,.<>?/" for c in pw):
            score += 1
        levels = ["Очень слабый", "Слабый", "Средний", "Хороший", "Сильный"]
        self.strength_var.set(f"Надёжность: {levels[score]}")

    def _export_json(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON файлы", "*.json")],
            title="Сохранить как"
        )
        if not path:
            return
        export_json(path, getattr(self.mgr.master, "salt", None))
        self._set_status(f"Экспортировано в {path}")

    def _import_json(self):
        path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json")],
            title="Выберите файл для импорта"
        )
        if not path:
            return
        try:
            import_json(path, self.mgr.master.key)
            self._refresh_list()
            self._set_status(f"Данные импортированы из {path}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось импортировать данные: {str(e)}")

    def _validate_username(self, event=None):
        username = self.username_var.get()
        if not username:
            self.username_valid_var.set("")
            return
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, username):
            self.username_valid_var.set("✓ Valid email")
            self.username_valid_label.configure(foreground="#00ff00")
            return
        url_pattern = r'^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/\S*)?$'
        if re.match(url_pattern, username):
            self.username_valid_var.set("✓ Valid URL")
            self.username_valid_label.configure(foreground="#00ff00")
            return
        if len(username) >= 3:
            self.username_valid_var.set("✓ Username")
            self.username_valid_label.configure(foreground="#00ff00")
        else:
            self.username_valid_var.set("⚠ Too short")
            self.username_valid_label.configure(foreground="#ff9500")

    def _manual_lock(self):
        self.mgr.master.lock()
        self._show_locked_screen()
        self._set_status("Приложение заблокировано вручную")

    # ---------------- Security Settings ----------------
    def _show_security_settings(self):
        settings_win = tk.Toplevel(self.root)
        settings_win.title("Настройки безопасности")
        settings_win.geometry("400x200")
        settings_win.transient(self.root)
        settings_win.grab_set()

        ttk.Label(settings_win, text="Настройки безопасности", font=TITLE_FONT).pack(pady=12)
        timeout_frame = ttk.Frame(settings_win)
        timeout_frame.pack(fill="x", padx=20, pady=8)
        ttk.Label(timeout_frame, text="Авто-блокировка через (минут):").pack(anchor="w")
        self.timeout_var = tk.StringVar(value=str(self.inactivity_timeout // 60))
        timeout_combo = ttk.Combobox(timeout_frame, textvariable=self.timeout_var, values=["1", "3", "5", "10", "15", "30"])
        timeout_combo.pack(fill="x", pady=4)
        ttk.Button(settings_win, text="Сохранить настройки", command=lambda: self._save_security_settings(settings_win)).pack(pady=12)

    def _save_security_settings(self, win):
        try:
            timeout_min = int(self.timeout_var.get())
            self.inactivity_timeout = timeout_min * 60
            win.destroy()
            self._set_status("Настройки безопасности сохранены")
        except ValueError:
            messagebox.showerror("Ошибка", "Некорректное значение таймаута")

    def _set_status(self, text: str):
        self.status_var.set(text)


def run_app():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    run_app()
