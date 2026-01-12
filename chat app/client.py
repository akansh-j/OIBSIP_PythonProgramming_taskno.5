# Chat App
# Developed by: Akansh Jadam
# Internship Task_4 - OIBSIP (Python Programming Internship)
# Date: 12/JAN/2026



import socket
import threading
import sqlite3
import pickle
import tkinter as tk
from tkinter import messagebox, scrolledtext
import sys

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
    KEY = b"Generate and insert your key here"
    cipher = Fernet(KEY)
except ImportError:
    HAS_CRYPTO = False

try:
    import winsound
except ImportError:
    winsound = None

# --- CONFIGURATION ---
HOST = '127.0.0.1'
PORT = 9999
HEADER_SIZE = 10

# --- THEME COLORS (DARK MODE) ---
BG_COLOR = "#121212"      # Deep Black
PANEL_COLOR = "#1e1e1e"   # Dark Gray
TEXT_COLOR = "#e0e0e0"    # Off-white
ACCENT_COLOR = "#00d2ff"  # Neon Cyan
ERROR_COLOR = "#cf6679"   # Muted Red
SUCCESS_COLOR = "#03dac6" # Teal
FONT_MAIN = ("Consolas", 11)
FONT_HEADER = ("Consolas", 16, "bold")

# --- DATABASE HANDLER ---
def init_db():
    conn = sqlite3.connect('chat.db', check_same_thread=False)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS history (room TEXT, sender TEXT, message TEXT)")
    conn.commit()
    return conn



class ServerThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen()
        self.clients = {} 
        self.db = init_db()
        self.daemon = True 

    def run(self):
        while True:
            try:
                client, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()
            except:
                break

    def handle_client(self, client_socket):
        username = "Guest"
        current_room = "General"
        try:
            while True:
                header = client_socket.recv(HEADER_SIZE)
                if not header: break
                msg_len = int(header.strip())
                data = b""
                while len(data) < msg_len:
                    packet = client_socket.recv(msg_len - len(data))
                    if not packet: break
                    data += packet
                
                request = pickle.loads(data)
                cmd = request['cmd']

                if cmd == 'REGISTER':
                    c = self.db.cursor()
                    try:
                        c.execute("INSERT INTO users VALUES (?, ?)", (request['user'], request['pass']))
                        self.db.commit()
                        self.send(client_socket, {'status': 'SUCCESS', 'msg': 'User Created'})
                    except:
                        self.send(client_socket, {'status': 'FAIL', 'msg': 'Username Taken'})

                elif cmd == 'LOGIN':
                    c = self.db.cursor()
                    c.execute("SELECT * FROM users WHERE username=? AND password=?", (request['user'], request['pass']))
                    if c.fetchone():
                        username = request['user']
                        self.clients[client_socket] = (username, current_room)
                        self.send(client_socket, {'status': 'SUCCESS', 'msg': 'Access Granted'})
                        self.load_history(client_socket, current_room)
                    else:
                        self.send(client_socket, {'status': 'FAIL', 'msg': 'Access Denied'})

                elif cmd == 'JOIN':
                    current_room = request['room']
                    self.clients[client_socket] = (username, current_room)
                    self.send(client_socket, {'cmd': 'CLEAR'})
                    self.load_history(client_socket, current_room)

                elif cmd == 'MSG':
                    c = self.db.cursor()
                    c.execute("INSERT INTO history VALUES (?, ?, ?)", (current_room, username, request['msg']))
                    self.db.commit()
                    self.broadcast(current_room, username, request['msg'])

        except: pass
        finally:
            if client_socket in self.clients: del self.clients[client_socket]
            client_socket.close()

    def load_history(self, sock, room):
        c = self.db.cursor()
        c.execute("SELECT sender, message FROM history WHERE room=?", (room,))
        for sender, msg in c.fetchall():
            self.send(sock, {'cmd': 'MSG', 'sender': sender, 'msg': msg})

    def broadcast(self, room, sender, message):
        for sock, (user, user_room) in self.clients.items():
            if user_room == room:
                self.send(sock, {'cmd': 'MSG', 'sender': sender, 'msg': message})

    def send(self, sock, data):
        try:
            serialized = pickle.dumps(data)
            header = bytes(f"{len(serialized):<{HEADER_SIZE}}", "utf-8")
            sock.sendall(header + serialized)
        except: pass



class ChatClient:
    def __init__(self, master):
        self.root = master
        self.root.title("NEXUS CHAT // SECURE TERMINAL")
        self.root.geometry("800x600")
        self.root.configure(bg=BG_COLOR)
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        
        try:
            self.sock.connect((HOST, PORT))
            threading.Thread(target=self.listen, daemon=True).start()
        except:
            messagebox.showerror("Connection Error", "Server Offline")

        self.login_ui()

    def send_packet(self, data):
        try:
            serialized = pickle.dumps(data)
            header = bytes(f"{len(serialized):<{HEADER_SIZE}}", "utf-8")
            self.sock.sendall(header + serialized)
        except: pass

    def create_button(self, parent, text, cmd, color=ACCENT_COLOR):
        return tk.Button(parent, text=text, command=cmd, bg=color, fg=BG_COLOR, 
                         font=("Consolas", 10, "bold"), activebackground=TEXT_COLOR, relief=tk.FLAT, padx=20, pady=5)

    def create_entry(self, parent, show=None):
        return tk.Entry(parent, font=FONT_MAIN, bg=PANEL_COLOR, fg=TEXT_COLOR, 
                        insertbackground=ACCENT_COLOR, relief=tk.FLAT, show=show)

    # --- LOGIN SCREEN ---
    def login_ui(self):
        self.clear()
        
        # Center Frame
        f = tk.Frame(self.root, bg=BG_COLOR)
        f.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        tk.Label(f, text="SYSTEM ACCESS", font=("Consolas", 24, "bold"), bg=BG_COLOR, fg=ACCENT_COLOR).pack(pady=20)
        
        tk.Label(f, text="IDENTITY:", font=FONT_MAIN, bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.u_entry = self.create_entry(f)
        self.u_entry.pack(pady=5, ipady=5, fill=tk.X)
        self.u_entry.insert(0, "User_1")
        
        tk.Label(f, text="PASSPHRASE:", font=FONT_MAIN, bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w", pady=(10,0))
        self.p_entry = self.create_entry(f, show="*")
        self.p_entry.pack(pady=5, ipady=5, fill=tk.X)
        self.p_entry.insert(0, "123")
        
        self.create_button(f, "AUTHENTICATE", self.do_login).pack(pady=20, fill=tk.X)
        tk.Button(f, text="[ CREATE NEW IDENTITY ]", command=self.do_register, bg=BG_COLOR, fg=TEXT_COLOR, 
                  font=("Consolas", 9), relief=tk.FLAT, activebackground=BG_COLOR).pack()

    # --- MAIN CHAT SCREEN ---
    def chat_ui(self):
        self.clear()
        
        # Sidebar
        sidebar = tk.Frame(self.root, width=200, bg=PANEL_COLOR)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        
        tk.Label(sidebar, text="// CHANNELS", fg=ACCENT_COLOR, bg=PANEL_COLOR, font=FONT_HEADER).pack(pady=20)
        
        for r in ["GENERAL", "OPS_TECHS", "CLASSIFIED"]:
            tk.Button(sidebar, text=f"# {r}", command=lambda x=r: self.send_packet({'cmd':'JOIN', 'room':x}),
                      bg=PANEL_COLOR, fg=TEXT_COLOR, font=FONT_MAIN, anchor="w", relief=tk.FLAT, 
                      activebackground=BG_COLOR, activeforeground=ACCENT_COLOR).pack(fill=tk.X, padx=10, pady=2)

        # Right Side
        right = tk.Frame(self.root, bg=BG_COLOR)
        right.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)
        
        # Header
        self.status_lbl = tk.Label(right, text=f"LOGGED IN AS: {self.username.upper()}", 
                                   bg=BG_COLOR, fg=SUCCESS_COLOR, font=("Consolas", 9), anchor="e")
        self.status_lbl.pack(fill=tk.X, padx=10, pady=5)
        
        # Chat Box
        self.box = scrolledtext.ScrolledText(right, state='disabled', font=FONT_MAIN, 
                                             bg=BG_COLOR, fg=TEXT_COLOR, insertbackground=ACCENT_COLOR)
        self.box.pack(expand=True, fill=tk.BOTH, padx=10, pady=0)
        
        # Input Area
        btm = tk.Frame(right, bg=BG_COLOR)
        btm.pack(fill=tk.X, padx=10, pady=10)
        
        self.msg_entry = self.create_entry(btm)
        self.msg_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, ipady=5)
        self.msg_entry.bind("<Return>", lambda e: self.send_msg())
        
        self.create_button(btm, "TRANSMIT", self.send_msg).pack(side=tk.LEFT, padx=(10,0))

    # --- LOGIC ---
    def do_login(self):
        u, p = self.u_entry.get(), self.p_entry.get()
        self.send_packet({'cmd': 'LOGIN', 'user': u, 'pass': p})
        self.username = u

    def do_register(self):
        u, p = self.u_entry.get(), self.p_entry.get()
        self.send_packet({'cmd': 'REGISTER', 'user': u, 'pass': p})

    def send_msg(self):
        txt = self.msg_entry.get()
        if not txt: return
        self.msg_entry.delete(0, tk.END)
        
        if HAS_CRYPTO:
            final_msg = cipher.encrypt(txt.encode())
        else:
            final_msg = "[UNSECURE] " + txt 
        self.send_packet({'cmd': 'MSG', 'msg': final_msg})

    def listen(self):
        while True:
            try:
                header = self.sock.recv(HEADER_SIZE)
                if not header: break
                msg_len = int(header.strip())
                data = b""
                while len(data) < msg_len:
                    data += self.sock.recv(msg_len - len(data))
                
                req = pickle.loads(data)
                
                if 'status' in req:
                    if req['status'] == 'SUCCESS':
                        self.root.after(0, self.chat_ui)
                    else:
                        messagebox.showerror("Access Denied", req['msg'])
                
                elif req.get('cmd') == 'MSG':
                    sender = req['sender']
                    raw = req['msg']
                    try:
                        if HAS_CRYPTO and isinstance(raw, bytes):
                            txt = cipher.decrypt(raw).decode()
                        else:
                            txt = str(raw)
                    except: txt = "<Encrypted Data>"

                    self.root.after(0, lambda s=sender, t=txt: self.append_msg(s, t))
            except: break

    def append_msg(self, sender, txt):
        self.box.config(state='normal')
        
        # Formatting for "cool" look
        if sender == self.username:
            self.box.insert(tk.END, f"\n> ME: {txt}", "self")
        else:
            self.box.insert(tk.END, f"\n[{sender}]: {txt}", "other")
            
        self.box.tag_config("self", foreground=SUCCESS_COLOR)
        self.box.tag_config("other", foreground=ACCENT_COLOR)
        
        self.box.see(tk.END)
        self.box.config(state='disabled')
        if sender != self.username and winsound:
            try: winsound.Beep(1200, 50)
            except: pass

    def clear(self):
        for w in self.root.winfo_children(): w.destroy()

# --- LAUNCHER ---
if __name__ == "__main__":
    # Start Server (Background)
    server = ServerThread()
    server.start()
    
    # Start GUI (Foreground)
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()