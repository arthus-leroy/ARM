#!/bin/python

from tkinter import Tk, StringVar, NW, W, E
from tkinter.ttk import Notebook, Frame, Style, Label, Button, Entry
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showerror, showinfo
from threading import Thread
from serial import Serial

from nacl.hash import sha256
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

from sys import argv

NO_ERR				= 0
ASSERT_ERR			= 1
CORRUPT				= 2
WRONG_HASH			= 3
WRONG_PWD			= 4
LOGIN_NOT_EXISTS	= 5

MOD_MAST_PWD		= 1
SEND_KEY			= 2
SIGN				= 3
ADD_LOGIN			= 4
GET_LOGIN			= 5
DEL_LOGIN			= 6
QUIT				= 7

# FIXME : set private key
private_key = SigningKey(b"0123456789ABCDEF0123456789ABCDEF")

assert(len(argv) >= 3)
com = argv[1]
baud = int(argv[2])
ser = Serial(com, baud)

root = Tk()
root.title("UI")

answer_area = StringVar(root)
def read_serial():
	while True:
		header = ser.read(3)
		args = ser.read(header[0])
		ser.read(1)		# checksum (ignored)

		err = header[2]
		if err == ASSERT_ERR:
			showerror("Assertion Error", "".join(chr(a) for a in args))
		elif err == CORRUPT:
			showerror("Corrution error", "Sent message was corrupted. Try again.")
		elif err == WRONG_HASH:
			showerror("Wrong hash", "The hash sent for the bootloader was wrong.")
		elif err == WRONG_PWD:
			showerror("Wrong password", "Wrong master password : %s." %master_password.get())
		elif err == LOGIN_NOT_EXISTS:
			showerror("Login does not exist", "The requested login does not exist")
		else:
			op = header[1]
			if op == MOD_MAST_PWD:
				showinfo("Master password changed")
				master_password.set(master_password_mod.get())
			elif op == SEND_KEY \
			  or op == SIGN:
				answer_area.set("".join("%0X" %a for a in args))
			elif op == ADD_LOGIN:
				showinfo("Added password")
			elif op == DEL_LOGIN:
				showinfo("Deleted password")
			elif op == GET_LOGIN:
				answer_area.set("".join(chr(a) for a in args))
			elif op == QUIT:
				showinfo("Returned to bootloader")

bootloader_path = StringVar(root)
def send_bootloader():
	with open(bootloader_path.get(), "rb") as f:
		data = f.read().split()
		h = sha256(data, encoder = HexEncoder)
		ch = private_key.sign(h)

		ser.write([len(data)] + data + ch + h)

master_password = StringVar(root)
def send_tx_message(password, op, args):
	checksum = 0
	for a in args:
		checksum += a

	if password:
		master_pass = [ord(c) for c in master_password.get()]
		ser.write([len(args), op] + master_pass + args + [checksum & 0xFF])
	else:
		ser.write([len(args), op] + args + [checksum & 0xFF])

master_password_mod = StringVar(root)
def modify_master_password():
	master_pass_mod = [ord(c) for c in master_password_mod.get()]
	send_tx_message(1, MOD_MAST_PWD, master_pass_mod)

def send_key():
	send_tx_message(1, SEND_KEY, [])

sign_file_path = StringVar(root)
def sign_file():
	sign_file_p = [ord(c) for c in sign_file_path.get()]
	send_tx_message(1, SIGN, sign_file_p)

login = StringVar(root)
password = StringVar(root)
def add_login():
	login_pwd = [ord(c) for c in login.get()] + [0] \
			  + [ord(c) for c in password.get()] + [0]
	send_tx_message(1, ADD_LOGIN, login_pwd)

def get_login():
	login_tab = [ord(c) for c in login.get()] + [0]
	send_tx_message(1, GET_LOGIN, login_tab)

def del_login():
	login_tab = [ord(c) for c in login.get()] + [0]
	send_tx_message(1, DEL_LOGIN, login_tab)

def quit():
	send_tx_message(0, QUIT, [])

Thread(target = read_serial, args = ())

style = Style()
for item in ("TFrame", "TButton", "TLabel"):
	style.configure(item, background = "black", foreground = "white")

frame = Notebook(root)

bootloader = Frame(frame)
Label(bootloader, text = "Bootloader path :").grid(row = 0, sticky = W)
Label(bootloader, textvariable = bootloader_path, relief = "groove").grid(row = 1, column = 0, columnspan = 2, sticky = W+E, padx = (0, 10))
Button(bootloader, text = "...", command = lambda: bootloader_path.set(askopenfilename(filetypes = [("Binary files", "*.bin")]))).grid(row = 1, column = 2)
Label(bootloader, text = "").grid(row = 2)
Button(bootloader, text = "Send bootloader code", command = send_bootloader).grid(row = 3, sticky = W)
frame.add(bootloader, text = "Bootloader")

manager = Frame(frame)
Label(manager, text = "Master password : ").grid(row = 0, column = 0, sticky = W)
Entry(manager, textvariable = master_password).grid(row = 0, column = 1, columnspan = 2, sticky = W+E)

Label(manager, text = "").grid(row = 1)

Label(manager, text = "Modify master password:").grid(row = 2, column = 0, sticky = W)
Entry(manager, textvariable = master_password_mod).grid(row = 3, column = 0, columnspan = 2, sticky = W+E)
Button(manager, text = "Modify", command = modify_master_password).grid(row = 3, column = 2)

Label(manager, text = "").grid(row = 4)

Button(manager, text = "Send public key", command = send_key).grid(row = 5, sticky = W)

Label(manager, text = "").grid(row = 6)

Label(manager, text = "Sign file:").grid(row = 7, sticky = W)
Label(manager, textvariable = sign_file_path, relief = "groove").grid(row = 8, column = 0, columnspan = 2, sticky = W+E)
Button(manager, text = "...", command = lambda: sign_file_path.set(askopenfilename())).grid(row = 8, column = 2)

Label(manager, text = "").grid(row = 9)

Label(manager, text = "Login:").grid(row = 10, column = 0, sticky = W)
Label(manager, text = "Password:").grid(row = 10, column = 1, sticky = W)
Entry(manager, textvariable = login).grid(row = 11, column = 0, sticky = W+E, padx = (0, 15))
Entry(manager, textvariable = password).grid(row = 11, column = 1, sticky = W+E)
Button(manager, text = "Add", command = add_login).grid(row = 12, column = 0)
Button(manager, text = "Get", command = get_login).grid(row = 12, column = 1)
Button(manager, text = "Del", command = del_login).grid(row = 12, column = 2)

Label(manager, text = "").grid(row = 13)

Button(manager, text = "Quit", command = quit).grid(row = 14, columnspan = 3, sticky = W+E)

bootloader.columnconfigure(0, weight = 1)
bootloader.columnconfigure(1, weight = 1)

manager.columnconfigure(0, weight = 1)
manager.columnconfigure(1, weight = 1)
manager.columnconfigure(2, weight = 1)

frame.add(manager, text = "Manager")

frame.pack(anchor = NW, expand = 1, fill = "both")

root.mainloop()