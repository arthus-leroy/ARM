#!/bin/python

from tkinter import Tk, StringVar, W, E
from tkinter.ttk import Notebook, Frame, Style, Label, Button, Entry
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showerror, showinfo
from threading import Thread
from serial import Serial
from math import ceil
from time import time

from nacl.hash import sha256
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder

from sys import argv

NO_ERR				= 0
ASSERT_ERR			= 1
DMA_LATE			= 2
CORRUPT				= 3
WRONG_SIGN			= 4
WRONG_PWD			= 5
LOGIN_NOT_EXISTS	= 6

MOD_MAST_PWD		= 1
SEND_KEY			= 2
SIGN				= 3
ADD_LOGIN			= 4
GET_LOGIN			= 5
DEL_LOGIN			= 6
QUIT				= 7

seed = "abcdefghijklmnopqrstuvwxyz012345".encode()
key = SigningKey(seed)

assert(len(argv) >= 3)
com = argv[1]
baud = int(argv[2])
ser = Serial(com, baud)

root = Tk()
root.title("UI")

def itob(num, size):
	return num.to_bytes(size, "little")

def read_serial(skip):
	while ser.in_waiting < 3:
		# in the rare cases it could receive only 1 or 2 bytes
		if skip():
			return None, None

	header = ser.read(3)
	length = header[0]

	t = time() * 1000
	while ser.in_waiting < length:
		# waiting 1 ms per byte max
		if time() * 1000 - t > length:
			return None, None

	args = ser.read(header[0])

	return header, args

answer_area = StringVar(root)
def process_serial(skip):
	while True:
		ser.reset_input_buffer()

		header, args = read_serial(skip)
		if header == None:
			continue

		err = header[2]
		if err == ASSERT_ERR:
			showerror("Assertion Error", args.decode())
		elif err == DMA_LATE:
			showerror("DMA error", "The DMA reception was hindered. Try again.")
		elif err == CORRUPT:
			showerror("Corrution error", "Sent message was corrupted. Try again.")
		elif err == WRONG_SIGN:
			showerror("Wrong hash", "Incorrect signature.")
		elif err == WRONG_PWD:
			showerror("Wrong password", "Wrong master password : %s." %master_password.get())
		elif err == LOGIN_NOT_EXISTS:
			showerror("Login does not exist", "The requested login does not exist")
		else:
			op = header[1]
			if op == MOD_MAST_PWD:
				showinfo("Info", "Master password changed")
				master_password.set(master_password_mod.get())
			elif op == SEND_KEY \
			  or op == SIGN:
				answer_area.set("".join("%02X" %a for a in args))
			elif op == ADD_LOGIN:
				showinfo("Info", "Added password")
			elif op == DEL_LOGIN:
				showinfo("Info", "Deleted password")
			elif op == GET_LOGIN:
				answer_area.set(args.decode())
			elif op == QUIT:
				showinfo("Info", "Returned to bootloader")
			else:
				print(args.decode())

bootloader_path = StringVar(root)
def send_bootloader():
	with open(bootloader_path.get(), "rb") as f:
		data = f.read()
		h = sha256(data, RawEncoder)
		ch = key.sign(h, RawEncoder).signature

		ser.write(itob(len(data), 4) + data + ch + h)

master_password = StringVar(root)
def send_tx_message(password, op, args):
	checksum = 0
	for a in args:
		checksum += a

	if password:
		master_pass = master_password.get().encode()
		ser.write(itob(len(args), 1) + itob(op, 1) \
			    + master_pass + args + itob(checksum, 1))
	else:
		ser.write(itob(len(args), 1) + itob(op, 1) \
				+ args + itob(checksum, 1))

master_password_mod = StringVar(root)
def modify_master_password():
	send_tx_message(1, MOD_MAST_PWD, master_password_mod.get().encode())

def send_key():
	send_tx_message(1, SEND_KEY, b'')

sign_file_path = StringVar(root)
def sign_file():
	send_tx_message(1, SIGN, sign_file_path.get().encode())

login = StringVar(root)
password = StringVar(root)
def add_login():
	login_pwd = login.get().encode() + b'\x00' \
			  + password.get().encode() + b'\x00'
	send_tx_message(1, ADD_LOGIN, login_pwd)

def get_login():
	login_tab = login.get().encode() + b'\x00'
	send_tx_message(1, GET_LOGIN, login_tab)

def del_login():
	login_tab = login.get().encode() + b'\x00'
	send_tx_message(1, DEL_LOGIN, login_tab)

def quit():
	send_tx_message(0, QUIT, b'')

def thread_stop():
	b = getattr(thread_stop, "bool")
	if b:
		setattr(thread_stop, "bool", False)

	return b

setattr(thread_stop, "bool", False)
Thread(target = process_serial, args = (thread_stop,), daemon = True).start()

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
Label(bootloader).grid(row = 4)
Label(bootloader, textvariable = answer_area, relief = "groove").grid(row = 5, columnspan = 3, sticky = W+E)
Label(bootloader, text = "").grid(row = 6)
Button(bootloader, text = "Flush input buffer", command = lambda: setattr(thread_stop, "bool", True)).grid(row = 7, sticky = W+E)
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

Label(manager, textvariable = answer_area, relief = "groove").grid(row = 14, columnspan = 3, sticky = W+E)

Button(manager, text = "Quit", command = quit).grid(row = 15, columnspan = 3, sticky = W+E)

bootloader.columnconfigure(0, weight = 1)
bootloader.columnconfigure(1, weight = 1)

manager.columnconfigure(0, weight = 1)
manager.columnconfigure(1, weight = 1)
manager.columnconfigure(2, weight = 1)
frame.add(manager, text = "Manager")

frame.pack(expand = 1, fill = "both")

root.mainloop()