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
DMA_ERROR			= 2
CORRUPT				= 3
WRONG_SIGN			= 4
INVALID_PROGRAM		= 5
WRONG_PWD			= 6
CANNOT_INSERT_LOGIN	= 7
LOGIN_NOT_EXISTS	= 8

MOD_MAST_PWD		= 1
SEND_KEY			= 2
SIGN				= 3
ADD_LOGIN			= 4
GET_LOGIN			= 5
DEL_LOGIN			= 6
QUIT				= 7

PUBLIC_KEY_SIZE			= 64
MASTER_PASSWORD_SIZE	= 32
# bootloader key
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

public_key_area = StringVar(root)
signature_area = StringVar(root)
def process_serial(skip):
	while True:
		ser.reset_input_buffer()

		header, args = read_serial(skip)
		if header == None:
			continue

		err = header[2]
		if err == ASSERT_ERR:
			showerror("Assertion Error", args.decode())
		elif err == DMA_ERROR:
			showerror("DMA error", "An error was encountered while transmitting the command. Try again.")
		elif err == CORRUPT:
			showerror("Corrution error", "Message was corrupted. Try again.")
		elif err == WRONG_SIGN:
			showerror("Wrong hash", "Incorrect signature.")
		elif err == INVALID_PROGRAM:
			showerror("Invalid program", "Stored program is invalid. Try sending it again.")
		elif err == WRONG_PWD:
			showerror("Wrong password", "Wrong master password : %s." %master_password.get())
		elif err == CANNOT_INSERT_LOGIN:
			showerror("Cannot insert login", "Couldn't insert login, there might not be any space left")
		elif err == LOGIN_NOT_EXISTS:
			showerror("Login does not exist", "The requested login does not exist")
		else:
			op = header[1]
			if op == MOD_MAST_PWD:
				master_password.set(master_password_mod.get())
				showinfo("Info", "Master password changed")
			elif op == SEND_KEY:
				key = "".join("%02X" %a for a in args)

				if len(key) == PUBLIC_KEY_SIZE:
					public_key_area.set(key)
				else:
					showerror("Corrupted key", "Key reception was corrupted")
			elif op == SIGN:
				signature_area.set("".join("%02X" %a for a in args))
			elif op == ADD_LOGIN:
				showinfo("Info", "Added password")
			elif op == DEL_LOGIN:
				showinfo("Info", "Deleted password")
			elif op == GET_LOGIN:
				showinfo("Password", "Password of %s : %s" %(login.get(), args.decode()))
			elif op == QUIT:
				showinfo("Info", "Returned to bootloader")
			else:
				print(args.decode(errors = "ignore"))

bootloader_path = StringVar(root)
def send_bootloader():
	try:
		with open(bootloader_path.get(), "rb") as f:
			data = f.read()
			h = sha256(data, RawEncoder)
			ch = key.sign(h, RawEncoder).signature

			ser.write(itob(len(data), 4) + data + ch + h)
	except:
		showerror("Cannot find file \"%s\"" %bootloader_path.get())

master_password = StringVar(root)
def send_tx_message(password, op, args):
	checksum = 0

	for a in args:
		checksum += a

	master_pass = master_password.get().encode() \
				+ b'0' * (MASTER_PASSWORD_SIZE - len(master_password.get()))
	p = master_pass if password else b''
	ser.write(itob(len(args), 4) + itob(op, 1) + p + args + itob(checksum & 0xFF, 1))

master_password_mod = StringVar(root)
def modify_master_password():
	send_tx_message(1, MOD_MAST_PWD, master_password_mod.get().encode())

def send_key():
	send_tx_message(0, SEND_KEY, b'')

sign_file_path = StringVar(root)
def sign_file():
	try:
		with open(sign_file_path.get().encode(), "rb") as f:
			send_tx_message(1, SIGN, f.read())
	except:
		showerror("Cannot find file \"%s\"" %sign_file_path.get())

login = StringVar(root)
password = StringVar(root)
def add_login():
	if len(login.get()) > 255 or len(password.get()) > 255:
		showerror("Password and login must be 255 characters max")
		return

	login_pwd = login.get().encode() + b'\x00' \
			  + password.get().encode() + b'\x00'
	send_tx_message(1, ADD_LOGIN, login_pwd)

def get_login():
	if len(login.get()) > 255:
		showerror("Password and login must be 255 characters max")
		return

	login_tab = login.get().encode() + b'\x00'
	send_tx_message(1, GET_LOGIN, login_tab)

def del_login():
	if len(login.get()) > 255:
		showerror("Password and login must be 255 characters max")
		return

	login_tab = login.get().encode() + b'\x00'
	send_tx_message(1, DEL_LOGIN, login_tab)

def quit():
	send_tx_message(0, QUIT, b'')

def thread_skip():
	b = getattr(thread_skip, "bool")
	if b:
		setattr(thread_skip, "bool", False)

	return b

setattr(thread_skip, "bool", False)
Thread(target = process_serial, args = (thread_skip,), daemon = True).start()

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
Label(bootloader, text = "").grid(row = 5)
Button(bootloader, text = "Flush input buffer", command = lambda: setattr(thread_skip, "bool", True)).grid(row = 6, sticky = W+E)
frame.add(bootloader, text = "Bootloader")

manager = Frame(frame)
Label(manager, text = "Master password : ").grid(row = 0, column = 0, sticky = W)
Entry(manager, textvariable = master_password).grid(row = 0, column = 1, columnspan = 2, sticky = W+E)

Label(manager, text = "").grid(row = 1)

Label(manager, text = "Modify master password:").grid(row = 2, column = 0, sticky = W)
Entry(manager, textvariable = master_password_mod).grid(row = 3, column = 0, columnspan = 2, sticky = W+E)
Button(manager, text = "Modify", command = modify_master_password).grid(row = 3, column = 2)

Label(manager, text = "").grid(row = 4)

Button(manager, text = "Send public key", command = send_key).grid(row = 5, column = 0, sticky = W)
Entry(manager, textvariable = public_key_area).grid(row = 5, column = 1, columnspan = 2, sticky = W+E)

Label(manager, text = "").grid(row = 6)

Label(manager, text = "Sign file:").grid(row = 7, sticky = W)
Label(manager, textvariable = sign_file_path, relief = "groove").grid(row = 8, column = 0, columnspan = 2, sticky = W+E)
Button(manager, text = "...", command = lambda: sign_file_path.set(askopenfilename())).grid(row = 8, column = 2)
Button(manager, text = "Sign", command = sign_file).grid(row = 9, column = 0, sticky = W)
Entry(manager, textvariable = signature_area).grid(row = 9, column = 1, columnspan = 2, sticky = W+E)

Label(manager, text = "").grid(row = 10)

Label(manager, text = "Login:").grid(row = 11, column = 0, sticky = W)
Label(manager, text = "Password:").grid(row = 11, column = 1, sticky = W)
Entry(manager, textvariable = login).grid(row = 12, column = 0, sticky = W+E, padx = (0, 15))
Entry(manager, textvariable = password).grid(row = 12, column = 1, sticky = W+E)
Button(manager, text = "Add", command = add_login).grid(row = 13, column = 0)
Button(manager, text = "Get", command = get_login).grid(row = 13, column = 1)
Button(manager, text = "Del", command = del_login).grid(row = 13, column = 2)

Label(manager, text = "").grid(row = 14)

Button(manager, text = "Quit", command = quit).grid(row = 15, columnspan = 3, sticky = W+E)

bootloader.columnconfigure(0, weight = 1)
bootloader.columnconfigure(1, weight = 1)

manager.columnconfigure(0, weight = 1)
manager.columnconfigure(1, weight = 1)
manager.columnconfigure(2, weight = 1)
frame.add(manager, text = "Manager")

frame.pack(expand = 1, fill = "both")

root.mainloop()