from encodings import search_function
from multiprocessing import Value
from tkinter import *
from tkinter import messagebox
import os, json
from tkinter import font
from turtle import width
import PySide6.QtCore
import base64, binascii, pefile  
from Crypto.Cipher import AES
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from secrets import token_bytes
from tkinter import ttk
import pyperclip
import hashlib

def xor_crypt_string(data, key = 'awesomepassword', encode = False, decode = False):
    from itertools import cycle   
    if decode:
        data = data
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, cycle(key)))
   
    if encode:
        return xored
    return xored

def copy_value(value):

    xor = xor_crypt_string(value, decode=True)
    messagebox.showinfo("Copy info", "Value coppied.")

def copy_from_treeview(tree, event):
    selection = tree.selection()
    column = tree.identify_column(event.x)
    column_no = int(column.replace("#", "")) - 1
            
    copy_values = []
    for each in selection:
        try:
            value = tree.item(each)["text"]
            copy_values.append(str(value))
        except:
            pass
        
    username,password = xor_crypt_string(copy_values[0].split(':')[0], decode=True), xor_crypt_string(copy_values[0].split(':')[1], decode=True)
    print(f'{username}:{password}')
    pyperclip.copy(f'{username}:{password}')
    messagebox.showinfo("Copy info", "Values coppied.")


def login_func():
    password = passField.get()
    password = hashlib.md5(password.encode())
    pass_hash = password.hexdigest()
    if pass_hash == '63a9f0ea7bb98050796b649e85481845':
        print('correct')
        frame.place_forget()
        initMenu()
    else:
        messagebox.showerror("Error", "Password not correct.")

#for i in tree.get_children():
#    tree.delete(i)
def initMenu():
    # plus = Frame(accountsFrame,width=600, height=50, bg='grey')
    # plusbutton = Button(plus, text='+')
    # plusbutton.pack()
    # plus.grid(column=0,row=0)



    # with open('accounts.json', 'r') as r:
    #     plaintext = r.read()
    # accounts = json.loads(plaintext)
    # for i in accounts:
    #     accounts[i]['username'] =  xor_crypt_string(accounts[i]['username'], encode = True)
    #     print(accounts[i]['username'])

    #     accounts[i]['password'] = xor_crypt_string(accounts[i]['password'], encode = True)
        
    #     print(accounts[i]['password'],'\n\n')
    # with open('accounts.json', 'w') as r:
    #     json.dump(accounts, r) 
    # # 
    # with open('accounts.json', 'r') as r:
    #     data = r.read()
    key = b'\x9f,\xc0\xed\xe4#p\xa2V\xee\xe1r(\x9d9\x19' #must be 16, 24 or 32 bytes long    
    # data = bytes(data, 'utf-8')
    # cipher = AES.new(key, AES.MODE_EAX)
    # ciphertext, tag = cipher.encrypt_and_digest(data)

    # file_out = open("encryptedfile.bin", "wb")
    # [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    # file_out.close()
    file_in = open("encryptedfile.bin", "rb")
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    print(data)
    accounts = json.loads(data)
    
    # for i in accounts:
    #     r = Frame(accountsFrame,width=100,height=80,bg='#b00b69', border=2, highlightbackground="black" )
    #     website = Label(r, text=accounts[i]['website'], font=100)
    #     website.grid(row=0,column=0)
    #     username = Button(r, text='***********', font=100, command= lambda : copy_value(accounts[i]['username']))
    #     username.grid(row=0,column=1)
    #     password = Button(r, text='***********', font=100, command=lambda : copy_value(accounts[i]['password']))
    #     password.grid(row=0,column=2)
    #     r.pack() # or .grid(...)

    style = ttk.Style()
    style.configure("mystyle.Treeview",
        rowheight=25
    )
    tv = ttk.Treeview(accountsFrame, style="mystyle.Treeview")
    
    tv['columns']=('Rank', 'Name', 'Badge')
    # tv.bind('<Button-3>', popup_menu)
    tv.bind("<Button-3>", lambda x: copy_from_treeview(tv, x))
    tv.column('#0', width=0, stretch=NO)
    tv.column('Rank', anchor=CENTER, width=80)
    tv.column('Name', anchor=CENTER, width=80)
    tv.column('Badge', anchor=CENTER, width=80)

    tv.heading('#0', text='', anchor=CENTER)
    tv.heading('Rank', text='Website', anchor=CENTER)
    tv.heading('Name', text='Username', anchor=CENTER)
    tv.heading('Badge', text='Password', anchor=CENTER)
    tv.configure(height=10)
    for i in accounts:
        website = accounts[i]['website']
        username=accounts[i]['username']
        password=accounts[i]['password']
        tv.insert(parent='', index=i, iid=i, text=f'{username}:{password}', values=(website,'***********','***********'))
    # tv.grid(column=0, row=1,columnspan=3)
    tv.pack(side=TOP,fill=X)
    search = Frame(accountsFrame)
    searchField = Entry(search)
    searchField.pack(side=LEFT,fill=BOTH, expand=True)
    searchbutton = Button(search, text='search', bg='white',command=lambda : search_func(searchField.get(), accounts,tv))
    searchbutton.pack(side=RIGHT, pady=2)
    
    search.pack(side=BOTTOM, expand=True, fill=X)
def comm():
    return
def popup_menu(event):
    tv.identify_row(event.y)
    popup1.post(event.x_root, event.y_root)
def search_func(filter, accounts,tv):
    for i in tv.get_children():
        tv.delete(i)
    if (filter==''):
        for i in accounts:
            website = accounts[i]['website']
            username = accounts[i]['username']
            password = accounts[i]['password']
            # tv.insert(parent='', index=i, iid=i, text='okay', values=(website,'***********','***********'))
            tv.insert(parent='', index=i, iid=i, text=f'{username}:{password}', values=(website,'***********','***********'))
    else:
        for i in accounts:
            if (accounts[i]['website'].find(filter) != -1):
                username = accounts[i]['username']
                password = accounts[i]['password']
                website = accounts[i]['website']
                tv.insert(parent='', index=i, iid=i, text=f'{username}:{password}', values=(website,'***********','***********'))

def your_copy():
    item = tv.selection()
    print(item)



# инициализация родительского окна

root = Tk()
root.geometry('600x350')

# запуск дебагера "спутника" для защиты от отладки
myProcess = PySide6.QtCore.QProcess()
myProcess.start("DebugProtector.exe", [f'{os.getpid()}'])
print('pid is', os.getpid())
pe = pefile.PE('PassManager.exe') # pe = pefile.PE(main.exe)

# вычисление хэша, 1ый аргумент - содержимое сегмента .text, второй - метод вычисления хэша
current_hash = PySide6.QtCore.QCryptographicHash.hash(pe.sections[0].get_data(), PySide6.QtCore.QCryptographicHash.Sha3_256) 
current_hash = current_hash.toBase64() # текущий хэш
hash = b'y9E0f5w5v15zIGud7QktbePEeeVfOwtrXL1p5Wa8MQA=' # эталонный хэш
print('current_hash is', current_hash)
if (hash == current_hash): # сравнение хэша
    print('ok')
else:
    messagebox.showerror("Error", "Application was modificated")
    root.destroy()



print(str(len(pe.sections[0].get_data()))) # первый сегмент - сегмент .text
for section in pe.sections:
    print('Section Name: ' + str(section.Name))

# Описание структуры приложения
accountsFrame = Frame(root)

accountsFrame.place(relx=0, rely=0, relwidth=1, relheight=1)
frame = Frame(accountsFrame)
frame.place(relx=0, rely=0, relwidth=1, relheight=1)
loginFrame = Frame(frame)
loginFrame.place(relx=0.4, rely=0.4, relwidth=0.15, relheight=0.15)
title = Label(loginFrame, text="Введите пароль")
title.pack()
passField = Entry(loginFrame, show='*')
passField.pack()
btn = Button(loginFrame, text='Войти', command=login_func)
tv = ttk.Treeview(accountsFrame, style="mystyle.Treeview")
popup1 = Menu(tv, tearoff=0)
popup1.add_command(
    command=your_copy,
    label="Copy")

btn.pack()
root.mainloop()