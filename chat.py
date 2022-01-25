#imports
import socket
import os.path
from threading import Thread
from datetime import datetime
from colorama import Fore, init, Back
import json
from hashlib import sha256
import base64
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random

#defs
def sendverify(usermail, usercode): # <- make sure u enabled less secured apps
    sender_email = "" #support email
    receiver_email = usermail

    message = MIMEMultipart("alternative")
    message["Subject"] = f"SimpleMessenger Verification: {usercode}"
    message["From"] = sender_email
    message["To"] = receiver_email

    text = f"""\
    Hello {name}!
    Your SimpleMessenger verification code is {usercode}

    If you never used this mail on SimpleMessenger ignore this mail.
    """
    part1 = MIMEText(text, "plain")

    message.attach(part1)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, "password of the mail")
        server.sendmail(
            sender_email, receiver_email, message.as_string()
        )
def secondpass(uname):
    global password
    print(f"\n"*200)
    print("LOGIN")
    print(f"Username: {uname}")
    password = input("Password: ")
    if truepassw == crypt(password):
        if isbanned == "true":
            print("\nYour account is banned")
            input()
            exit()
        if isbanned == "false":
            if lastip != newip:
                print("\n"*200)
                print("OOPS! You connected from another ip-address, please enter your 2FA code:")
                ask2fa = input("> ")
                if crypt(ask2fa) != crypt(check["2fa"]):
                    print("Incorrect 2fa code")
                    input()
                    exit()
                
                else:
                    check["ip"] = newip
                    savedb()
                    print("\n"*200)
                    print(f"Welcome, {name}")
                    print("Made by HTechnologies")
                    print(f"\nYour roles:\nAdmin: {check['isadmin']}\nDeveloper: {check['developer']}")
                    pass
            else:
                print("\n"*200)
                print(f"Welcome, {name}")
                print("Made by HTechnologies")
                print(f"\nYour roles:\nAdmin: {check['isadmin']}\nDeveloper: {check['developer']}")
                pass
        
    else:
        print("[-] Wrong data, forgot password? [y/n]")
        ask = input("> ")
        if ask == "y":
            print("[?] Please enter your mail\nIf you have not added mail write '2'")
            secask = input("> ")
            if secask == "2":
                print("[?] Enter your 2fa code")
                thecode = input("> ")
                if check["2fa"] == crypt(thecode):
                    print("[+] Enter new password")
                    newpass = input("> ")
                    check["password"] = crypt(newpass)
                    savedb()
                    print("[+] Changed password")
                    pass
                else:
                    print("[-] Wrong 2fa code")
                    input()
                    exit()
            else:
                if check["mail"] == secask: 
                    gencode = random.randint(1111, 9999)
                    sendverify(usermail=secask,usercode=gencode)
                    print(f"[~] Sent message with verification code to your mail({secask})")
                    print("[?] Enter code")
                    xthecode = int(input("> "))
                    if xthecode == gencode:
                        print("[?] Enter new password")
                        newpass = input("> ")
                        check["password"] = crypt(newpass)
                        savedb()
                        print("[+] Changed password")
                        pass
                    else:
                        print("[-] Wrong code")
                        input()
                        exit()
                elif secask == "":
                    print("[-] Wrong mail")
                    input()
                    exit()
                else:
                    print("[-] Wrong mail")
                    input()
                    exit()
        else:
            secondpass(uname=f"{name}")
def crypt(txt):
    sha = sha256(str(txt).encode('utf-8')).hexdigest()
    done = base64.b64encode(sha.encode('UTF-8')).decode('UTF-8')
    return done
def decrypt(txt):
    done = base64.b64decode(txt.decode('UTF-8')).decode('UTF-8')
    return done

Main = False

init()

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5002 
separator_token = "<SEP>" 


s = socket.socket()
print(f"[*] Connecting to the servers...")

try:
    s.connect((SERVER_HOST, SERVER_PORT))
except:
    print("[!] The servers are down")
    input()
    exit()
print("[+] Connected")
hostname = socket. gethostname()
IPAddr = socket. gethostbyname(hostname)

#log/reg
startin = input("Login/Register\n> ")
if startin == "login":
    print("LOGIN")
    name = input("Username: ")
    password = input("Password: ")
if startin == "register":
    print("REGISTER")
    name = input("Username: ")
    password = input("Password: ")
    regpassword = crypt(txt=password)
    auth2 = input("2FA code: ")
    regauth2 = crypt(txt=auth2)
    if os.path.exists(f"accounts/{name}.json"):
        print(f"Account with name '{name}' already exists.")
        input()
        exit()
    else:
        if name == "humanot":
            idiotic = """
    {"password": '"""+ regpassword +"""', "isbanned": "false", "isadmin": "true", "developer": "true", "ip": '"""+ crypt(IPAddr) +"""', "2fa": '"""+ regauth2 +"""', "mail": '""" + "" + """'}
    """
            with open(f'accounts/{name}.json', 'w+') as f: 
                f.write(idiotic.replace("'", """""" + '"' + """"""))
                f.close()
        else:
            idiotic = """
    {"password": '"""+ regpassword +"""', "isbanned": "false", "isadmin": "false", "developer": "false", "ip": '"""+ crypt(IPAddr) +"""', "2fa": '"""+ regauth2 +"""', "mail": '""" + "" + """'}
    """
            with open(f'accounts/{name}.json', 'w+') as f: 
                f.write(idiotic.replace("'", """""" + '"' + """"""))
                f.close()   

#open db
try:
    with open(f'accounts/{name}.json') as f:
        check = json.load(f)
except:
    print(f"[-] No account with username {name}")
    input()
    exit()

#strs
truepassw = check["password"]
isbanned = check["isbanned"]
lastip = check["ip"]
newip = crypt(IPAddr)

#saves db
def savedb():
    with open(f'accounts/{name}.json', 'w+') as f:
        json.dump(check, f)

#pass verify
if truepassw == crypt(password):
    if isbanned == "true":
        print("\nYour account is banned")
        input()
        exit()
    if isbanned == "false":
        if lastip != newip:
            print("\n"*200)
            print("OOPS! You connected from another ip-address, please enter your 2FA code:")
            ask2fa = input("> ")
            if crypt(ask2fa) != crypt(check["2fa"]):
                print("Incorrect 2fa code")
                input()
                exit()
            
            else:
                check["ip"] = newip
                savedb()
                print("\n"*200)
                print(f"Welcome, {name}")
                print("Made by HTechnologies")
                print(f"\nYour roles:\nAdmin: {check['isadmin']}\nDeveloper: {check['developer']}")
                pass
        else:
            print("\n"*200)
            print(f"Welcome, {name}")
            print("By humanot#1337 - https://discord.gg/xCHSTKJA5H")
            print(f"\nYour roles:\nAdmin: {check['isadmin']}\nDeveloper: {check['developer']}")
            pass
else:
    print("[-] Wrong data, forgot password? [y/n]")
    ask = input("> ")
    if ask == "y":
        print("[?] Please enter your mail\nIf you have not added mail write '2'")
        secask = input("> ")
        if secask == "2":
            print("[?] Enter your 2fa code")
            thecode = input("> ")
            if check["2fa"] == crypt(thecode):
                print("[+] Enter new password")
                newpass = input("> ")
                check["password"] = crypt(newpass)
                savedb()
                print("[+] Changed password")
                pass
            else:
                print("[-] Wrong 2fa code")
                input()
                exit()
        else:
            if check["mail"] == secask: 
                gencode = random.randint(1111, 9999)
                sendverify(usermail=secask,usercode=gencode)
                print(f"[~] Sent message with verification code to your mail({secask})")
                print("[?] Enter code")
                xthecode = int(input("> "))
                if xthecode == gencode:
                    print("[?] Enter new password")
                    newpass = input("> ")
                    check["password"] = crypt(newpass)
                    savedb()
                    print("[+] Changed password")
                    pass
                else:
                    print("[-] Wrong code")
                    input()
                    exit()
            elif secask == "":
                print("[-] Wrong mail")
                input()
                exit()
            else:
                print("[-] Wrong mail")
                input()
                exit()
    else:
        secondpass(uname=f"{name}")

#role-color
if check["isadmin"] == "true":
    if check["developer"] == "true":
        client_color = Fore.RED
        rank = "DEV"
    else:
        client_color = Fore.GREEN
        rank = "ADMIN"
else:
    client_color = Fore.WHITE
    rank = "USER"

def listen_for_messages():
    while True:
        try:
            message = s.recv(1024).decode()
        except:
            break
        
        if message == "/reconnect":
            break
        if message == "":
            break
        else:
            print("\n" + message)

t = Thread(target=listen_for_messages)

t.daemon = True

t.start()

def savebanned(name):
    with open(f'accounts/{name}.json', 'w+') as f:
        json.dump(tobandata, f)

while True:
    onaskmsg = input("")
    print(f"""\033[A{" " * len(onaskmsg)}\033[A""")
    if onaskmsg == "/ban":
        if check["isadmin"] == "true":
            toban = input("enter name to ban: ")
            with open(f'accounts/{toban}.json') as f:
                tobandata = json.load(f)
                thetrue = "true"
                tobandata["isbanned"] = thetrue
                savebanned(name=toban)
                print(f"[!] Banned {toban}")
                date_now = datetime.now().strftime('%Y-%m-%d/%H:%M:%S') 
                to_send = f"[{date_now}] Global-System-Message:\n{Fore.LIGHTRED_EX}{toban} has been BANNED by [{rank}]{name}.{Fore.RESET}"
                s.send(to_send.encode())
        if check["isadmin"] == "false":
            print("[-] You must be admin to perfom that action.")
            #break
    if onaskmsg == "/help":
        if check["isadmin"] == "true":
            if check["developer"] == "true":
                print("/demote, /giveadmin, /givedev, /ban, /unban, /reconnect, /changepassword, /mail")
            else:
                print("/ban, /unban, /reconnect, /changepassword, /mail")
        else:
            print("/reconnect, /changepassword, /mail")
    if onaskmsg == "/unban":
        if check["isadmin"] == "true":
            toban = input("enter name to unban: ")
            with open(f'accounts/{toban}.json') as f:
                tobandata = json.load(f)
                thetrue = "false"
                tobandata["isbanned"] = thetrue
                savebanned(name=toban)
                print(f"[!] Un-Banned {toban}")
                date_now = datetime.now().strftime('%Y-%m-%d/%H:%M:%S') 
                to_send = f"[{date_now}] Global-System-Message:\n{Fore.LIGHTRED_EX}{toban} has been UN-BANNED by [{rank}]{name}.{Fore.RESET}"
                s.send(to_send.encode())
                
        if check["isadmin"] == "false":
            print("[-] You must be admin to perfom that action.")
            #break
    if onaskmsg == "/demote":
        if check["developer"] == "true":
            toban = input("enter name to demote: ")
            with open(f'accounts/{toban}.json') as f:
                tobandata = json.load(f)
                thetrue = "false"
                tobandata["isadmin"] = thetrue
                tobandata["developer"] = thetrue
                savebanned(name=toban)
                print(f"[!] Demoted {toban}")
                date_now = datetime.now().strftime('%Y-%m-%d/%H:%M:%S') 
                to_send = f"[{date_now}] Global-System-Message:\n{Fore.LIGHTRED_EX}{toban} has been DEMOTED by [{rank}]{name}.{Fore.RESET}"
                s.send(to_send.encode())
        if check["developer"] == "false":
            print("[-] You must be developer to perfom that action.")
            #break
    if onaskmsg == "/givedev":
        if check["developer"] == "true":
            toban = input("enter name to give developer: ")
            with open(f'accounts/{toban}.json') as f:
                tobandata = json.load(f)
                thetrue = "true"
                tobandata["developer"] = thetrue
                savebanned(name=toban)
                print(f"[!] Gave developer to {toban}")
                date_now = datetime.now().strftime('%Y-%m-%d/%H:%M:%S') 
                to_send = f"[{date_now}] Global-System-Message:\n{Fore.LIGHTRED_EX}{toban} recieved DEVELOPER from [{rank}]{name}.{Fore.RESET}"
                s.send(to_send.encode())
        if check["developer"] == "false":
            print("[-] You must be developer to perfom that action.")
            #break
    if onaskmsg == "/giveadmin":
        if check["developer"] == "true":
            toban = input("enter name to give admin: ")
            with open(f'accounts/{toban}.json') as f:
                tobandata = json.load(f)
                thetrue = "true"
                tobandata["isadmin"] = thetrue
                savebanned(name=toban)
                print(f"[!] Gave admin to {toban}")
                date_now = datetime.now().strftime('%Y-%m-%d/%H:%M:%S') 
                to_send = f"[{date_now}] Global-System-Message:\n{Fore.LIGHTRED_EX}{toban} recieved ADMIN from [{rank}]{name}.{Fore.RESET}"
                s.send(to_send.encode())
        if check["developer"] == "false":
            print("[-] You must be developer to perfom that action.")
            #break
    if onaskmsg == "/reconnect":
        s.close()
        s.connect(SERVER_HOST, SERVER_PORT)
    if onaskmsg == "/mail":
        print("[?] Enter your mail")
        themail = input("> ")
        gencode = random.randint(1111, 9999)
        sendverify(usermail=themail,usercode=gencode)
        print("[~] Sent message with verification code to your mail")
        print("[?] Enter code")
        xthecode = int(input("> "))
        if xthecode != gencode:
            print("[-] Incorrect code")
            pass
        else:
            print("[+] Correct code")
            check["mail"] = themail
            savedb()
            print(f"[+] Added {themail} as your account email")
    if onaskmsg == "/changepassword":
        print("[?] Enter your password")
        writepass = input("> ")
        if crypt(writepass) == check["password"]:
            print("[?] Enter new password")
            newpass = input("> ")
            check["password"] = crypt(newpass)
            savedb()
            print("[+] Changed password")
        else:
            print("[-] Wrong password")

    if onaskmsg.startswith("  "):
        pass
    if onaskmsg == "":
        pass

    if onaskmsg.startswith('/reconnect'):
        break

    date_now = datetime.now().strftime('%Y-%m-%d/%H:%M:%S') 
    to_send = f"\n{client_color}[{rank}] {name}{separator_token}{onaskmsg}{Fore.RESET}"
    try:
        blacklist = [""," ","  "]
        if onaskmsg not in blacklist and len(onaskmsg) < 100:
            s.send(to_send.encode())
        if len(onaskmsg) > 100:
            print(f"[-] You used {len(onaskmsg)}/100 symbols")
            pass
        else:
            pass
    except:
        pass

s.close()
