#!/usr/bin/env python3

# IMPORTANT
# This is version 'dev1.0.0' of the LogProbe COLLECTION_API
# This code is not optimized but works and is the current version to use

# IMPORTING LIBRARIES
# ----------------------------------------------------------------
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from pymongo import MongoClient
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from configparser import ConfigParser
import secrets, re, hashlib, os, random, smtplib, uvicorn, schedule, datetime, asyncio
# ----------------------------------------------------------------


# CONFIG SETTINGS INITIALIZATION
# ----------------------------------------------------------------
config = ConfigParser()
config.read("config.ini")
config_app = config["API"]
config_mail = config["MAIL"]
config_schedule = config["SCHEDULE"]
config_sql = config["SQL"]
config_mongo = config["NOSQL"]
# ----------------------------------------------------------------

# FASTAPI APP INITIALIZATION
# ----------------------------------------------------------------
app = FastAPI()
app.add_middleware(HTTPSRedirectMiddleware)
# ----------------------------------------------------------------

# SQLALCHEMY TABLE BASE INITIALIZATION
# ----------------------------------------------------------------
Base = declarative_base()
# ----------------------------------------------------------------


# CUSTOM ERRORS INITIALIZATION
class InvalidConfiguration(Exception): ...


# CLASS: UTILITIES
class Utils:

    # SQL DATABASE TABLES
    # ----------------------------------------------------------------
    class Waitlist(Base):
        __tablename__ = 'waitlist'
        id = Column(Integer, primary_key=True, autoincrement=True)
        key = Column(String(length=100), nullable=False, unique=True)
        sid = Column(String(length=100), nullable=False, unique=True)
        pwd = Column(String(length=100), nullable=False)
        salt = Column(String(length=100), nullable=False)

        def __init__(self, key, sid, pwd, salt) -> None:
            self.key = key
            self.sid = sid
            self.pwd = pwd
            self.salt = salt
        
        def __repr__(self) -> str:
            return f"({self.id}, {self.key})\n{self.sid} / (WAITLIST)\nPassword: {self.pwd}\nSalt: {self.salt}"

    class Registered(Base):
        __tablename__ = 'registered'
        id = Column(Integer, primary_key=True, autoincrement=True)
        key = Column(String(length=100), nullable=False, unique=True)
        sid = Column(String(length=100), nullable=False, unique=True)
        pwd = Column(String(length=100), nullable=False)
        salt = Column(String(length=100), nullable=False)

        def __init__(self, key, sid, pwd, salt) -> None:
            self.key = key
            self.sid = sid
            self.pwd = pwd
            self.salt = salt
        
        def __repr__(self) -> str:
            return f"({self.id}, {self.key})\n{self.sid} / (REGISTERED)\nPassword: {self.pwd}\nSalt: {self.salt}"

    class Admins(Base):
        __tablename__ = 'admins'
        id = Column(Integer, primary_key=True, autoincrement=True)
        sid = Column(String(length=100), nullable=False, unique=True)
        key = Column(String(length=100), nullable=False, unique=True)
        role = Column(String(length=100), nullable=False)
        email = Column(String(length=100), nullable=False)
        pwd = Column(String(length=100), nullable=False)
        salt = Column(String(length=100), nullable=False)

        def __init__(self, sid, key, role, email, pwd, salt) -> None:
            self.sid = sid
            self.key = key
            self.role = role
            self.email = email
            self.pwd = pwd
            self.salt = salt
        
        def __repr__(self) -> str:
            return f"({self.id}, {self.key})\n{self.sid} / {self.role}, (ADMIN)\nPassword: {self.pwd}\nSalt: {self.salt}"
    # ----------------------------------------------------------------

    # MAIL HANDLER FUNCTIONS
    # ----------------------------------------------------------------
    @dataclass
    class Mail:
        smtp: str
        port: int
        s_mail: str
        s_pwd: str
        rc_mail: str
        sbj: str
        body: str

    @staticmethod
    def generate_styled_html_body(text) -> str:
        lines = text.split('\n')
        main_title = lines[0]
        details = lines[1:]
        
        main_title_html = f'<h1 style="text-align: center; background-color: black; color: white; padding: 10px; font-family: Roboto;">{main_title}</h1>'
        
        details_html = ''
        for detail in details:
            title, content = detail.split(": ")
            details_html += f'<h3 style="background-color: #e0f2f1; padding: 5px; font-family: Roboto;">{title}</h3><p>{content}</p>'
        
        final_html = f'''
    <html>
    <head>
        <style>
        body {{
            font-family: Roboto, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            padding: 20px;
        }}
        </style>
    </head>
    <body>
        <div class="container">
        {main_title_html}
        {details_html}
        </div>
    </body>
    </html>
    '''
        return final_html

    @staticmethod
    def send_email(mail: Mail) -> bool:
        try:
            msg = MIMEMultipart()
            msg['From'] = mail.s_mail
            msg['To'] = mail.rc_mail
            msg['Subject'] = mail.sbj
            msg.attach(MIMEText(Utils.generate_styled_html_body(mail.body), 'html'))
            server = smtplib.SMTP(mail.smtp, mail.port)
            server.starttls()
            server.login(mail.s_mail, mail.s_pwd)
            server.sendmail(mail.s_mail, mail.rc_mail, msg.as_string())
            server.quit()
            return True
        except: return False
    # ----------------------------------------------------------------

    # PASSWORD HASH HANDLER FUNCTIONS
    # ----------------------------------------------------------------
    @staticmethod
    def generate_salt() -> str:
        return os.urandom(random.randint(16, 32)).hex()

    @staticmethod
    def CHAROT_X(plain, base, isCipher=False) -> str:
        if isCipher:
            base *= -1
        return str(''.join([chr(ord(d)+base) for d in list(plain)]))

    @staticmethod
    def generate_hash(pwd, salt=None) -> tuple[str, str]:
        base = len(pwd)
        if salt is None:
            salt = Utils.generate_salt()
        h_pwd = hashlib.sha256((pwd+salt).encode('utf8')).hexdigest()
        charot_salt = Utils.CHAROT_X(salt, base)
        f_pwd = hashlib.sha256((h_pwd[:base]+charot_salt+h_pwd[base:]).encode('utf8'))
        return f_pwd.hexdigest(), charot_salt

    @staticmethod
    def compare_hash(pwd, r_salt, h_pwd) -> bool:
        salt = Utils.CHAROT_X(r_salt, len(pwd), isCipher=True)
        n_pwd, n_salt = Utils.generate_hash(pwd, salt=salt)
        if n_pwd == h_pwd and n_salt == r_salt:
            return True
        return False
    # ----------------------------------------------------------------

    # API HANDLER FUNCTIONS
    # ----------------------------------------------------------------
    @staticmethod
    def generate_api_token() -> str:
        return secrets.token_urlsafe(24)

    @staticmethod
    def hash_api_token(token) -> str:
        return hashlib.sha256(token.encode('utf8')).hexdigest()
    # ----------------------------------------------------------------

    # ELEMENT VALIDATION FUNCTIONS
    # ----------------------------------------------------------------
    @staticmethod
    def is_valid_sid(sid) -> bool:
        return re.match(r"^[a-zA-Z0-9]{5,20}$", sid)

    @staticmethod
    def is_valid_pwd(pwd) -> bool:
        # Password Policy:
        # - At least one digit (0-9) is required.
        # - At least one special character from the set [!@#$%^&*(),.?":{}|<>] is required.
        # - The password must be at least 8 characters in length.
        # - The password can contain alphanumeric characters and specific special characters.
        return re.match(r"^(?=.*[0-9])(?=.*[!@#$%^&*(),.?\":{}|<>])(?=.{8,})[a-zA-Z0-9!@#$%^&*(),.?\":{}|<>]+$", pwd)

    @staticmethod
    def is_valid_action(action) -> bool:
        return action in ["confirm", "delete"]

    @staticmethod
    def is_valid_uid(uid) -> bool:
        return isinstance(uid, int) and uid > 0

    @staticmethod
    def is_valid_filename(filename) -> bool:
        return bool(re.match(r'^[^<>:"/\\|?*\x00-\x1F]*\.log$', filename, re.IGNORECASE))

    @staticmethod
    def is_valid_upload(upload) -> bool:
        fileset = set()
        if not isinstance(upload, dict) and upload != {}:
            return False
        for file_name in upload:
            if (not isinstance(upload[file_name], str)) or (not Utils.is_valid_filename(file_name)):
                return False
            fileset.add(file_name)
        if len(fileset) != len(upload):
            return False
        return True
    # ----------------------------------------------------------------

    # REQUEST VALIDATION FUNCTIONS
    # ----------------------------------------------------------------
    @staticmethod
    def validate_register_data(data) -> bool:
        if not all(key in data for key in ["sid", "pwd"]):
            return False
        if not Utils.is_valid_sid(data["sid"]):
            return False
        if not Utils.is_valid_pwd(data["pwd"]):
            return False
        return True

    @staticmethod
    def validate_confirm_data(data) -> bool:
        if not all(key in data for key in ["key", "action", "r_pwd", "uid"]):
            return False
        if not Utils.is_valid_action(data["action"]):
            return False
        if not Utils.is_valid_pwd(data["r_pwd"]):
            return False
        if not Utils.is_valid_uid(data["uid"]):
            return False
        return True

    @staticmethod
    def validate_upload_data(data) -> bool:
        if not all(key in data for key in ["key","files", "pwd"]):
            return False
        if not Utils.is_valid_pwd(data["pwd"]):
            return False
        if not Utils.is_valid_upload(data["files"]):
            return False
        return True
    # ----------------------------------------------------------------


# CLASS: REPORTER
class Reporter:
    # SCHEDULE WRAPPER FUNCTION
    # ----------------------------------------------------------------
    @staticmethod
    def get_scheduled_wrapper():
        try:
            days = {
                "monday": schedule.every().monday,
                "tuesday": schedule.every().tuesday, 
                "wednesday": schedule.every().wednesday, 
                "thursday": schedule.every().thursday, 
                "friday": schedule.every().friday, 
                "saturday": schedule.every().saturday, 
                "sunday": schedule.every().sunday
            }

            scope = config_schedule["scope"]
            hour = int(config_schedule["hour"])
            minute = int(config_schedule["minute"])
            if hour > 23 or hour < 0:
                raise InvalidConfiguration("'hour' configured value is out of scope.")
            if minute > 59 or minute < 0:
                raise InvalidConfiguration("'minute' configured value is out of scope.")
            scheduled_time = ":".join([str(hour).zfill(2), str(minute).zfill(2)])
            print(scheduled_time)
            match scope:
                case "daily":
                    def wrapper(func):
                        return schedule.every().day.at(scheduled_time).do(func)
                    return wrapper
                case "weekly":
                    day = config_schedule["day"]
                    if day in days:
                        def wrapper(func):
                            return days[day].at(scheduled_time).do(func)
                        return wrapper
                    raise InvalidConfiguration("Configured 'day' is not valid.")
                case "monthly":
                    day = int(config_schedule["day"])
                    if day in range(1, 29):
                        def wrapper(func):
                            return schedule.every().day.at(scheduled_time).do(func).tag("monthly").every(1).months.at(day)
                        return wrapper
                    raise InvalidConfiguration("Configured 'day' is not valid.")
                case _:
                  raise InvalidConfiguration("Chosen scope is not an option.")
        except:
            raise InvalidConfiguration("Invalid configuration(s).")
    # ----------------------------------------------------------------

    # DATA PROCESSER FUNCTION
    # ----------------------------------------------------------------
    @staticmethod
    def process_data(data):
        match data["call"]:
            case "register":
                monits = [value for value, keep in zip(data["monitors"], data["isSent"]) if keep]
                report_map = {
                    "reportBy": "COLLECTION_API",
                    "reportOn": "REGISTRATION",
                    "creationTime": data["time"],
                    "userIP": data["ip"]
                }

                if data["result"] == "FAILED":
                    report_map["result"]  = data["result"]
                    report_map["reason"] = data["reason"]
                    return report_map
                
                report_map["ID"] = data["id"]
                report_map["SID"] = data["sid"]
                report_map["notifiedAdmins"] = len(monits)
                for monit in monits:
                    report_map[f"admin_{monit.id}"] = monit.sid
                report_map["senderEmail"] = data["mail"]
                report_map["result"] = data["result"]
                return report_map
            case "confirm":
                monits = [value for value, keep in zip(data["monitors"], data["isSent"]) if keep]
                report_map = {
                    "reportBy": "COLLECTION_API",
                    "reportOn": "CONFIRMATION",
                    "creationTime": data["time"],
                    "userIP": data["ip"]
                }
                if data["result"] == "FAILED":
                    report_map["result"]  = data["result"]
                    report_map["reason"] = data["reason"]
                    return report_map
                report_map["ID"] = data["id"]
                report_map["SID"] = data["sid"]
                report_map["action"] = data["action"]
                report_map["adminID"] = data["admid"]
                report_map["adminSID"] = data["admsid"]
                report_map["adminEmail"] = data["admemail"]
                report_map["notifiedAdmins"] = len(monits)
                for monit in monits:
                    report_map[f"admin_{monit.id}"] = monit.sid
                report_map["senderEmail"] = data["mail"]
                report_map["result"] = data["result"]
                return report_map
            case "upload":
                report_map = {
                    "reportBy": "COLLECTION_API",
                    "reportOn": "UPLOAD",
                    "creationTime": data["time"],
                    "userIP": data["ip"]
                }
                if data["result"] == "FAILED":
                    report_map["result"]  = data["result"]
                    report_map["reason"] = data["reason"]
                    return report_map
                report_map["ID"] = data['id']
                report_map['SID'] = data["sid"]
                report_map["numberOfFiles"] = data["numfiles"]
                report_map["result"] = data['result']
                return report_map
    # ----------------------------------------------------------------


# LOADING DATABASES
# ----------------------------------------------------------------

# SQL DATABASE LOADING
# ----------------------------------------------------------------
engine = create_engine(f"mariadb+mariadbconnector://{config_sql['user']}:{config_sql['password']}@{config_sql['host']}:{int(config_sql['port'])}/{config_sql['database']}")
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()
# ----------------------------------------------------------------

# NOSQL DATABASE LOADING
# ----------------------------------------------------------------
client = MongoClient(f"mongodb://{config_mongo['host']}:{config_mongo['port']}/{config_mongo['database']}", username=config_mongo['user'], password=config_mongo['password'])
db = client[config_mongo['database']]
raw_logs = db.raw_logs 
reports = db.reports
# ----------------------------------------------------------------


# REGISTER ROUTE
# ----------------------------------------------------------------
@app.post("/register")
async def register(data: dict, req: Request):
    report = {'call': "register",'time': str(datetime.datetime.now()).split('.')[0], 'ip': req.client.host}
    if not Utils.validate_register_data(data):
        report["result"] = "FAILED"
        report["reason"] = "Invalid input data."
        raise HTTPException(status_code=400, detail="Invalid input data.")
    
    for table in [Utils.Waitlist, Utils.Registered, Utils.Admins]:
        res = session.query(table).filter(table.sid == data["sid"]).all()
        if res == []:
            continue
        report["result"] = "FAILED"
        report["reason"] = "SID already in use."
        raise HTTPException(status_code=409, detail="SID already in use.")
    
    pwd, salt = Utils.generate_hash(data["pwd"])
    api_t = Utils.generate_api_token()
    api_token = Utils.hash_api_token(api_t)

    session.add(Utils.Waitlist(key=api_token, sid=data["sid"], pwd=pwd, salt=salt))
    session.commit()
    uip = req.client.host
    user = session.query(Utils.Waitlist).filter(Utils.Waitlist.sid == data["sid"]).first()
    id = user.id
    monitors = session.query(Utils.Admins).filter(Utils.Admins.role == "monitor").all()

    isSent = ()
    suj = "NEW CANDIDATE REGISTERED"
    body = f"New candidate in the waitlist:\nIP address: {uip}\nID: {id}\nSID: {data['sid']}"
    for monitor in monitors:
        mail = Utils.Mail(config_mail["smtp"], int(config_mail["port"]), config_mail["email"], config_mail["password"], monitor.email, suj, body)
        isSent += (Utils.send_email(mail),)

    if any(isSent):
        report["monitors"] = monitors
        report["isSent"] = isSent
        report["id"] = id
        report["sid"] = data["sid"]
        report["mail"] = config_mail["email"]
        report["result"] = "SUCCESS"
        reports.insert_one(Reporter.process_data(report))
        return {"message": "User registered successfully. Until your verification please conserve your API key.", "key": api_t}
    
    session.query(Utils.Waitlist).filter(Utils.Waitlist.id == id).delete()
    session.commit()
    report["result"] = "FAILED"
    report["reason"] = "Couldn't notify monitor(s)."
    raise HTTPException(status_code=500, detail="Couldn't notify monitor(s). Aborting registration. Please try again later.") 
# ----------------------------------------------------------------


# CONFIRM ROUTE
# ----------------------------------------------------------------
@app.post("/confirm")
async def confirm(data: dict, req: Request):
    report = {'call': "confirm",'time': str(datetime.datetime.now()).split('.')[0], 'ip': req.client.host}
    if not Utils.validate_confirm_data(data):
        report["result"] = "FAILED"
        report["reason"] = "Invalid input data."
        raise HTTPException(status_code=400, detail="Invalid input data.")

    admin = session.query(Utils.Admins).filter(Utils.Admins.key == Utils.hash_api_token(data["key"])).first()
    if not admin:
        report["result"] = "FAILED"
        report["reason"] = "Admin not found."
        raise HTTPException(status_code=404, detail="Admin not found.")
    if not admin.role in ["superuser", "monitor"]:
        report["result"] = "FAILED"
        report["reason"] = "User permission denied."
        raise HTTPException(status_code=403, detail="Permission denied.")
    if not Utils.compare_hash(data["r_pwd"], admin.salt, admin.pwd):
        report["result"] = "FAILED"
        report["reason"] = "Invalid admin passcode."
        raise HTTPException(status_code=403, detail="Invalid admin passcode.")
    
    match data["action"]:
        case "confirm":
            uid = data["uid"]
            admin_id = admin.id
            admin_sid = admin.sid
            monitors = session.query(Utils.Admins).filter(Utils.Admins.role == "monitor").all()

            isSent = ()
            suj = "CANDIDATE CONFIRMED"
            body = f"New candidate confirmed:\nAdmin ID: {admin_id}\nAdmin SID: {admin_sid}\nAction taken: Confirmation\nRegistered user ID: {uid}"
            for monitor in monitors:
                mail = Utils.Mail(config_mail["smtp"], int(config_mail["port"]), config_mail["email"], config_mail["password"], monitor.email, suj, body)
                isSent += (Utils.send_email(mail),)

            if any(isSent):
                user = session.query(Utils.Waitlist).get(data["uid"])
                if user:
                    session.query(Utils.Waitlist).filter(Utils.Waitlist.id == data["uid"]).delete()
                    session.commit()
                    ruser = Utils.Registered(key=user.key, sid=user.sid, pwd=user.pwd, salt=user.salt)
                    session.add(ruser)
                    session.commit()
                    report["action"] = "CONFIRM"
                    report["id"] = uid
                    report["sid"] = user.sid
                    report["admid"] = admin_id
                    report["admsid"] = admin_sid
                    report["admemail"] = admin.email
                    report["monitors"] = monitors
                    report["isSent"] = isSent
                    report["mail"] = config_mail["email"]
                    report["result"] = "SUCCESS"
                    reports.insert_one(Reporter.process_data(report))
                    return {"message": "User confirmed and registered successfully."}
                else:
                    report["result"] = "FAILED"
                    report["reason"] = "User not found in waitlist."
                    raise HTTPException(status_code=404, detail="User not found.")

            report["result"] = "FAILED"
            report["reason"] = "Couldn't notify monitor(s)."
            raise HTTPException(status_code=500, detail="Couldn't notify monitor(s). Aborting confirmation. Please try again later.") 

        case "delete":
            uid = data["uid"]
            admin_id = admin.id
            admin_sid = admin.sid
            monitors = session.query(Utils.Admins).filter(Utils.Admins.role == "monitor").all()

            isSent = ()
            suj = "CANDIDATE DELETED"
            body = f"New candidate deleted:\nAdmin ID: {admin_id}\nAdmin SID: {admin_sid}\nAction taken: Deletion\nDeleted user ID: {uid}"
            for monitor in monitors:
                mail = Utils.Mail(config_mail["smtp"], int(config_mail["port"]), config_mail["email"], config_mail["password"], monitor.email, suj, body)
                isSent += (Utils.send_email(mail),)

            if any(isSent):
                user = session.query(Utils.Waitlist).get(data["uid"])
                if user:
                    session.query(Utils.Waitlist).get(data["uid"]).delete()
                    session.commit()
                    report["action"] = "DELETE"
                    report["id"] = uid
                    report["sid"] = user.sid
                    report["admid"] = admin_id
                    report["admsid"] = admin_sid
                    report["admemail"] = admin.email
                    report["monitors"] = monitors
                    report["isSent"] = isSent
                    report["mail"] = config_mail["email"]
                    report["result"] = "SUCCESS"
                    reports.insert_one(Reporter.process_data(report))
                    return {"message": "User deleted successfully."}
                else:
                    report["result"] = "FAILED"
                    report["reason"] = "User not found in waitlist."
                    raise HTTPException(status_code=404, detail="User not found.")

            report["result"] = "FAILED"
            report["reason"] = "Couldn't notify monitor(s)."
            raise HTTPException(status_code=500, detail="Couldn't notify monitor(s). Aborting deletion. Please try again later.") 
# ----------------------------------------------------------------


# UPLOAD ROUTE
# ----------------------------------------------------------------
@app.post("/upload")
async def upload(data: dict, req: Request):
    report = {'call': "confirm",'time': str(datetime.datetime.now()).split('.')[0], 'ip': req.client.host}
    if not Utils.validate_upload_data(data):
        report["result"] = "FAILED"
        report["reason"] = "Invalid input data."
        raise HTTPException(status_code=400, detail="Invalid input data.")

    fetch = session.query(Utils.Registered).filter(Utils.Registered.key == Utils.hash_api_token(data["key"])).one()
    if fetch:
        if not Utils.compare_hash(data["pwd"], fetch.salt, fetch.pwd):
            report["result"] = "FAILED"
            report["reason"] = "Invalid password."
            raise HTTPException(status_code=403, detail="Invalid password.")
        for filename in data["files"]:
            raw_logs.insert_one({'file_base64': data["files"][filename]})
        report["id"] = fetch.id
        report["sid"] = fetch.sid
        report["numfiles"] = len(data["files"])
        report["result"] = "SUCCESS"
        reports.insert_one(Reporter.process_data(report))
        return {"message": "File(s) uploaded successfully."}
    else:
        report["result"] = "FAILED"
        report["reason"] = "User not found."
        raise HTTPException(status_code=404, detail="User not found.")
# ----------------------------------------------------------------


# SHUTDOWN EVENT
# ----------------------------------------------------------------
@app.on_event("shutdown")
def shutdown_event():
    session.close()
# ----------------------------------------------------------------


# REPORT FUNCTION
# ----------------------------------------------------------------
def report_to_admins():
    report_map = {'reg_suc': 0, 'reg_fail': 0, 'conf_conf_suc': 0, 'conf_conf_fail': 0, 'conf_del_suc': 0, 'conf_del_fail': 0, 'upl_suc': 0, 'upl_fail': 0}
    for report in reports.find():
        match report["reportOn"]:
            case "REGISTRATION":
                if report["result"] == "SUCCESS":
                    report_map["reg_suc"] += 1
                if report["result"] == "FAILED":
                    report_map["reg_fail"] += 1
            case "CONFIRMATION":
                if report["result"] == "SUCCESS" and report["action"] == "CONFIRM":
                    report_map["conf_conf_suc"] += 1
                if report["result"] == "SUCCESS" and report["action"] == "DELETE":
                    report_map["conf_del_suc"] += 1
                if report["result"] == "FAILED" and report["action"] == "CONFIRM":
                    report_map["conf_conf_fail"] += 1
                if report["result"] == "SUCCESS" and report["action"] == "CONFIRM":
                    report_map["conf_del_fail"] += 1
            case "UPLOAD":
                if report["result"] == "SUCCESS":
                    report_map["upl_suc"] += 1
                if report["result"] == "FAILED":
                    report_map["upl_fail"] += 1
    admins = session.query(Utils.Admins).filter(Utils.Admins.role == 'superuser').all()
    suj = "CHECKOUT NEW REPORT"
    body = f"COLLECTION API REPORT (CHECK ATI FOR MORE):\nRegistrations(Success): {report_map['reg_suc']}\nRegistrations(Failed): {report_map['reg_fail']}\n[CONFIRM] Confirmations(Success): {report_map['conf_conf_suc']}\n[CONFIRM] Confirmations(Failed): {report_map['conf_conf_fail']}\n[DELETE] Confirmations(Success): {report_map['conf_del_suc']}\n[DELETE] Confirmations(Failed): {report_map['conf_del_fail']}\nUploads(Success): {report_map['upl_suc']}\nUploads(Failed): {report_map['upl_fail']}"
    for admin in admins:
        mail = Utils.Mail(config_mail["smtp"], int(config_mail["port"]), config_mail["email"], config_mail["password"], admin.email, suj, body)
        Utils.send_email(mail)
        print("REPORT: Sent to admin.")
# ----------------------------------------------------------------


# ASYNCHRONOUS SCHEDULER LOOP
# ----------------------------------------------------------------
async def run_scheduler():
    while True:
        schedule.run_pending()
        await asyncio.sleep(1)
# ----------------------------------------------------------------


# ASYNCHRONOUS MAIN FUNCTION
# ----------------------------------------------------------------
async def main():
    scheduled_wrapper = Reporter.get_scheduled_wrapper()
    scheduled_wrapper(report_to_admins)
    scheduler_task = asyncio.create_task(run_scheduler())
    await asyncio.gather(scheduler_task, uvicorn.run("main:app", host=config_app["host"], port=int(config_app["port"]), ssl_keyfile=config_app["ssl_key_path"], ssl_certfile=config_app["ssl_cert_path"], reload=True))
# ----------------------------------------------------------------


# START THE APP
# ----------------------------------------------------------------
if __name__ == "__main__":
    asyncio.run(main())
# ----------------------------------------------------------------