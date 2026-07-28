from flask import Flask, render_template, jsonify, request, redirect, session

import psutil
import socket
import platform
import time
import sqlite3
import subprocess
import re

from datetime import datetime
from ping3 import ping


app = Flask(__name__)

app.secret_key = "network_monitor_secret"


DATABASE = "monitor.db"





# ================= DATABASE =================


def create_database():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(

        username TEXT,

        password TEXT

    )
    """)



    cursor.execute("""
    CREATE TABLE IF NOT EXISTS history(

        time TEXT,

        cpu REAL,

        ram REAL,

        download REAL,

        upload REAL

    )
    """)



    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_logs(

        time TEXT,

        event TEXT,

        risk TEXT

    )
    """)



    cursor.execute(
        "SELECT * FROM users"
    )


    if cursor.fetchone() is None:


        cursor.execute(

            "INSERT INTO users VALUES (?,?)",

            ("admin","admin123")

        )


    conn.commit()

    conn.close()





create_database()








# ================= LOGIN =================


@app.route("/", methods=["GET","POST"])

def login():


    if request.method == "POST":


        username = request.form["username"]

        password = request.form["password"]



        conn = sqlite3.connect(DATABASE)

        cursor = conn.cursor()



        cursor.execute(

            """
            SELECT * FROM users
            WHERE username=? AND password=?
            """,

            (username,password)

        )


        user = cursor.fetchone()


        conn.close()



        if user:


            session["user"] = username


            return redirect("/dashboard")



    return render_template("login.html")










# ================= DASHBOARD =================


@app.route("/dashboard")

def dashboard():


    if "user" not in session:


        return redirect("/")



    return render_template("index.html")









# ================= LIVE DATA =================



last_net = psutil.net_io_counters()

last_time = time.time()





@app.route("/data")

def data():


    global last_net,last_time



    cpu = psutil.cpu_percent()


    ram = psutil.virtual_memory().percent





    current_net = psutil.net_io_counters()


    current_time = time.time()



    diff = current_time-last_time



    if diff == 0:

        diff = 1




    download = (

        current_net.bytes_recv -

        last_net.bytes_recv

    ) / 1024 / diff





    upload = (

        current_net.bytes_sent -

        last_net.bytes_sent

    ) / 1024 / diff





    last_net = current_net

    last_time = current_time
        # Save history data

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()



    cursor.execute(

        """
        INSERT INTO history
        VALUES(?,?,?,?,?)
        """,

        (

        datetime.now().strftime("%H:%M:%S"),

        cpu,

        ram,

        round(download,2),

        round(upload,2)

        )

    )



    conn.commit()

    conn.close()





    # Internet status


    try:


        ping_time = ping(

            "google.com",

            timeout=2

        )


        if ping_time:


            internet = "Connected"


            ping_ms = round(

                ping_time*1000,

                2

            )


        else:


            internet = "Disconnected"


            ping_ms = 0



    except:


        internet = "Disconnected"


        ping_ms = 0







    health = "Normal"



    if cpu > 90 or ram > 90:


        health = "Critical"



    elif cpu > 70 or ram > 70:


        health = "Warning"






    return jsonify({


        "cpu":cpu,


        "ram":ram,


        "download":round(download,2),


        "upload":round(upload,2),


        "health":health,


        "internet":internet,


        "ping":ping_ms,



        "ip":

        socket.gethostbyname(

            socket.gethostname()

        ),



        "computer":

        socket.gethostname(),



        "os":

        platform.system(),



        "total_ram":

        round(

            psutil.virtual_memory().total/(1024**3),

            2

        )


    })









# ================= HISTORY =================


@app.route("/history")

def history():


    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()



    cursor.execute(

        """

        SELECT *

        FROM history

        ORDER BY rowid DESC

        LIMIT 50

        """

    )



    data = cursor.fetchall()



    conn.close()



    data.reverse()



    return jsonify(data)









# ================= NETWORK SCANNER =================


@app.route("/scan")

def scan_network():


    devices=[]



    try:


        output = subprocess.check_output(

            "arp -a",

            shell=True

        ).decode()



        lines = output.split("\n")



        for line in lines:



            match = re.search(

                r"(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9-]{17})",

                line

            )



            if match:


                devices.append({


                    "ip":match.group(1),


                    "mac":match.group(2),


                    "status":"Online"


                })




        if len(devices)==0:


            devices.append({


                "ip":"No device found",


                "mac":"-",


                "status":"Offline"


            })




    except Exception as e:



        devices.append({


            "ip":"Error",


            "mac":"-",


            "status":str(e)


        })




    return jsonify(devices)
    # ================= PORT SCANNER =================


@app.route("/ports")

def port_scan():


    target = request.args.get(

        "ip",

        "192.168.20.1"

    )



    ports = [

        21,

        22,

        23,

        80,

        443,

        3306,

        8080

    ]



    results=[]




    for port in ports:



        sock = socket.socket(

            socket.AF_INET,

            socket.SOCK_STREAM

        )



        sock.settimeout(0.5)



        status="Closed"



        try:



            result = sock.connect_ex(

                (target,port)

            )



            if result == 0:


                status="Open"



        except:



            status="Error"



        finally:



            sock.close()




        results.append({


            "port":port,


            "status":status


        })




    return jsonify({


        "target":target,


        "ports":results


    })









# ================= SECURITY CHECK =================


@app.route("/security")

def security_check():



    target = request.args.get(

        "ip",

        "192.168.20.1"

    )




    risky_ports = {


        21:"FTP",

        22:"SSH",

        23:"Telnet"

    }




    alerts=[]


    status="Safe"





    for port,service in risky_ports.items():



        sock = socket.socket(

            socket.AF_INET,

            socket.SOCK_STREAM

        )



        sock.settimeout(0.5)



        try:



            result = sock.connect_ex(

                (target,port)

            )



            if result == 0:



                status="Warning"



                alerts.append({


                    "port":port,


                    "service":service,


                    "risk":"High"


                })





                conn = sqlite3.connect(DATABASE)

                cursor = conn.cursor()



                cursor.execute(


                    """

                    INSERT INTO security_logs

                    VALUES(?,?,?)

                    """,


                    (

                    datetime.now().strftime("%H:%M:%S"),


                    service+" port detected",


                    "High"

                    )

                )



                conn.commit()

                conn.close()




        except:


            pass



        finally:


            sock.close()






    if len(alerts)==0:


        alerts.append({

            "message":

            "No security issues detected"

        })





    return jsonify({


        "target":target,


        "status":status,


        "alerts":alerts


    })









# ================= SECURITY LOGS =================


@app.route("/security_logs")

def security_logs():



    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()



    cursor.execute(


        """

        SELECT *

        FROM security_logs

        ORDER BY rowid DESC

        LIMIT 20

        """

    )



    logs = cursor.fetchall()



    conn.close()



    return jsonify(logs)







# ================= NETWORK TRAFFIC =================


@app.route("/traffic")

def traffic():



    net = psutil.net_io_counters()



    return jsonify({



        "bytes_sent":

        round(

            net.bytes_sent/(1024**2),

            2

        ),



        "bytes_received":

        round(

            net.bytes_recv/(1024**2),

            2

        ),



        "packets_sent":

        net.packets_sent,



        "packets_received":

        net.packets_recv



    })
    # ================= NETWORK INTERFACE DETAILS =================


@app.route("/interface")

def interface():


    interfaces = psutil.net_if_addrs()

    stats = psutil.net_if_stats()



    result = []



    for name, addresses in interfaces.items():


        mac = "-"

        ip = "-"



        for addr in addresses:



            if addr.family == psutil.AF_LINK:


                mac = addr.address



            elif addr.family == socket.AF_INET:


                ip = addr.address





        speed = 0

        status = "Disconnected"




        if name in stats:



            speed = stats[name].speed



            if stats[name].isup:


                status = "Connected"





        result.append({


            "interface":name,


            "ip":ip,


            "mac":mac,


            "speed":speed,


            "status":status


        })




    return jsonify(result)









# ================= BANDWIDTH MONITOR (PHASE 13) =================


@app.route("/bandwidth")

def bandwidth():


    net1 = psutil.net_io_counters()



    time.sleep(1)



    net2 = psutil.net_io_counters()




    download = (

        net2.bytes_recv -

        net1.bytes_recv

    ) / 1024




    upload = (

        net2.bytes_sent -

        net1.bytes_sent

    ) / 1024





    status = "Normal"



    if download > 1000 or upload > 1000:


        status = "High Usage"





    return jsonify({



        "download":round(download,2),



        "upload":round(upload,2),



        "status":status



    })









# ================= LOGOUT =================


@app.route("/logout")

def logout():


    session.clear()


    return redirect("/")









# ================= RUN =================


if __name__ == "__main__":


    app.run(debug=True)