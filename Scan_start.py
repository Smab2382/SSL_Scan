from sslscan import heartbleed
from sslscan import beast
from sslscan import poodle
from sslscan import certificat
from sslscan import freak
from sslscan import logjam
from sslscan import status
import tkinter
import urllib
import socket
import ssl

#parses url and gets the host name
def url2host(url):
    result = urllib.parse.urlparse(url)
    if result.netloc != '':
        return result.netloc
    return url

#checks if host is available
def checkAccess(host):
    try:
        port = 443
        sock = socket.socket()
        ssl_sock=ssl.SSLSocket(sock)
        ssl_sock.connect((host, port))
        return True
    except:
        return False

# 1 = Heartbleed
# 2 = Beast
# 3 = Poodle
# 4 = Freak
# 5 = Logjam
# 6 = Certificate problems
# 7 = ALL
vulnerabilities = ['Heartbleed', 'Beast', 'Poodle', 'Freak', 'Logjam', 'Certificate']
def chk_main(url, vuln, firstLaunch=True):
    host = url
    if firstLaunch==True:
        #root.destroy() #destroy gui
        host = url2host(url) #transfrom url to hostaddr
        print("host: " + host)
        if checkAccess(host)==False: #checking if site is available
            print("SSL on this host is not available! Scan has been interrupted!")
            return

    if vuln==1:
        print(">>>Heartbleed has been choosen<<<<")
        return heartbleed.check(host)
    elif vuln==2:
        print(">>>Beast has been choosen<<<")
        return beast.funbest(host)
    elif vuln==3:
        print(">>>Poodle has been choosen<<<")
        return poodle.poodlefun(host)
    elif vuln==4:
        print(">>>>Freak has been choosen<<<<")
        return freak.check(host)
    elif vuln==5:
        print(">>>Logjam has been choosen<<<")
        return logjam.funlogjam(host)
    elif vuln==6:
        print(">>>SSL2 availability has been choosen<<<")
        return certificat.ssl2av(host)
    elif vuln==7:
        print(">>>SSL3 availability has been choosen<<<")
        return certificat.ssl3av(host)
    elif vuln==8:
        print(">>>TLS1.0 availability has been choosen<<<")
        return certificat.tlsav(host)
    elif vuln==9:
        print(">>>TLS1.1 availability has been choosen<<<")
        return certificat.tls11av(host)
    elif vuln==10:
        print(">>>TLS1.2 availability has been choosen<<<")
        return certificat.tls12av(host)
    elif vuln==11:
        print(">>>Certificate info has been choosen<<<")
        return certificat.cert_info(host)
    elif vuln==12:
        print("Cheking site for the whole list of vulnerabilities\n")
        results = [0] * 6

        for i in range(1, 12):
            results[i-1] = chk_main(host, i, False)

        print('>>>Result<<<')
        for i in range(1, 12):
            result = ''
            if(results[i-1]==status.Status.stOk):
                result = 'Not vulnerable'
            if(results[i-1]==status.Status.stVuln):
                result = 'Vulnerable'
            if(results[i-1]==status.Status.stError):
                result = 'Error'
            if(results[i-1]==status.Status.stUnknown):
                result = 'Unknown'
            if(results[i-1]==None):
                result = 'Unknown'
            print(str(i)+'. '+vulnerabilities[i-1]+': '+result)


#central windows of the interface
def center_window(root, width=300, height=500):
    # get screen width and height
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # calculate position x and y coordinates
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    root.geometry('%dx%d+%d+%d' % (width, height, x, y))

def draw_gui():
    #create gui window
    global root
    root = tkinter.Tk()
    root.title("SSL scaner")

    #create label
    label1 = tkinter.Label(root, text="Enter hostname here:")
    label1.pack(fill=tkinter.X)

    #create input for host
    site_entry = tkinter.Entry(root, width=50)
    site_entry.insert(0, "www.google.com")
    site_entry.pack(fill=tkinter.X, padx=5,pady=10)

    #create list of vulnerabilities
    bPanel = tkinter.Frame(root)
    bPanel.pack(fill=tkinter.X, expand=1)
    but1 = tkinter.Button(bPanel, text = "1. Heartbleed", fg="red", command=lambda: chk_main(site_entry.get(), 1))
    but1.pack(fill=tkinter.X)
    but2 = tkinter.Button(bPanel, text = "2. Beast", fg="red", command=lambda: chk_main(site_entry.get(), 2))
    but2.pack(fill=tkinter.X)
    but3 = tkinter.Button(bPanel, text = "3. Poodle", fg="red", command=lambda: chk_main(site_entry.get(), 3))
    but3.pack(fill=tkinter.X)
    but4 = tkinter.Button(bPanel, text = "4. Freak", fg="red", command=lambda: chk_main(site_entry.get(), 4))
    but4.pack(fill=tkinter.X)
    but5 = tkinter.Button(bPanel, text = "5. Logjam", fg="red", command=lambda: chk_main(site_entry.get(), 5))
    but5.pack(fill=tkinter.X)
    but6 = tkinter.Button(bPanel, text = "6. SSL2 availability", fg="red", command=lambda: chk_main(site_entry.get(), 6))
    but6.pack(fill=tkinter.X)
    but7 = tkinter.Button(bPanel, text = "7.SSL3 availability", fg="red", command=lambda: chk_main(site_entry.get(), 7))
    but7.pack(fill=tkinter.X)
    but8 = tkinter.Button(bPanel, text = "8. TLS1.0 availability", fg="red", command=lambda: chk_main(site_entry.get(), 8))
    but8.pack(fill=tkinter.X)
    but9 = tkinter.Button(bPanel, text = "9. TLS1.1 availability", fg="red", command=lambda: chk_main(site_entry.get(), 9))
    but9.pack(fill=tkinter.X)
    but10 = tkinter.Button(bPanel, text = "10. TLS1.2 availability", fg="red", command=lambda: chk_main(site_entry.get(), 10))
    but10.pack(fill=tkinter.X)
    but11 = tkinter.Button(bPanel, text = "11. Certificate info", fg="red", command=lambda: chk_main(site_entry.get(), 11))
    but11.pack(fill=tkinter.X)
    but12 = tkinter.Button(bPanel, text = "12. Check ALL", fg="green", command=lambda: chk_main(site_entry.get(), 12))
    but12.pack(fill=tkinter.X)

    #center window and start loop
    center_window(root, 300, 300)
    root.mainloop()

def main():
    print("Choose vulnerability:")
    draw_gui()

if __name__ == '__main__':
	main()
