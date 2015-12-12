from sslscan import heartbleed
from sslscan import beast
from sslscan import sertificat
from sslscan import freak
from sslscan import logjam
from sslscan import status
import tkinter
import urllib

#parses url and gets the host name
def url2host(url):
    result = urllib.parse.urlparse(url)
    if result.netloc != '':
        return result.netloc
    return url

# 1 = Heartbleed
# 2 = Beast
# 3 = Poodle
# 4 = Freak
# 5 = Logjam
# 6 = Certificate problems
# 7 = ALL
vulnerabilities = ['Heartbleed', 'Beast', 'Poodle', 'Freak', 'Logjam', 'Certificate']
def chk_main(url, vuln, gui=1):
    host = url
    if gui==1:
        root.destroy() #destroy gui
        host = url2host(url) #transfrom url to hostaddr

    if vuln==1:
        print(">>>Heartbleed has been choosen<<<<")
        print("host: " + host)
        return heartbleed.check(host)
    elif vuln==2:
        print(">>>Beast has been choosen<<<")
        print("host: " + host)
        return beast.funbest(host)
    elif vuln==3:
        print(">>>Poodle has been choosen<<<")
        print("Warning! Not implemented yet")
        return status.Status.stUnknown
    elif vuln==4:
        print(">>>>Freak has been choosen<<<<")
        print("host: " + host)
        return freak.check(host)
    elif vuln==5:
        print(">>>Logjam has been choosen<<<")
        print("host: " + host)
        return logjam.funlogjam(host)
    elif vuln==6:
        print(">>>Certificate problems has been choosen<<<")
        print("host: " + host)
        return sertificat.cert_info(host)
    elif vuln==7:
        print("Cheking site for the whole list of vulnerabilities")
        print("host: " + host)
        print("\n")
        results = [0] * 6

        for i in range(1, 7):
            results[i-1] = chk_main(host, i, 0)

        print('>>>Result<<<')
        for i in range(1, 7):
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
            print(vulnerabilities[i-1]+' '+result)


#central windows of the interface
def center_window(root, width=300, height=200):
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
    site_entry.insert(0, "https://fitnessland.spb.ru")
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
    but6 = tkinter.Button(bPanel, text = "6. Certificate problems", fg="red", command=lambda: chk_main(site_entry.get(), 6))
    but6.pack(fill=tkinter.X)
    but7 = tkinter.Button(bPanel, text = "7. Check ALL", fg="green", command=lambda: chk_main(site_entry.get(), 7))
    but7.pack(fill=tkinter.X)

    #center window and start loop
    center_window(root, 300, 300)
    root.mainloop()

def main():
    print("Choose vulnerability:")
    draw_gui()

if __name__ == '__main__':
	main()