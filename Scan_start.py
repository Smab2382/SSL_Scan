from sslscan import heartbleed
from sslscan import beast
import tkinter
import urllib

def url2host(url):
    result = urllib.parse.urlparse(url)
    if result.netloc != '':
        return result.netloc
    return url

# 1 = Heartbleed
# 2 = Beast
def chk_main(url, vuln):
    root.destroy() #destroy gui
    host = url2host(url) #transfrom url to hostaddr

    if vuln==1:
        print("Heartbleed has been choosen")
        print("host: " + host)
        heartbleed.check(host)
    elif vuln==2:
        print("Beast has been choosen")
        print("host: " + host)
        beast.funbest(host)

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
    but3 = tkinter.Button(bPanel, text = "3. ???")
    but3.pack(fill=tkinter.X)
    but4 = tkinter.Button(bPanel, text = "4. ???")
    but4.pack(fill=tkinter.X)
    but5 = tkinter.Button(bPanel, text = "5. ???")
    but5.pack(fill=tkinter.X)

    #center window and start loop
    center_window(root, 300, 200)
    root.mainloop()

def main():
    print("Choose vulnerability:")
    draw_gui()

if __name__ == '__main__':
	main()