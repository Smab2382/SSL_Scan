import urllib.parse

def check(host, port=443):
    print("Start scan: {0} at port {1}".format(host, port))


def main(): #for test
    url = "https://edit.aag.standardchartered.com"
    host = urllib.parse.urlparse(url).netloc
    check(host)

if __name__ == '__main__':
    main()