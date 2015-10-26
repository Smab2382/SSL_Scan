__author__ = 'Den'


class HeartBleed:
    def out(self):
        print("Hello World!")

def check(host, port = 443):
     print("Start scan: {0} at port {1}".format(host, port))

def main(): #for test
	check("https://fitnessland.spb.ru")

if __name__ == '__main__':
	main()