from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
import subprocess
import time
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary

# Chrome
chrome_options = ChromeOptions()
# chrome_options.add_argument("--no-sandbox")
# chrome_options.add_argument("--headless")
# chrome_options.add_argument("--whitelisted-ips")
# chrome_options.add_argument("--no-sandbox")
# chrome_options.add_argument("--disable-extensions")    
# driver = webdriver.Chrome(executable_path=r'/home/joey/Desktop/fingerprinting/extracting-metadata/chromedriver', options=chrome_options)


# firefox_options = FirefoxOptions()
# firefox_options.add_argument("--headless")
# firefox_options.add_argument("--whitelisted-ips")
# firefox_options.add_argument("--no-sandbox")
# firefox_options.add_argument("--disable-extensions")      
# driver = webdriver.Firefox(executable_path=r'/home/joey/Desktop/fingerprinting/tool/geckodriver', options=firefox_options)

OUTPUT_DIR = ""
LOAD_DELAY = 4
SETUP_DELAY = 2
urls = [
	'https://www.imdb.com/title/tt0111161/',
	'https://www.imdb.com/title/tt0068646/',
	'https://www.imdb.com/title/tt0071562/',
	'https://www.imdb.com/title/tt0468569/',
	'https://www.imdb.com/title/tt0050083/',
	'https://www.imdb.com/title/tt0108052/',
	'https://www.imdb.com/title/tt0167260/',
	'https://www.imdb.com/title/tt0110912/',
	'https://www.imdb.com/title/tt0060196/',
	'https://www.imdb.com/title/tt0137523/',
	'https://www.imdb.com/title/tt0120737/',
	'https://www.imdb.com/title/tt0109830/',
	'https://www.imdb.com/title/tt0080684/',
	'https://www.imdb.com/title/tt1375666/',
	'https://www.imdb.com/title/tt0167261/',
	'https://www.imdb.com/title/tt0073486/',
	'https://www.imdb.com/title/tt0099685/',
	'https://www.imdb.com/title/tt0133093/',
	'https://www.imdb.com/title/tt0047478/',
	'https://www.imdb.com/title/tt0114369/',
	'https://www.imdb.com/title/tt0317248/',
	'https://www.imdb.com/title/tt0076759/',
	'https://www.imdb.com/title/tt0102926/',
	'https://www.imdb.com/title/tt0038650/',
	'https://www.imdb.com/title/tt0118799/',
	'https://www.imdb.com/title/tt0245429/',
	'https://www.imdb.com/title/tt0120815/',
	'https://www.imdb.com/title/tt0114814/',
	'https://www.imdb.com/title/tt0110413/',
	'https://www.imdb.com/title/tt0120689/',
	'https://www.imdb.com/title/tt0816692/',
	'https://www.imdb.com/title/tt0054215/',
	'https://www.imdb.com/title/tt0120586/',
	'https://www.imdb.com/title/tt0021749/',
	'https://www.imdb.com/title/tt0034583/',
	'https://www.imdb.com/title/tt0064116/',
	'https://www.imdb.com/title/tt0253474/',
	'https://www.imdb.com/title/tt0027977/',
	'https://www.imdb.com/title/tt1675434/',
	'https://www.imdb.com/title/tt0407887/',
	'https://www.imdb.com/title/tt0088763/',
	'https://www.imdb.com/title/tt0103064/',
	'https://www.imdb.com/title/tt2582802/',
	'https://www.imdb.com/title/tt0110357/',
	'https://www.imdb.com/title/tt0047396/',
	'https://www.imdb.com/title/tt0082971/',
	'https://www.imdb.com/title/tt0172495/',
	'https://www.imdb.com/title/tt0482571/',
	'https://www.imdb.com/title/tt0078788/',
	'https://www.imdb.com/title/tt4633694/',
	'https://www.imdb.com/title/tt0209144/',
	'https://www.imdb.com/title/tt0078748/',
	'https://www.imdb.com/title/tt0095327/',
	'https://www.imdb.com/title/tt0095765/',
	'https://www.imdb.com/title/tt0032553/',
	'https://www.imdb.com/title/tt0043014/',
	'https://www.imdb.com/title/tt0405094/',
	'https://www.imdb.com/title/tt0057012/',
	'https://www.imdb.com/title/tt0050825/',
	'https://www.imdb.com/title/tt4154756/',
	'https://www.imdb.com/title/tt1853728/',
	'https://www.imdb.com/title/tt0081505/',
	'https://www.imdb.com/title/tt0910970/',
	'https://www.imdb.com/title/tt0119698/',
	'https://www.imdb.com/title/tt0051201/',
	'https://www.imdb.com/title/tt0364569/',
	'https://www.imdb.com/title/tt0090605/',
	'https://www.imdb.com/title/tt1345836/',
	'https://www.imdb.com/title/tt0169547/',
	'https://www.imdb.com/title/tt0087843/',
	'https://www.imdb.com/title/tt2380307/',
	'https://www.imdb.com/title/tt0082096/',
	'https://www.imdb.com/title/tt0033467/',
	'https://www.imdb.com/title/tt0112573/',
	'https://www.imdb.com/title/tt0052357/',
	'https://www.imdb.com/title/tt0053125/',
	'https://www.imdb.com/title/tt0105236/',
	'https://www.imdb.com/title/tt5311514/',
	'https://www.imdb.com/title/tt0086190/',
	'https://www.imdb.com/title/tt0022100/',
	'https://www.imdb.com/title/tt0086879/',
	'https://www.imdb.com/title/tt0180093/',
	'https://www.imdb.com/title/tt5074352/',
	'https://www.imdb.com/title/tt1187043/',
	'https://www.imdb.com/title/tt0986264/',
	'https://www.imdb.com/title/tt0062622/',
	'https://www.imdb.com/title/tt0114709/',
	'https://www.imdb.com/title/tt0338013/',
	'https://www.imdb.com/title/tt0056172/',
	'https://www.imdb.com/title/tt0066921/',
	'https://www.imdb.com/title/tt0045152/',
	'https://www.imdb.com/title/tt0211915/',
	'https://www.imdb.com/title/tt0036775/',
	'https://www.imdb.com/title/tt0075314/',
	'https://www.imdb.com/title/tt0361748/',
	'https://www.imdb.com/title/tt0093058/',
	'https://www.imdb.com/title/tt0056592/',
	'https://www.imdb.com/title/tt0040522/',
	'https://www.imdb.com/title/tt0012349/',
	'https://www.imdb.com/title/tt0119217/',
]


id = 0
page_load = 0
max_page_loads = 200
for url in urls:
    for page_load in range(0, max_page_loads):
        try:
            driver = webdriver.Chrome(options=chrome_options)
            # driver = webdriver.Firefox(options=firefox_options)
            driver.get('http://google.be')

            
            time.sleep(SETUP_DELAY + 1)
            p_process = subprocess.Popen(['tcpdump', '-U', '-w' + OUTPUT_DIR + str(id) + '-' + str(page_load) + '.pcap'])
            time.sleep(SETUP_DELAY)
            driver.get(url)
            time.sleep(LOAD_DELAY)
            p_process.send_signal(subprocess.signal.SIGTERM)
            driver.close()

        except:
            print("Exception occured, going into sleep for 1 minute.")
            time.sleep(60)
            page_load -= 1
            continue
    id += 1
    
