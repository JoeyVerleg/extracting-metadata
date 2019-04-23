from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
import subprocess
import time
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary

# Chrome
# chrome_options = ChromeOptions()
# chrome_options.add_argument("--no-sandbox")
# chrome_options.add_argument("--headless")
# chrome_options.add_argument("--whitelisted-ips")
# chrome_options.add_argument("--no-sandbox")
# chrome_options.add_argument("--disable-extensions")    
# driver = webdriver.Chrome(executable_path=r'/home/joey/Desktop/fingerprinting/extracting-metadata/chromedriver', options=chrome_options)


firefox_options = FirefoxOptions()
# firefox_options.add_argument("--headless")
# firefox_options.add_argument("--whitelisted-ips")
# firefox_options.add_argument("--no-sandbox")
# firefox_options.add_argument("--disable-extensions")      
# driver = webdriver.Firefox(executable_path=r'/home/joey/Desktop/fingerprinting/tool/geckodriver', options=firefox_options)

OUTPUT_DIR = ""
LOAD_DELAY = 4
SETUP_DELAY = 2
urls = [
    'https://www.imdb.com/title/tt0111161',
    'https://www.imdb.com/title/tt0068646',
    'https://www.imdb.com/title/tt0071562',
    'https://www.imdb.com/title/tt0468569',
    'https://www.imdb.com/title/tt0050083',
    'https://www.imdb.com/title/tt0108052',
    'https://www.imdb.com/title/tt0167260',
    'https://www.imdb.com/title/tt0110912',
    'https://www.imdb.com/title/tt0060196',
    'https://www.imdb.com/title/tt0137523'
]
id = 0
page_load = 0
max_page_loads = 500
for url in urls:
    for page_load in range(0, max_page_loads):
        try:
            #driver = webdriver.Chrome(options=chrome_options)
            driver = webdriver.Firefox(options=firefox_options)
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
    
