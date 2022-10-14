import uuid
import requests
import time
import random
import geoip2.database
import UArand
import string
from signal import signal, SIGINT
import logging
import os



log = logging.getLogger('ProxyApp_Checker')
logging.basicConfig(level=logging.INFO, format='%(relativeCreated)6d %(threadName)s %(message)s')
myuuid=uuid.uuid4()
urlAPI=os.environ.get('api_host')
password=''
goodproxy=[]
badproxy=[]
errorproxy=[]
proxylist=[]

texit=0


def get_random_string(length):
    # With combination of lower and upper case
    result_str = ''.join(random.choice(string.ascii_letters) for i in range(length))
    # print random string
    return result_str


def exithandler(signal_received, frame):
    global texit
    # Handle any cleanup here
    log.info('SIGINT or CTRL-C detected. Exiting gracefully')
    sendproxy()
    api_get =urlAPI+ f"?unique={myuuid}?pass={password}"
    response = requests.delete(api_get)
    log.info('ByBy')
    texit=1


def get_my_ip():
    sites = ['http://ipinfo.io/ip', 'https://api.ipify.org/']
    error=1
    while error==1:
        try:
            ip = requests.get(random.choice(sites), headers=UArand.randomua())
            if ip.status_code==200:
                error=0
            else:
                log.debug('Чёт не получилось получить IP. Код ошибки: %s.Но я не здамся'%ip.status_code)
        except:
            log.debug('Чёт не получилось получить IP. Но я не здаюсь')
            time.sleep(5)
    return ip.text


def get_info(url=None, proxy=None):
    info = {}
    proxy_type = []
    judges = ['http://proxyjudge.us/', 'http://azenv.net/', 'http://httpheader.net/azenv.php', 'http://mojeip.net.pl/asdfa/azenv.php','http://www.proxyjudge.info/azenv.php']
    if url != None:
        try:
            response = requests.get(url, headers=UArand.randomua(), timeout=2)
            return response
        except:
            pass
    elif proxy != None:
        for protocol in ['http', 'socks4', 'socks5']:
            proxy_dict = {
                'https': f'{protocol}://{proxy}',
                'http': f'{protocol}://{proxy}',
            }
            try:
                start = time.time()
                response = requests.get(random.choice(judges), proxies=proxy_dict, headers=UArand.randomua(), timeout=2)
                finish = time.time() - start
                if response.status_code == 200:
                    proxy_type.append(protocol)
                    info['type'] = proxy_type
                    info['time_response'] = ("%.3f" % finish)
                    info['status'] = True
                    if str(myip) in response.text:
                        info['anonymity'] = 'Transparent'
                    else:
                        info['anonymity'] = 'Anonymous'
                    if protocol == 'http':
                        return info
            except:
                pass

        if 'status' not in info.keys():
            info['status'] = False
            return info
        else:
            return info


def get_geo(ip):
    try:
        with geoip2.database.Reader('./GeoLite2-Country.mmdb') as reader:
            response = reader.country(ip)
            country=response.registered_country.iso_code
            if country!='':
                return country
            else:
                country='NONE'
                return country
    except geoip2.errors.AddressNotFoundError:
        country='NONE'
        return country
    except ValueError:
        country='NONE'
        return country


def ProxyChecker(proxy):
    ip = proxy.split(':')
    resp = get_info(proxy=proxy)
    if resp['status'] == True:
        result = {}
        geo = get_geo(ip[0])
        result['status'] = resp['status']
        result['type'] = resp['type']
        result['time_response'] = resp['time_response']
        result['anonymity'] = resp['anonymity']
        try:
            result['country_code'] = geo
        except:
            result['country_code'] = geo

        return result

    else:
        return resp


def check_proxy(ip,port):
    global goodproxy, badproxy, errorproxy
    try:
        proxy=ip+':'+str(port)
        r = ProxyChecker(str(proxy))
    except Exception as e:
        log.info(proxy, e)
        errorproxy.append([ip,port])
        return
    if r["status"]==False:
        badproxy.append([ip,port])
    else:
        r['ip']=ip
        r['port']=port
        log.info(r)
        goodproxy.append(r)
    return


def getproxy():
    global password
    error=1
    while error==1:
        if password=='':
            response = requests.get(urlAPI+f'?unique={myuuid}&ip={myip}&reg=1')
        else:
            response = requests.get(urlAPI+f'?unique={myuuid}&pass={password}&reg=0&ip={myip}')
        respcode=response.status_code
        if respcode!=200:
            if respcode==403:
                password==''
            else:
                log.error('Чёт не получилось получить прокси попробуем ещё')
                time.sleep(5)
        else:
            error=0
    lenresp=len(response.json())-1
    password=response.json()[lenresp]
    answer=response.json()
    del answer[lenresp]
    th=len(answer)
    proxy=[]
    i=0
    while i<=th-1:
        ip=answer[i]["ip"]
        port=answer[i]["port"]
        proxy.append([ip,port])
        i=i+1
    return proxy

def reqsend(types,proxy):
    probe=0
    error=1
    while (error==1):
        if types==0:
            api_get = urlAPI + f"?unique={myuuid}&pass={password}&types=bad&ip={proxy[0]}&port={proxy[1]}"
        if types==1:
            api_get = urlAPI + f"?unique={myuuid}&pass={password}&types=error&ip={proxy[0]}&port={proxy[1]}"
        if types==2:
            api_get = urlAPI + f"?unique={myuuid}&pass={password}&types=good&type={proxy[0]}&time_response={proxy[1]}&anonymity={proxy[2]}&country_code={proxy[3]}&ip={proxy[4]}&port={proxy[5]}"
        try:
            response = requests.put(api_get)
            if response.status_code==404:
                log.error('API не принял Прокси')
                error=0
            if response.status_code==201:
                error=0
        except:
            if probe>10:
                log.error('Пропускаю отправку. Не получается.')
                return
            log.error('Чёт не получилось отправить прокси попробуем ещё')
            probe+=1
            time.sleep(5)
    return


def sendproxy(): #sendmysql
    global goodproxy, badproxy, errorproxy
    i=0
    while i<=len(badproxy)-1:
        reqsend(0,(badproxy[i][0],badproxy[i][1]))
        if texit==1:exit()
        i=i+1
    badproxy.clear()
    i=0
    while i<=len(errorproxy)-1:
        reqsend(1,(errorproxy[i][0],errorproxy[i][1]))
        if texit==1:exit()
        i=i+1
    errorproxy.clear()
    i=0
    while i<=len(goodproxy)-1:
        reqsend(2,(goodproxy[i]['type'],goodproxy[i]["time_response"],goodproxy[i]["anonymity"],goodproxy[i]["country_code"],goodproxy[i]["ip"],goodproxy[i]["port"]))
        if texit==1:exit()
        i=i+1
    goodproxy.clear()
    return


def worker():
    global proxylist
    timestart=time.time()
    proxylist=getproxy()
    maxproxy=len(proxylist)-1
    log.info('Получено с базы:%s прокси за %s с. Работаем.'%(maxproxy+1,time.time()-timestart))
    tempnumproxy=0
    timestart=time.time()

    while tempnumproxy<=maxproxy:
        randpr=random.randint(0, len(proxylist)-1)
        check_proxy(proxylist[randpr][0],proxylist[randpr][1])
        del proxylist[randpr]
        if texit==1:
            return
        tempnumproxy+=1
    log.info("Заход в сотню за:%s секунд"%(time.time()-timestart))
    sendproxy()
    log.info('Погнали по второму кругу')
    return



signal(SIGINT, exithandler)
myip=get_my_ip()
log.info('IP получен: %s'%myip)
while True:
    worker()
    if texit==1:
        exit()
    time.sleep(2)
