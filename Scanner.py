
import pyfiglet 
import socket
import whois 
import re
import requests
from datetime import datetime

def port_scanner():
        print("Example usage -> xxx.com||192.168.1.1\nExample usage  -> xxx.com||192.168.1.1 20\nExample usage  -> xxx.com||192.168.1.1 20-80 ")
        # Kullanıcıdan hedef IP adresini ve port aralıklarını tek satırda alın
        user_input = input("Enter an IP address or domain name and provide an optional port search. (exm: xxx.com||192.168.1.1 20-80): ")

        try:
            

            # Kullanıcıdan hedef IP adresini alın
            ip_and_ports = user_input.split() #ip ve portu bosluğa göre al
            target = ip_and_ports[0]  # IP adresi veya alan adı

            if len(ip_and_ports)==2:
                ports = ip_and_ports[1]    # Port aralığı
                if '-'in ports: # Eğer - aralığı varsa
                    # Port aralığını ayrıştır
                    min_port, max_port = map(int, ports.split('-'))#bir dizedeki (string) port aralığını alıp, iki tam sayı (integer) olarak ayrıştırmak ve bunları min_port ve max_port değişkenlerine atamak için kullanılır.
                else:
                    min_port=max_port=int(ports)# Tek portu hem min hem de max degere eşitledik
            else:
                min_port=1
                max_port=65535
            
           
            # Banner Ekle
            print("-" * 50)
            print("Scanned Target: " + target)
            print("Time to start scanning : " + str(datetime.now()))
            print("-" * 50)

            try:
                
                for port in range(min_port, max_port+1):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #ipv4 ve tcp üzerinden
                    socket.setdefaulttimeout(1)#Bu satır, socket bağlantısı için varsayılan zaman aşımını 1 saniye olarak ayarlar. Bu, bağlantının 1 saniye içinde yapılmaması durumunda zaman aşımı hatası vereceği anlamına gelir.

                    # Hata göstergesi döndürür
                    result = s.connect_ex((target, port))#s.connect_ex() metodu, target (hedef IP adresi veya ana bilgisayar adı) ve port numarasına bir TCP bağlantısı kurmaya çalışır. Eğer bağlantı başarılı olursa result değişkeni 0 olur. Bağlantı başarısız olursa, result bir hata kodu döndürür.
                    if result == 0:
                        try:
                            service=socket.getservbyport(port)#port numarasına göre servis adını döndürür

                        except:
                            service="unknown service"
                        print(f"Port {port} is open ({service})")    
                        try:
                            #Banner Grabbing
                            s.send(b'HEAD / HTTP/1.0\r\n\r\n')  # HTTP protokolünde banner bilgisi almak için başlık gönderiliyor #HTTP sunucusuna, bir HEAD isteği göndeririz. HEAD isteği, sunucunun bağlantıya cevap vermesini bekler, fakat sadece başlık bilgilerini döndürmesini sağlar (body kısmı yoktur). Bu genellikle hızlı bir sorgu yapmamıza olanak tanır.
                            banner=s.recv(1024).decode().strip()# Sunucunun cevabı alınıyor ve banner bilgisi # sunucudan gelen cevabı bekler ve recv(1024) ile 1024 byte kadar veri alır.
                            print(f"Service version: {banner}")  
                               
                        except:
                            print("Service information could not be obtained")
                    s.close()
                print("The scan is over")

            except (KeyboardInterrupt, EOFError):
                print("\nExiting Program !!!!")
            except socket.gaierror:#Hedef ana bilgisayar adı çözülemezse (örneğin, yanlış bir alan adı verilmişse), bu hata yakalanır ve "Hostname Could Not Be Resolved !!!!" mesajı yazdırılır.
                print("\nHostname Could Not Be Resolved !!!!")
            except socket.error:#Diğer genel socket hataları, örneğin hedef sunucuya bağlanılamıyorsa, bu hata yakalanır ve "Server not responding !!!!" mesajı yazdırılır.
                print("\nServer not responding !!!!")
        except(IndexError,ValueError):
            print("Please log in in the correct format (exm: 192.168.1.1 20-80).") 
def whois_query():
        print("Example usage -> xxx.com||192.168.1.1")

        dns_ip = input('Please enter a valid IP address or domain name: ')
        
        # IP adresi için regex
        is_valid_ip = re.match(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", dns_ip)
        
        # Alan adı için regex 
        is_valid_dns_format = re.match(r"^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?$", dns_ip)

        if is_valid_ip:
            try:
                domain_info=whois.whois(dns_ip)
                print("\nDetailed IP information")
                for key,value in domain_info.items():
                    print(f"{key}: {value}")
            except Exception as e:
                print(f"An error occurred in the WHOIS query {e}")

        elif is_valid_dns_format:
            try:
                socket.gethostbyname(dns_ip) #girilen dns adını alır sonrasında socket üzerinden kontrol edilir

                domain_info=whois.whois(dns_ip)
                for key,value in domain_info.items():
                    print(f"{key}: {value}")
            except socket.gaierror:
                    print("this dns cannot be resolved, please enter a valid domain name")   
            except Exception as e:
                    print(f"An error occurred in the WHOIS query {e}")
        else:
             print("an incorrect login was made, please enter a valid ip address or domain name")              
def ip_dns_analysis():
    print("Example usage -> xxx.com||192.168.1.1")

    dns_ip = input('Please enter a valid IP address or domain name: ')
        
    # IP adresi için regex
    is_valid_ip = re.match(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", dns_ip)
    
    # Alan adı için genişletilmiş regex (örn: .com, .net, .edu.tr gibi iki parçalı uzantılar)
    is_valid_dns_format = re.match(r"^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?$", dns_ip)

    if is_valid_ip:
        try:
            # Ters DNS sorgusu (IP'yi alan adına çevirme)
            dns_adres = socket.gethostbyaddr(dns_ip)
            print(f"IP adress: {dns_ip}, DNS: {dns_adres[0]}")
        except Exception as e:
            print(f"An error occurred in reverse DNS resolution: {e}")   

    elif is_valid_dns_format:
        try:
            # Alan adını IP adresine çevirme
            ip_adres = socket.gethostbyname(dns_ip)
            print(f"DNS: {dns_ip}, IP adress: {ip_adres}")
        except Exception as e:
            print(f"An error occurred in DNS resolution: {e}")
    else:
        print("an incorrect login was made, please enter a valid ip address or domain name")        
def geoip_API():
    print("Example usage -> 192.168.1.1")
    ip_address =input('Please enter a valid IP address: ')

    is_valid_ip = re.match(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip_address)
    if is_valid_ip:
        try:
            url = f"https://freeipapi.com/api/json/{ip_address}"

            response = requests.get(url)
            data = response.json()
            print("GeoIP Results:\n----------------")
            for key,value in data.items():
                print(f"{key}: {value}")
            print("---------------------")    
        except Exception as e:
            print(f"An error occurred in the GeoIP query {e}")
    else:
        print("an incorrect login was made, please enter a valid ip address or domain name")        
def cve_fAPI():
    # NVD API URL'si
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    try:
        print("Example usage -> Apache 2.4.5")
        find=input("please enter product and version information for the vulnerability you want to find: ")

        if not find.strip():#boş veya boşluk karakterinden oluşuyorsa
            print("Incorrect entry: You entered a null value")
        elif len(find)<3:
            print("Incorrect entry: Enter at least 3 characters")
        elif find.isdigit():#tamamen sayılardan oluşan giriş varsa
            print("Incorrect entry: You just entered a number")   
        else:


            # API parametreleri (doğru formatta)
            params = {
                "keywordSearch": find,  # Örneğin Apache'yi hedef alan zafiyetleri ara
                
            }

            # GET isteği gönder
            response = requests.get(url, params=params)

            # Yanıtın durum kodunu kontrol et
            if response.status_code == 200:
                # JSON formatındaki yanıtı al
                cve_data = response.json()
                for item in cve_data.get("vulnerabilities", []):#diziye erişiyoruz
                    cve_id = item.get("cve", {}).get("id")
                    description = item.get("cve", {}).get("descriptions", [])[0].get("value")
                    #json verisinde değerlerin yerleri metrik versiyonlarına göre değişebiliyor bunun için iki farklı değişken tanımladık
                    cvssMetricV3_sev = item.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity") #[0] cvssmetrik listesinin ilk elemanına erişeceğiz
                    cvssMetricV2_sev = item.get("cve", {}).get("metrics", {}).get("cvssMetricV2", [{}])[0].get("baseSeverity")  #parantezler eğer öyle bir değer yoksa boş bir sözlük dön hata vermemesi için yazılır
                    severity= cvssMetricV2_sev or cvssMetricV3_sev or "Unknown" # Önem derecesini belirle: varsa v3.1 kullan, yoksa v2 kullan, hiçbiri yoksa 'Bilinmiyor'
                    cvssMetricV3_score=item.get("cve",{}).get("metrics",{}).get("cvssMetricV31",[{}])[0].get("cvssData",{}).get("baseScore")
                    cvssMetricV2_score=item.get("cve",{}).get("metrics",{}).get("cvssMetricV2",[{}])[0].get("cvssData",{}).get("baseScore")
                    baseScore= cvssMetricV2_score or cvssMetricV3_score or" Unknown"
                    cvssMetricV3_ipct=item.get("cve",{}).get("metrics",{}).get("cvssMetricV31",[{}])[0].get("impactScore")
                    cvssMetricV2_ipct=item.get("cve",{}).get("metrics",{}).get("cvssMetricV2",[{}])[0].get("impactScore")
                    impactScore= cvssMetricV2_ipct or cvssMetricV3_ipct or "Unknown"
                    cvssMetricV3_cmplx=item.get("cve",{}).get("metrics",{}).get("cvssMetricV31",[{}])[0].get("cvssData",{}).get("attackComplexity")
                    cvssMetricV2_cmplx=item.get("cve",{}).get("metrics",{}).get("cvssMetricV2",[{}])[0].get("cvssData",{}).get("accessComplexity")
                    attack_cmplx= cvssMetricV3_cmplx or cvssMetricV2_cmplx or "Unknown"
                    print(f"CVE ID: {cve_id}")
                    print(f"Description: {description}")
                    print(f"Degree of Importance: {severity}")
                    print(f"Overall Score: {baseScore}")
                    print(f"Impact degree: {impactScore}")
                    print(f"Degree of Complexity: {attack_cmplx}")
                    print("-" * 40)
            else:
                print(f"API ERROR: {response.status_code}")
    except (KeyboardInterrupt, EOFError):
        print("Exiting")






try:   
    while True :
         # ASCII Banner
        ascii_banner = pyfiglet.figlet_format("MultiScanV1")
        print(ascii_banner)

        print("1.PORT SCAN")
        print("2.IP/DNS ANALYSIS")
        print("3.WHOİS QUERY")
        print("4.GeoIp QUERY")
        print("5.CVE QUERY")
        print("6.EXIT")
        sec = input("Please choose one of the options ")

        if  sec=='1':
            port_scanner()      
        elif sec=='2':
            ip_dns_analysis()
        elif sec=='3':
            whois_query()   
        elif sec=='4':
            geoip_API()   
        elif sec=='5':
            cve_fAPI()   
        elif sec=='6':
            exit()        
        else:
            print("Please enter the correct option")
except (KeyboardInterrupt, EOFError):
    print("Exiting")   


