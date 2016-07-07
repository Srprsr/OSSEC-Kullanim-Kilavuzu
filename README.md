# OSSEC Kullanım Kılavuzu
Özellikle dağıtık yapılarda, sunucu güvenliği konusunda süreklilik sağlamak en önemli noktalardan birisidir. Zira, tüm sistemlerin bir şekilde izlenmesi ve olası anormalliklerin oldukları an tespit edilip müdahale edilmesi olası servis kesintilerini oluşmadan engellemek üzerine kurulu proaktif sistem yönetiminin başlıca kurallarından birisidir. Bu noktada network trafiğini izleyerek saldırı tespiti yapmanın yanı sıra her bir sunucu/cihaz üzerinde de bir **HIDS (host-based intrusion detection)** uygulaması kullanarak log monitoring, dosya bütünlük kontrolü ve rootkit tespiti gibi genel işlemler gerçekleştirilmelidir.

![alt text](https://glynrob.com/wp-content/uploads/ossec-hids.jpg "OSSEC Logo")
# OSSEC Nedir?
OSSEC, Trend Micro tarafından desteklenen, tamamen açık kaynak kodlu, standalone çalışabildiği gibi, agent/master yapısı ile merkezi yönetim de sağlayabilen bir host-based saldırı tespit sistemidir. Temel olarak log analizi, dosya bütünlük kontrolü, rootkit tespiti, gerçek zamanlı alarm üretme ve tespit edilen saldırılara karşılık active response özelliği ile aksiyonlar alma gibi görevleri yerine getiren OSSEC, hali hazırda kullanılan SIM/SIEM platformları ile de entegre edilebilmektedir.

 **OSSEC, native olarak  tüm *nix ( Linux, MacOS, Solaris, HP-UX, AIX, Vmware ESX) ve Windows platformlarda çalışabilmekte**, agentless modu sayesinde de router, switch gibi network cihazlarını da monitor edebilmektedir.

# TEMEL ÖZELLİKLERİ
* [Dosya Bütünlük Kontrolü](#dosya-butunluk-kontrolu)
* [Log Monitoring](#log-monitoring)
* [Rootkit Detection](#rookit-detection)
* [Active Response](#active-response)

##Dosya Bütünlük Kontrolü
File Integrity Checking ya da File Integrity Monitoring (FIM) olarak adlandırılan bu işlem, temel olarak sistemde şu ya da bu şekilde değişikliğe uğrayan dosyaların tespit edilmesi ve bu değişikliklerin sistem yöneticisine bildirilmesini hedeflemektedir.

Sisteminize sızmaya çalışan her tür atağın ortak özelliğinin sistem üzerinde bir takım dosyaları değiştirmek ya da sisteme bir takım dosyalar eklemek olduğu düşünülürse, HIDS’ler için dosya bütünlük kontrolü en önemli bileşenlerden birisidir ve sistemlerinizdeki değişiklikleri oldukları an tespit etmek büyük öneme sahiptir.

##Log Monitoring
Meydana gelen değişikliklerin tespit edilmesi üzere kontrolü gereken bir diğer nokta ise log dosyalarıdır. OSSEC bu amaca yönelik olarak sistem loglarını izleyip analiz eder ve herhangi bir problem tespit edilmesi halinde alarm üreterek sistem yöneticisini bilgilendirir. Örnek olarak sisteme bir paket kurulduğu zaman ya da web sunucusuna ait loglara bir sızma girişimini işaret eden satırlar düşmeye başladığı zaman alarm üretilir ve durumun farkında olmanız sağlanır.


#### Log Monitoring Soru&Cevap

  * Ne kadar sıklıkla loglar izlenebilir.
      * Gerçek Zamanlı olarak dosyaları inceleyebilirsiniz.
  * Olaylar nerede analiz edilir?
      * manager bölümünde.
  * Ne kadar süre saklanır?
      * Politikalar izin verdiği sürece (kullanıcı tarafından yönetilebilir).
  * CPU kullanımı nasıl?
      * Agent, çok az CPU/memory kullanır, sadece olayları okur ve onu manager'a gönderir.
      * Manager, saniyede gerçekleşen olay(EPS:event per second) sayısına göre CPU kullanımı değişir.
  * False Pozitif nasıl oluşur?
      * Lokal kurallar konularak False Positiveler kaldırılabilir.

#### Log Monitoring Yapılandırma Seçenekleri

Bu seçenekler her ajanın ossec.conf dosyasında belirtilmelidir. <localfile> öğensinin içinde, aşağıdaki seçenekleri bulabilirsiniz.

##### localfile
##### location

Log dosyalarının konumunu belirtmek okunacak. strftime biçimleri log dosyası adları için kullanılabilir. Örneğin, file.log-2011-01-22 adında bir log dosyası file.log-% Y-% m-% d ile başvurulan olabilir. Wildcard olmayan Windows sistemlerinde kullanılabilir. Wildcard kullanıldığında, log dosyaları OSSEC-logcollector başlatıldığı anda mevcut olmalıdır. Bu durumda otomatik olarak yeni log dosyaları izlemeye başlamaz. strftime ve wildcard aynı girişte kullanılamaz.

**Varsayılan:** Çoklu (eg /var/log/messages)

**İzin Verilen:** Tüm Log Dosylaraı

##### log_format
Log dosyasının okunma formatı.
```
Note
Eğer log dosyasında her bir satırda bir entry varsa syslog kullanın.
```
**Default:** syslog

**Allowed** 
> * syslog
> * snort-full
> * snort-fast
> * squid
> * iis
> * eventlog
> * eventchannel
> * mysql_log
> * postgresql_log
> * nmapg
> * apache
> * command
> * full_command
> * djb-multilog
> * multi-line

##### command
Komut çalıştırmak için kullanılır. Bu komutun bütün çıkış komutu veya tam komut kullanılıp kullanılmadığını bağlı olarak bir veya daha fazla log mesajı olarak okunacaktır.

**İzin Verilen:** Tüm commandline ve argümanlar.

##### alias
Komutu tanımlamak için kullanılır. Bu log dosyası komutu yerini alır.

Örneğin: <alias>usb-check</alias> değişecek
```
ossec: output: 'reg QUERY HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR':

```
ve
```
ossec: output: 'usb-check':

```

**İzin Verilen:** String.

##### frequency
Komut çalışırken arasındaki saniye cinsinden minimum süre. Komut muhtemelen tam her frekans saniyede çalışmıyor, ancak çalışmalar arasındaki zaman bu ayardan daha kısa olmayacaktır. frequency command ve fullcommand'le kullanılır.

**İzin Verilen:** Saniye.

##### checkdiff
Bir event çıktısı, bir iç veri tabanında depolanacaktır. Aynı olay alındığında her zaman, üretimi, bir önceki çıkış ile karşılaştırılır. Çıktı değişti ise bir uyarı oluşturulur.

##### only-future-events
Sadece eventchannel kayıt formatı ile kullanılır. OSSEC son durdurulan beri OSSEC-logcollector cevapsız tüm eventleri okuyacaktır eventchannel log biçimi başlar varsayılan olarak. Bu durumun ortaya çıkmaması için *only-future-events*'i *yes* olarak ayarlamanız gerekir. Bu şekilde OSSEC sadece logcollector başladıktan sonra meydana gelen olayları alacaksınız.

```
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
  <only-future-events>yes</only-future-events>
</localfile>
```

##### query
Sadece eventchannel kayıt formatı ile kullanılır. OSSEC işleyecek olayları filtrelemek için aşağıdaki gibi ID'sini daha önce microsoft dökümanlarından keşfettiğin bir event numarası bulup, aşağıdaki gibi oluşturmalısınız.

Örneğin, aşağıdaki yapılandırma sadece 7040 kimliğine sahip eventleri işleyecek:
```
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID=7040]</query>
</localfile>
```

##Rootkit Detection
OSSEC’in bir diğer görevi de sistemlerde periyodik olarak rootkit taraması yapmaktır. Bu şekilde sunucuların herhangi birinde  bir rootkit, trojan ya da virus’ün varlığı anında tespit edilir ve bildirilir.

#### Rootkit Detection Yapılandırma Seçenekleri
Bu yapılandırma seçenekleri yöneticisi yan seçenekleri auto_ignore ve alert_new_file hariç, her ajanın ossec.conf belirtilebilir. Özel olarak belirtilmişse ayar tüm ajanlar için küresel hale gelir.

| Yapılandırma Adı | Açıklama                                                                                 | İzin Verilen                                           | Varsayılan                                       |
| ---------------- |:----------------------------------------------------------------------------------------:| ------------------------------------------------------:| ------------------------------------------------:|
| rootkit_files    | Bu seçenek rootkit dosyalarını veritabanının konumunu değiştirmek için kullanılabilir.   | A file with the rootkit files signatures               | /etc/shared/rootkit_files.txt                    |
| rootkit_trojans  | Bu seçenek rootkit trojanlerinin veritabanının konumunu değiştirmek için kullanılabilir. | A file with the trojans signatures                     | /etc/shared/rootkit_trojans.txt                  |
| windows_malware  |                                                                                          |                                                        |                                                  |
| windows_audit    |                                                                                          |                                                        |                                                  |
| windows_apps     |                                                                                          |                                                        |                                                  |
| systems_audit    |                                                                                          |                                                        |                                                  |
| scan_all         | Tüm sistemi taramasını söyle (bu baze false positive durumlara sebep olur).              | yes/no                                                 | no                                               |
| frequency        | Rootcheckin hangi aralıklarla çalışacağını belirler.                                     | Saniye cinsinden zaman                                 | 36000 sn                                         |
| disabled         | rootcheck'in çalışmasını devre dışı bırakır.                                             | yes/no                                                 | no                                               |
| check_dev        | Enable/Disable                                                                           | yes/no                                                 | yes                                              |
| check_files      | Enable/Disable                                                                           | yes/no                                                 | yes                                              |
| check_if         | Enable/Disable                                                                           | yes/no                                                 | yes                                              |
| check_pids       | Enable/Disable                                                                           | yes/no                                                 | yes                                              |
| check_policy     | Enable/Disable                                                                           | yes/no                                                 | yes                                              |
| check_ports      | Enable/Disable                                                                           | yes/no                                                 | yes                                              |
| check_sys        | Enable/Disable                                                                           | yes/no                                                 | yes                                              |
| check_trojans    | Enable/Disable                                                                           | yes/no                                                 | yes                                              |
| check_unixaudit  | Enable/Disable                                                                           | yes/no                                                 | yes                                              |
| check_winapps    | Enable/Disable                                                                           | yes/no                                                 | yes                                              |
| check_winaudit   | Enable/Disable                                                                           | 1/0                                                    | 1                                                |
| check_winmalware | Windows malware için Enable/disable.                                                     | yes/no                                                 | yes                                              |
| skip_nfs         | Rrootcheck ağı monunted filesystemlerini taraması gereken olmadığını belirtir.           | yes/no                                                 | no                                               |


##Active Response
OSSEC’in aktive response özelliği sistemde oluşan bir problem için otomatik aksiyonlar almak üzere kullanılmaktadır. Örneğin web sunucunuzu tarayan bir saldırgan’ı, web loglarından tespit edip saldırgan’ın *ip adresinin firewall üzerinden bloklanması OSSEC’in active response özelliği* ile mümkündür.

![alt text](http://i67.tinypic.com/2i96seq.png "OSSEC Active Response")


#### Özel Active Response Oluşturmak
##### Command Oluşturmak
Yapmamız gereken ilk şey OSSEC config yeni bir "command" girdisini yaratmaktır.
```
<command>
    <name>mail-test</name>
    <executable>mail-test.sh</executable>
    <timeout_allowed>no</timeout_allowed>
    <expect />
</command>
```

Şu an komut dosyası zaman aşımı gerek olmadığından, boş bırakıyoruz. Eğer zaman aşımı kullanmak istiyorsanız expect taginin içine değeri girebilirsiniz.
```
Note
Örn: <expect>srcip</expect>
```

##### Active Response'u Yapılandırmak
Sonra, aktif tepki çalıştırmak için OSSEC yapılandırmanız gerekir. Benim durumumda, ben OSSEC sunucu üzerinde çalıştırmak istediğiniz (yani konum sunucusunu seçin) ve kural 1002 ateş her zaman (1002 rules_id bakınız). Ayrıca seviyesini veya farklı yerlerde belirtebilirsiniz.
```
<active-response>
    <command>mail-test</command>
    <location>server</location>
    <rules_id>1002</rules_id>
</active-response>
```

##### Active Response Script'i Oluşturmak
Biz aktif response komut dosyası oluşturabilirsiniz. mail-test.sh set yürütme izinlerine sahip 'var/OSSEC/active-response/bin' içinde olmalıdır.

**Script'e hangi argümanlar geçirilebilir?**
> * action (delete or add)
> * user name (or - if not set)
> * src ip (or - if not set)
> * Alert id (uniq for every alert)
> * Rule id
> * Agent name/host
> * Filename

```
#!/bin/sh
# E-mails an alert - copy at /var/ossec/active-response/bin/mail-test.sh
# Change e-mail ADDRESSS
# Author: Daniel Cid

MAILADDRESS="xx@ossec.net"
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5

LOCAL=`dirname $0`;
cd $LOCAL
cd ../
PWD=`pwd`


# Logging the call
echo "`date` $0 $1 $2 $3 $4 $5 $6 $7 $8" >> ${PWD}/../logs/active-responses.log


# Getting alert time
ALERTTIME=`echo "$ALERTID" | cut -d  "." -f 1`

# Getting end of alert
ALERTLAST=`echo "$ALERTID" | cut -d  "." -f 2`

# Getting full alert
grep -A 10 "$ALERTTIME" ${PWD}/../logs/alerts/alerts.log | grep -v ".$ALERTLAST: " -A 10 | mail $MAILADDRESS -s "OSSEC Alert"
```
##### Restart OSSEC and test
Yapılandırma işlemi tamamlandıktan sonra, size OSSEC yeniden başlatın ve yapılandırmayı test edebilirsiniz. sana Yukarıdaki örnekte, ben benzer bir segmentasyon hatası mesajı logger komutunu çalıştırabilirsiniz.
```
# /var/ossec/bin/ossec-control restart
# logger "Segmentation Fault"
```
/var/ossec/logs/active-response.log dosyası için aşağıdaki komutları gerçekleştirin.
```
Fri Jul 03 23:48:31 BRT 2016 /var/ossec/active-response/bin/mail-test.sh add - - 1185590911.25916 1002 /var/log/messages
```
E-posta olarak:
```
from: root <root@xx.org>
to: xx@ossec.net
date: Jul 03,03 2016 11:48 PM
subject: OSSEC Alert

** Alert 1185590911.25661: mailsl  - syslog,errors,
2016 Jul 03 23:48:31 xx->/var/log/messages
Rule: 1002 (level 7) -> 'Unknown problem somewhere in the system.'
Src IP: (none)
User: (none)
Jul 27 23:48:30 xx dcid: Segmentation Fault 123
```
#### UNIX: Active Response Yapılandırması
Active Response yapılandırması iki bölüme ayrılmıştır. İlkinde sen yürütmek istediğiniz komutları yapılandırır, İkinci durumda ise, kurallar ya da olayları komutlara bağlarsınız.

##### Komut Yapılandırması

Komut yapılandırmada yeni "commands" yeni tepkiler olarak kullanılmak üzere oluşturursunuz. İstediğiniz gibi birçok komutları olabilir. Her biri kendi "command" tagi içinde olmalıdır.
```
<command>
    <name>The name (A-Za-Z0-9)</name>
    <executable>The command to execute (A-Za-z0-9.-)</executable>
    <expect>Comma separated list of arguments (A-Za-z0-9)</expect>
    <timeout_allowed>yes/no</timeout_allowed>
</command>
```
> * **name:** Command'in mi.
> * **executable:** Çalıştırılabilir iznine sahip bir dosya olmalıdır ve bu path'in içinde olmalıdır: “/var/ossec/active-response/bin”.
> * **expect:** (Seçenekler: srcip/username).
> * **timeout_allowed:** command'in zaman aşımına uğramasını isterseniz bu alanı doldurabilirsiniz..

##### Geri Dönüşlerin Yapılandırılması
Aktif-response yapılandırmada, olaylara (oluşturulan) komutları bağlar. İstediğiniz kadar response olabilir. Her biri kendi "aktif-response" elemanı içinde olmalıdır.
```
<active-response>
    <disabled>Completely disables active response if "yes"</disabled>
    <command>The name of any command already created</command>
    <location>Location to execute the command</location>
    <agent_id>ID of an agent (when using a defined agent)</agent_id>
    <level>The lower level to execute it (0-9)</level>
    <rules_id>Comma separated list of rules id (0-9)</rules_id>
    <rules_group>Comma separated list of groups (A-Za-z0-9)</rules_group>
    <timeout>Time to block</timeout>
</active-response>
```
> * **disable:** Active-responsu kapatır.
> * **command:** responsu command'e bağlamak için kullanılır
> * **location:** Komutun nerede çalışacağını belirtir. 4 seçeneğiniz var
> **local:** Agent'ta
> **server:** OSSEC server'da
> **defined-agent:** özellikle belirtilmiş bir agent'ta (Bunu kullanmak isterseniz agent_id set etmeniz gerekir.)
> **all:** her yerde.
> * **agent_id:** Responsu çalışataracak olan agent id'si (yukarıda location olarak defined-agent seçilirse kullanılır).
> * **level:** Responsun çalışacağı eventin seviyesini belirler.
> * **timeout:** Ne kadar süre çalışacağını belirtir. (Örn: IP unblocked).

##### Active Response Araçları
Varsayılan olarak, OSSEC HIDS aşağıda daha önce yapılandırılmış araçlar ile birlikte gelir.
* **host-deny.sh:** /etc/hosts.deny dosyasına bir IP adresi ekler. (bir çok Unix sistemde).
* **firewall-drop.sh** (iptables): iptables deny list'e bir IP adresi ekler.  (Linux 2.4 and 2.6).
* **firewall-drop.sh (ipfilter):** ipfilter deny list'e bir IP adresi ekler.  (FreeBSD, NetBSD and Solaris).
* **firewall-drop.sh (ipfw):** ipfw deny table'a bir IP adresi ekler.  (FreeBSD).

> ```
> Not
> Uzerinde IPFW biz IP'ler bloke edilecek eklemek için tablo 1'i kullanın. Güvenlik duvarı listesinin başında deny gibi bu tabloyu ayarlayın. Eğer başka bir şey için tablo 1 kullanıyorsanız, farklı bir tablo kimliği kullanmak için komut dosyasını değiştirin.
> ```

* **firewall-drop.sh (ipsec):** ipsec drop table'a bir IP adresi ekler.  (AIX).
* **pf.sh (pf):**  pre-configured pf deny table'a bir IP adresi ekler. (OpenBSD and FreeBSD).

> ```
> Not
> PF, sizin config bir tablo oluşturmak ve buna tüm trafiği engellemek gerekir. senin kuralların başında aşağıdaki satırları ekleyin ve pf yeniden (pfctl -F tüm && pfctl -f /etc/pf.conf): Tablo <ossec_fwtable> #ossec_fwtable devam
için herhangi çabuk herhangi bir blok dışarı <ossec_fwtable> dan hızlı blok <ossec_fwtable>
> ```

* **firewalld-drop.sh (firewalld):** firewalld'a bir IP adresi ekler (firewalld aktif olan Linux sistemlerde).

> ```
> Note
> Eğer firewalld etkin ise yukarıdaki komut kullanılmalıdır.
> ```

#OSSEC BİLEŞENLERİ
* [Manager](#manager)
* [Agent](#agent)
* [Agentless](#agentless)
* [Virtualization/Vmware](#Virtualization-Vmware)
* [Syslogs Üzerinden Monitoring](#syslogs--zerinden-monitoring)

##Manager
Manager, OSSEC’in temel bileşeni olup görevi tüm yapıyı monitor etmek ve uzak hostlardan aldığı bilgileri -ki bu konunun detayına aşağıda değineceğim- analiz etmektir.

Ossec Server da denilen Manager tüm sistemler için merkezi noktadır. Bu noktada dosya bütünlük kontrolü database’leri, loglar, olaylar (events) ve system auditing girdileri bulunmaktadır. Ayrıca, agentların -tercihen yapılandırma dosyaları-, kurallar ve decoderlar Manager’da tutulmaktadır. Bu şekilde çok fazla sayıda sistemden oluşan networkler merkezi olarak kolayca yönetilebilmektedirler.

##Agent
Agent, monitor edilmesini istediğimiz her sisteme kurduğumuz küçün Ossec programının adıdır. Göveri, kurulu olduğu sisteme ait bilgileri toplamak ve analiz edilmesi için Manager’a göndermektir. Bu uygulaması çok küçük bir memory ve CPU footprint’ine sahip olduğundan dolayı sisteme ekstra yük bindirmez.

Agent’lar kurulum sırasında oluşturulan düşük yetkili kullanıcı tarafından, chroot ortamda ana sistemden izole edilmiş bir şekilde çalıştırılır. Ayrıca, agent ile ilgili yapılandırmanın hemen hemen hepsi Manager tarafında tutulabilmekte ve agent’in bulunduğu host üzerinde yapılandırmanın sadece bir kısmınun bulunması sağlanabilmektedir.  Zaten bu özelliklerden hariç olarak lokaldeki herhangi bir yapılandırma dosyası değiştirilirse Manager alarm üretip sistem yöneticisini uyaracaktır.

##Agentless
Agentless modu, üzerine agent kuramayacağımız her türlü sistemi monitor etmek için kullanılan mode’dur. Agentless monitoring özellikle firewall, switch, router gibi network cihazlarının ya da üzerinde agent kurma yetkinizin olmadığı *nix sistemlerin izlenmesi ve dosya bütünlük kontrollerinin yapılması için idealdir.

##Virtualization/Vmware
OSSEC agent’i VMWare ESX hostlara kurulabilmektedir. Bu şekilde sanallaştırma altyapıları OSSEC üzerinden monitor edilebilir ve  örneğin guest’lerin kurulumu, başlatılması, kaldırılması gibi işlemler takip edilerek belirlenen koşullar için alarmlar ürettirilebilmektedir. Ayrıca, ESX hostların logları da izlenebilmekte, login, logout ve error durumları izlenebilmekte ve güvenlik açısından dikkat edilmesi gereken ESX özelliklerinin aktif hale gelmesi durumunda alarm üretilmesi sağlanabilmektedir.

##Syslogs Üzerinden Monitoring
Ossec uzak sistemlerden syslog üzerinden iletilen logları alarak analiz edebilmektedir. Aktif network cihazlarının loglarının analiz edilmesi için ideal olan bu yöntem ile  tüm Cisco ve Juniper router’ları, Cisco PIX, Cisco FWSM, Cisco ASA, Netscreen firewall, Checkpoint gibi sistemler izlemeye alınabilmektedir.


#OSSEC MİMARİSİ
Ossec’in çalışma prensibini açıklamak üzere aşağıdaki şekilde güzel bir çizim bulunmakta:
![alt text](https://www.bilgio.com/wp-content/uploads/2014/04/ossec-arch21.jpg "OSSEC mimari")


# Nasıl Yüklenir?

```
$ (ossec_version="2.8.2" ; ossec_checksum="a0f403270f388fbc6a0a4fd46791b1371f5597ec" ; cd /tmp/ && wget https://github.com/ossec/ossec-hids/archive/${ossec_version}.tar.gz && mv ${ossec_version}.tar.gz ossec-hids-${ossec_version}.tar.gz && checksum=$(sha1sum ossec-hids-${ossec_version}.tar.gz | cut -d" " -f1); if [ $checksum == $ossec_checksum ]; then tar xfz ossec-hids-${ossec_version}.tar.gz && cd ossec-hids-${ossec_version} && sudo ./install.sh ; else "Wrong checksum. Download again or check if file has been tampered with."; fi)

```
Ben kurulumları Master/Agent modunda olmak üzere iki adet CentOS 6.5 kullanarak yapacağım. Ancak kurulum yönergeleri her dağıtım için hemen hemen aynı olduğundan siz kendi tercih ettiğiniz bir dağıtımı kullanabilirisiniz. (Farklılık gösteren yönergeleri ayrıca bildireceğim.)

##Gereksinimler
OSSEC gcc, libc ve OpenSSL paketlerine ihtiyaç duyuyor ki bu paketler genellikle default kurulumlarda gelmektedir. Bunlar dışında:

##Debian/Ubuntu
Debian tabanlı sistemlerde build-essential paketinin yüklü olması gerekmektedir:
```
# apt-get install build-essential
```
ve ayrıca Ossec’i database desteği ile kullanacaksanız mysql-dev ya da postgresql-dev paketlerinden birisi yüklü olmalıdır.
Ben kurulumu mysql destekli olarak yapacağım için mysql-dev paketini kuruyorum:
```
# apt-get install mysql-server mysql-dev
```

##RHEL/CentOS
RHEL ve CentOS sistemlerde, sistemi minimal kurmadıysanız mysql paketleri hariç diğer gerekli olan herşey kurulu gelecektir. Ancak miminal bir sisteminiz varsa “Development tools” grubunu yükleyebilirsiniz:
```
# yum groupinstall "Development tools"
```
Ayrıca, Ossec’i mysql destekli kuracağımız için mysql ile ilgili paketleri de kuruyoruz:
```
# yum install mysql-server mysql-devel 
# chkconfig mysqld on 
# service mysqld start
```
Şimdi de mysql_secure_installation aracını kullanarak MySQL’i güvenli bir hale getirelim:
```
# mysql_secure_installation
```

Yönergeleri takip ettikten sonra root kullanıcısı için bir şifre tanımlamış ve diğer güvenlik önlemlerini almış oluyoruz.

##IPTables

Ossec Server agentları ile udp 1514. porttan konuştuğu ve opsiyonel olarak syslog üzerinden log almak istemeniz durumunda udp 514. portu kullandığı için sisteminizde iptables devrede ise bu iki porta kendi networkünüzden izin vermeniz gerekir.

Bu iş için iptables’ın INPUT zincirine aşağıdakine benzer bir tanımlama ekleyebilirsiniz:
```
-A INPUT -p udp --dport 514 -s 10.0.0.0/16 -j ACCEPT 
-A INPUT -p udp --dport 1514 -s 10.0.0.0/16 -j ACCEPT
```
Bu örnekte 10.0.0.0/16 networkünden upd 1514 ve 514 için izin verilmektedir.

#Manager / Agent Mode Kurulumu

Bu aşamda öncelikle Ossec Server (Manager) kurulumu yapacağız.

İlk işlem Ossec paketinin download edilmesidir. Şu anki son Ossec sürümü 2.8 olsa da download etmeden önce yeni bir sürüm çıkıp çıkmadığını http://ossec.github.io/downloads.html adresinden kontrol etmeyi ihmal etmeyin.

Şimdi hem ossec paketini hem de indirdiğimiz paketi doğrulamak için kullanacağımız checksum dosyasını indirelim:

```
# wget http://www.ossec.net/files/ossec-hids-2.8.tar.gz 
# wget http://www.ossec.net/files/ossec-hids-2.8-checksum.txt
```
ve hem md5 hem de sha1 hashlerini kontrol edelim:
```
# cat ossec-hids-2.8-checksum.txt 
MD5(ossec-hids-2.8.tar.gz)= b0a9268e9dfc0ca4c31a3c8df4d17a9e 
SHA1(ossec-hids-2.8.tar.gz)= fb82bf984ddb77399be20ab9d2181a8b7ebccac3  

# md5sum ossec-hids-2.8.tar.gz 
b0a9268e9dfc0ca4c31a3c8df4d17a9e ossec-hids-2.8.tar.gz  

# sha1sum ossec-hids-2.8.tar.gz 
fb82bf984ddb77399be20ab9d2181a8b7ebccac3 ossec-hids-2.8.tar.gz
```

Doğrulama işleminin ardından Ossec Server kurulumunu başlatacağız. Kurulum install.sh scripti üzerinden gerçekleştirildiği için süreç oldukça kolaydır.

Download ettiğimiz paketi açıyoruz:
```
# tar xvfz ossec-hids-2.8.tar.gz
```
Normalde ossec dizini içerisindeki install.sh scriptini çalıştırıp yönergeleri takip etmek kurulum için yeterli ancak biz MySQL destekli kurulum yapacağımız için öncesinde Ossec’in db desteğini etkinleştiriyoruz:

```
# cd ossec-hids-2.7.1 
# cd src; make setdb
```
Sonrasında src dizininden bir üst dizine çıkıyoruz ve normal bir şekilde install.sh üzerinden kurulumu başlatıyoruz:

```
# cd .. 
# bash install.sh
```

Bu komutu verdiğiniz zaman ilk olarak kurulumu hangi dilde yapmak istediğimizi soran çıktı gelecektir: Türkçe de seçebilirsiniz ancak ben uygulamanın kendi diline sadık kalmayı tercih ederek “en” diyerek devam ediyorum:

```
** Para instalação em português, escolha [br]. 
** 要使用中文进行安装, 请选择 [cn]. 
** Fur eine deutsche Installation wohlen Sie [de]. 
** Για εγκατάσταση στα Ελληνικά, επιλέξτε [el]. 
** For installation in English, choose [en]. 
** Para instalar en Español , eliga [es]. 
** Pour une installation en français, choisissez [fr] 
** A Magyar nyelvű telepítéshez válassza [hu]. 
** Per l'installazione in Italiano, scegli [it]. 
** 日本語でインストールします．選択して下さい．[jp]. 
** Voor installatie in het Nederlands, kies [nl]. 
** Aby instalować w języku Polskim, wybierz [pl]. 
** Для инструкций по установке на русском ,введите [ru]. 
** Za instalaciju na srpskom, izaberi [sr]. 
** Türkçe kurulum için seçin [tr]. 
(en/br/cn/de/el/es/fr/hu/it/jp/nl/pl/ru/sr/tr) [en]: en
```
Dili seçtikten sonra aşağıdaki karşılama ekranı gelecektir. Bu ekranda ENTER ile devam ediyoruz.

```
OSSEC HIDS v2.7.1 Installation Script - http://www.ossec.net  

You are about to start the installation process of the OSSEC HIDS. You must have a C compiler pre-installed in your system. If you have any questions or comments, please send an e-mail to dcid@ossec.net (or daniel.cid@gmail.com).  

- System: Linux CromLab-OssecManager 2.6.32-431.11.2.el6.x86_64 
- User: root 
- Host: CromLab-OssecManager  

-- Press ENTER to continue or Ctrl-C to abort. --
```

Ardından ne tip bir kurulum yapmak istediğimizi soran aşağıdaki çıktı görüntülenecektir. Biz server kurulumu yaptığımız için burada “server” yazıp enter ile devam ediyoruz:
```
1- What kind of installation do you want (server, agent, local, hybrid or help)? server
```

Ardından, Ossec’in nereye kurulmasını istediğinizi soran aşağıdaki ekran gelecektir. Burayı default olarak bırakalım, bu yüzden “ENTER” ile devam ediyoruz:

```
2- Setting up the installation environment.  

- Choose where to install the OSSEC HIDS [/var/ossec]:
```

Üçüncü bölüm HIDS yapılandırmaları ile ilgili bölümdür ve ilk olarak aşağıdaki ekran çıktısı ile uyarıları email olarak alıp almak istemediğimiz sorulacaktır. Bu kısımda “y” ile email notification özelliğini devreye alalım; emaillerin gönderilmesini istediğimiz posta adresini ve posta sunucumuzun ip adresini girelim. Bu noktada posta sunucusu olarak relay izniniz olan bir sunucu kullanabilir ya da localhost üzerinden gönderilmesini sağlayabilirsiniz.

```
3- Configuring the OSSEC HIDS.  

3.1- Do you want e-mail notification? (y/n) [y]: y 
- What's your e-mail address? email@adresiniz.com 
- What's your SMTP server ip/host? 127.0.0.1
```

Bir sonraki tanımlama aşağıdaki çıktıda görüldüğü gibi dosya bütünlük kontrolünü devreye almak isteyip istemediğimizi soran bölümdür ki burada “y” diyerek bu özelliği aktif ediyoruz.

```
3.2- Do you want to run the integrity check daemon? (y/n) [y]: y  

- Running syscheck (integrity check daemon).
```

Ardından, benzer şekilde rootkit detection özelliğini aktifleştirmek isteyip istemediğimiz sorulur; buna da “y” diyoruz.

```
3.3- Do you want to run the rootkit detection engine? (y/n) [y]: y  

- Running rootcheck (rootkit detection).
```

Bir sonraki aşama active response özelliğini kullanmak isteyip istemediğimizi sorar. Bu konu gelişmiş ve hata durumunda problemlere neden olabilecek bir konu olduğu için bu yazıda devreye almayacağız (Bu konuya ayrı bir makale ile değineceğim). Bu nedenle “n” diyelim.

```
3.4- Active response allows you to execute a specific command based on the events received. For example,  you can block an IP address or disable access for  a specific user.  

More information at:  http://www.ossec.net/en/manual.html#active-response  - Do you want to enable active response? (y/n) [y]: n
```

Bir sonraki tanımlama uzak sistemlerden syslog üzerinden log alıp almak istemediğimiz sorar. Bu özelliği “y” diyerek aktif hale getiriyoruz:

```
3.5- Do you want to enable remote syslog (port 514 udp)? (y/n) [y]:  

- Remote syslog enabled
```

Son çıktı ise aşağıda görüldüğü gibi hangi logların analiz edileceğini belirten ve “ENTER” ile devam edeceğimiz kısımdır.

```
3.6- Setting the configuration to analyze the following logs: 
-- /var/log/messages 
-- /var/log/secure 
-- /var/log/maillog  

- If you want to monitor any other file, just change the ossec.conf and add a new localfile entry. Any questions about the configuration can be answered by visiting us online at http://www.ossec.net .  

--- Press ENTER to continue ---
```

Bundan sonra kurulum işlemine başlanacaktır ve tamamlandıktan sonra aşağıdaki bilgi ekranı görüntülenecektir.

```
- System is Redhat Linux. 
- Init script modified to start OSSEC HIDS during boot.  
- Configuration finished properly.  
- To start OSSEC HIDS: /var/ossec/bin/ossec-control start  
- To stop OSSEC HIDS: /var/ossec/bin/ossec-control stop  
- The configuration can be viewed or modified at /var/ossec/etc/ossec.conf  

Thanks for using the OSSEC HIDS. If you have any question, suggestion or if you find any bug, contact us at contact@ossec.net or using our public maillist at ossec-list@ossec.net ( http://www.ossec.net/main/support/ ).  More information can be found at http://www.ossec.net
```

Normalde bu aşamada kurulum tamamlanmış oluyor, ancak biz agentlardan gelen alarmları ve tüm bilgileri MySQL db’sinde tutmak istediğimiz için Ossec’i bu yönde yapılandırmamız gerekiyor.

Bunun için önelikle MySQL’de ossec için bir db oluşturacağız ve bir user/pass belirleyeceğiz. Bu iş için mysql sunucusuna bağlanın:

```
# mysql -u root -p
```

ve db ve kullanıcı oluşturma işlemlerini “kırmızı renkli alanları kendinize göre düzenledikten sonra” gerçekleştirin:

```
mysql> create database ossec; 
mysql> grant INSERT,SELECT,UPDATE,CREATE,DELETE,EXECUTE on ossec.* to ossecuser@<ossec-ip>; 
mysql> set password for ossecuser@<ossec-ip>=PASSWORD('ossecpass'); 
mysql> flush privileges; 
mysql> quit
```
Şimdi oluşturduğumuz db’yi ossec kaynak kodlarının bulunduğu dizindeki “src/os_dbd” dizini içerisinde bulunan mysql.schema dosyasını kullanarak populate edeceğiz:

```
# cd ~/ossec-hids-2.8/src/os_dbd 
# mysql -u root -p ossec < mysql.schema
```

Böylece ilgili db’de gerekli tablolar oluşturulmuş olacaktır.

Şimdi, Ossec’in ana yapılandırma dosyasına db’ye nasıl bağlanacağını bildiren tanım satırlarını ekleyeceğiz. Conf dosyasını editleyelim:

```
# vi /var/ossec/etc/ossec.conf
```

ve en üstteki global bölümünün bittiği yerin hemen altına aşağıdaki ibareleri “db ve user bilgilerini kendimize göre düzenledikten sonra” ekleyelim.

```
<database_output> 
  <hostname>server-ip</hostname> 
  <username>ossecuser</username> 
  <password>ossecpass</password> 
  <database>ossec</database> 
  <type>mysql</type> 
</database_output>
```
Son olarak Ossec’in db desteğini etkinleştiriyoruz:
```
# /var/ossec/bin/ossec-control enable database
```

Bu şekilde kurulum tamamlanmış oluyor. Şimdi Ossec’i startup’e ekleyip servisi başlatacağız:

```
# chkconfig ossec on 
# /var/ossec/bin/ossec-control restart
```

erşey yolunda gittiyse servis normal bir şekilde çalışıyor olmalıdır. Bu aşamada, Ossec Server kurulumu tamamlanmış oluyor ve Ossec kendi localhost’unu monitor etmeye başlıyor.

Örnek olarak sisteme bir user eklerseniz, bununla ilgili bilgiler hem db’ye yazılacak hem de size bir email olarak bildirilecektir. (Yapılandırmada email ayarlarınızı düzgün yaptığınıza emin olun.)

DB’de tüm loglar data tablosuna yazılmaktadır. Kontrol etmek için ilgili tabloyu sorgulayabilirsiniz:

```
# mysql -u root -p -e 'use ossec; select * from data
```


Herşey yolunda gittiyse çıktı olarak, Ossec’in başlatıldığını ifade eden bir log kaydı görmeniz gerekir.

#### Agent Tarafındaki Yapılandırma İşlemleri
Bahsettiğimiz gibi Ossec agent’larda tüm yapılandırma /var/ossec/etc/ossec.conf dosyasında bulunmaktadır. Yapılandırmayı Ossec Server’dan merkezi olarak düzenlemek istemeniz durumunda ilgili dosya içerisinde sadece Ossec Server’ın IP’sinin belirtildiği bölümün -ve varsa command ile full_command bölümlerinin- kalması yeterlidir.

Örnek bir ossec.conf şu şekilde olmalıdır:

```
<ossec_config>
  <client>
    <server-ip>10.10.12.200</server-ip>
  </client>
</ossec_config>
```
Ana yapılandırma içerisinde command ve full-command komutları da varsa (ki defaulf kurulumda gelir), aynı şekilde ilgil bölümleri <ossec_config></ossec_config> tagleri içerisine yazmanız gerekmektedir. Bu gibi bir yapılandırma için conf şu şekilde olmalıdır:
```
<ossec_config>
  <client>
    <server-ip>10.10.12.200</server-ip>
  </client>

  <localfile>
    <log_format>command</log_format>
    <command>df -h</command>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tan |grep LISTEN |grep -v 127.0.0.1 | sort</command>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 5</command>
  </localfile>
  
</ossec_config>
```

Agent tarafında zorunlu olarak yapılması gereken tanımlamalar bundan ibarettir.

#### Server Tarafındaki Yapılandırma İşlemleri
Ossec Server tarafında tüm işlemler /var/ossec/etc/shared/agent.conf içerisinde yapılmaktadır. Örnek olarak ismi agent001 olan bir host için default monitoring yapılandırması şu şekilde olmalıdır:

```
<agent_config name="agent001"> 
 <syscheck>
    <!-- Frequency that syscheck is executed - default to every 22 hours -->
    <frequency>79200</frequency>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/mnttab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>

    <!-- Windows files to ignore -->
    <ignore>C:\WINDOWS/System32/LogFiles</ignore>
    <ignore>C:\WINDOWS/Debug</ignore>
    <ignore>C:\WINDOWS/WindowsUpdate.log</ignore>
    <ignore>C:\WINDOWS/iis6.log</ignore>
    <ignore>C:\WINDOWS/system32/wbem/Logs</ignore>
    <ignore>C:\WINDOWS/system32/wbem/Repository</ignore>
    <ignore>C:\WINDOWS/Prefetch</ignore>
    <ignore>C:\WINDOWS/PCHEALTH/HELPCTR/DataColl</ignore>
    <ignore>C:\WINDOWS/SoftwareDistribution</ignore>
    <ignore>C:\WINDOWS/Temp</ignore>
    <ignore>C:\WINDOWS/system32/config</ignore>
    <ignore>C:\WINDOWS/system32/spool</ignore>
    <ignore>C:\WINDOWS/system32/CatRoot</ignore>
  </syscheck>

  <rootcheck>
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <system_audit>/var/ossec/etc/shared/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_debian_linux_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_rhel_linux_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_rhel5_linux_rcl.txt</system_audit>
  </rootcheck>

  <active-response>
    <disabled>yes</disabled>
  </active-response>

  <!-- Files to monitor (localfiles) -->

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/authlog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/xferlog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/maillog</location>
  </localfile>
</agent_config>
```

Gördüğünüz gibi ilgili yapılandırma, aslında agent tarafında tanımladığımız yapılandırmanın aynısı. Burada sadece <agent_config name=”agent001“> şeklinde agent’imizin ismini belirterek yapılandırmanın sadece ilgili agent’a uygulanması gerektiğini söylüyoruz.

Bu şekilde birden çok host için tanımlama <agent_config name=”agent ismi“> </agent_config> şeklindeki tagler içerisine yazılarak spefisik olarak tanımlanabilmektedir. OS bazlı tanımlama için ise <agent_config os=”Linux (ya da) Windows“> şeklinde bir kategorizasyon uygulanabilmektedir.

Tanımlamaların ardından, hem server hem de agent tarafından ossec servisinin restart edilmesi gerekiyor:
```
/var/ossec/bin/ossec-control restart
```

Bu şekilde yapılandırma merkezi bir şekilde düzenlenmiş oluyor.
Not: Ossec kendi içerisinde bir caching mekanizması kullandığından dolayı değişikliklerin yansıması biraz zaman alabilmektedir.
