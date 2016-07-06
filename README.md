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

##Rootkit Detection
OSSEC’in bir diğer görevi de sistemlerde periyodik olarak rootkit taraması yapmaktır. Bu şekilde sunucuların herhangi birinde  bir rootkit, trojan ya da virus’ün varlığı anında tespit edilir ve bildirilir.

##Active Response
OSSEC’in aktive response özelliği sistemde oluşan bir problem için otomatik aksiyonlar almak üzere kullanılmaktadır. Örneğin web sunucunuzu tarayan bir saldırgan’ı, web loglarından tespit edip saldırgan’ın *ip adresinin firewall üzerinden bloklanması OSSEC’in active response özelliği* ile mümkündür.

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
