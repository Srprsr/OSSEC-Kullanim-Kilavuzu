# OSSEC Kullanım Kılavuzu
Özellikle dağıtık yapılarda, sunucu güvenliği konusunda süreklilik sağlamak en önemli noktalardan birisidir. Zira, tüm sistemlerin bir şekilde izlenmesi ve olası anormalliklerin oldukları an tespit edilip müdahale edilmesi olası servis kesintilerini oluşmadan engellemek üzerine kurulu proaktif sistem yönetiminin başlıca kurallarından birisidir. Bu noktada network trafiğini izleyerek saldırı tespiti yapmanın yanı sıra her bir sunucu/cihaz üzerinde de bir **HIDS (host-based intrusion detection)** uygulaması kullanarak log monitoring, dosya bütünlük kontrolü ve rootkit tespiti gibi genel işlemler gerçekleştirilmelidir.

![alt text](https://glynrob.com/wp-content/uploads/ossec-hids.jpg "OSSEC Logo")
# OSSEC Nedir?
OSSEC, Trend Micro tarafından desteklenen, tamamen açık kaynak kodlu, standalone çalışabildiği gibi, agent/master yapısı ile merkezi yönetim de sağlayabilen bir host-based saldırı tespit sistemidir. Temel olarak log analizi, dosya bütünlük kontrolü, rootkit tespiti, gerçek zamanlı alarm üretme ve tespit edilen saldırılara karşılık active response özelliği ile aksiyonlar alma gibi görevleri yerine getiren OSSEC, hali hazırda kullanılan SIM/SIEM platformları ile de entegre edilebilmektedir.

 **OSSEC, native olarak  tüm *nix ( Linux, MacOS, Solaris, HP-UX, AIX, Vmware ESX) ve Windows platformlarda çalışabilmekte**, agentless modu sayesinde de router, switch gibi network cihazlarını da monitor edebilmektedir.
 
 
 # QUICK INSTALL
 
 ```
$ (ossec_version="2.8.2" ; ossec_checksum="a0f403270f388fbc6a0a4fd46791b1371f5597ec" ; cd /tmp/ && wget https://github.com/ossec/ossec-hids/archive/${ossec_version}.tar.gz && mv ${ossec_version}.tar.gz ossec-hids-${ossec_version}.tar.gz && checksum=$(sha1sum ossec-hids-${ossec_version}.tar.gz | cut -d" " -f1); if [ $checksum == $ossec_checksum ]; then tar xfz ossec-hids-${ossec_version}.tar.gz && cd ossec-hids-${ossec_version} && sudo ./install.sh ; else "Wrong checksum. Download again or check if file has been tampered with."; fi)

```

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
