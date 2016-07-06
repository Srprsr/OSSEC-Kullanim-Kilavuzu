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

  <div class="section" id="log-monitoring-analysis">

# Log monitoring/analysis[¶](#log-monitoring-analysis "Permalink to this headline")

Log Analysis (or log inspection) is done inside OSSEC by the logcollector and analysisd processes. The first one collects the events and the second one analyzes (decodes, filters and classifies) them.

It is done in real time, so as soon as an event is written OSSEC will process them. OSSEC can read events from internal log files, from the Windows event log and also receive them directly via remote syslog.

<div class="section" id="what-is-log-analysis">

## What is log analysis?[¶](#what-is-log-analysis "Permalink to this headline")

Inside OSSEC we call log analysis a LIDS, or log-based intrusion detection. The goal is to detect attacks, misuse or system errors using the logs.

LIDS - Log-based intrusion detection or security log analysis are the processes or techniques used to detect attacks on a specific network, system or application using logs as the primary source of information. It is also very useful to detect software misuse, policy violations and other forms of inappropriate activities.

</div>

<div class="section" id="quick-facts">

## Quick Facts[¶](#quick-facts "Permalink to this headline")

*   How often are logs monitored?
    *   In real time.
*   Where are the events analyzed?
    *   In the manager.
*   How long are they stored?
    *   For as long as your policy dictates (it is user configurable).
*   Where does this help me with compliance?
    *   (PCI DSS, etc) It helps with the whole section 10 (log monitoring) of PCI.
*   How much CPU does it use?
    *   On the agent, it uses very little CPU/memory since it just read the events and forwards them to the manager.
    *   On the manager, it depends on the number of events per second (EPS).
*   How does it deal with false positives?
    *   False positives can be eliminated using local rules.

</div>

<div class="section" id="configuration-options">

## Configuration Options[¶](#configuration-options "Permalink to this headline")

These options should be specified locally in each agent’s ossec.conf file or the share agent.conf. Inside the `<span class="pre"><localfile></span>` element, you can have the following options.

<dl class="element">

<dt id="element-localfile">`localfile`[¶](#element-localfile "Permalink to this definition")</dt>

</dl>

<dl class="element">

<dt id="element-location">`location`[¶](#element-location "Permalink to this definition")</dt>

<dd>

Specify the location of the log to be read. strftime formats may be used for log file names. For instance, a log file named `<span class="pre">file.log-2011-01-22</span>` could be referenced with `<span class="pre">file.log-%Y-%m-%d</span>`. Wildcards may be used on non-Windows systems. When wildcards are used, the log files must exist at the time `<span class="pre">ossec-logcollector</span>` is started. It will not automatically begin monitoring new log files. `<span class="pre">strftime</span>` and wildcards cannot be used on the same entry.

**Default:** Multiple (eg /var/log/messages)

**Allowed:** Any log file

</dd>

</dl>

<dl class="element">

<dt id="element-log_format">`log_format`[¶](#element-log_format "Permalink to this definition")</dt>

<dd>

The format of the log being read.

<div class="admonition note alert alert-info">

Note

If the log has one entry per line, use syslog.

</div>

**Default:** syslog

**Allowed:**

> <div>
> 
> *   <dl class="first docutils">
>     
>     <dt>syslog</dt>
>     
>     
>     
>     <dd>
>     
>     This format is for plain text files in a syslog-like format. It can also be used when there is no support for the logging format, and the logs are single line messages.
>     
>     </dd>
>     
>     </dl>
>     
>     
> 
> *   <dl class="first docutils">
>     
>     <dt>snort-full</dt>
>     
>     
>     
>     <dd>
>     
>     This is used for Snort’s full output format.
>     
>     </dd>
>     
>     </dl>
>     
>     
> 
> *   <dl class="first docutils">
>     
>     <dt>snort-fast</dt>
>     
>     
>     
>     <dd>
>     
>     This is used for Snort’s fast output format.
>     
>     </dd>
>     
>     </dl>
>     
>     
> 
> *   squid
> 
> *   iis
> 
> *   <dl class="first docutils">
>     
>     <dt>eventlog</dt>
>     
>     
>     
>     <dd>
>     
>     This is used for Microsoft Windows eventlog format.
>     
>     </dd>
>     
>     </dl>
>     
>     
> 
> *   <dl class="first docutils">
>     
>     <dt>eventchannel</dt>
>     
>     
>     
>     <dd>
>     
>     This is used for Microsoft Windows eventlogs, using the new EventApi. This allows OSSEC to monitor both standard “Windows” eventlogs and more recent “Application and Services” logs. This support was added in 2.8.
>     
>     </dd>
>     
>     </dl>
>     
>     
> 
> <div class="admonition warning alert alert-warning">
> 
> Warning
> 
> `<span class="pre">eventchannel</span>` cannot be used on Windows systems older than Vista.
> 
> </div>
> 
> *   <dl class="first docutils">
>     
>     <dt>mysql_log</dt>
>     
>     
>     
>     <dd>
>     
>     This is used for [MySQL](http://dev.mysql.com/) logs. It does not support multi-line logs.
>     
>     </dd>
>     
>     </dl>
>     
>     
> 
> *   <dl class="first docutils">
>     
>     <dt>postgresql_log</dt>
>     
>     
>     
>     <dd>
>     
>     This is used for [PostgreSQL](http://www.postgresql.org) logs. It does not support multi-line logs.
>     
>     </dd>
>     
>     </dl>
>     
>     
> 
> *   <dl class="first docutils">
>     
>     <dt>nmapg</dt>
>     
>     
>     
>     <dd>
>     
>     This is used for monitoring files conforming to the grepable output from [nmap](http://nmap.org).
>     
>     </dd>
>     
>     </dl>
>     
>     
> 
> *   apache
>     
>     
>     
>     > <div>
>     > 
>     > This format is for apache’s default log format.
>     > 
>     > **Example:**
>     > 
>     > <div class="highlight-console">
>     > 
>     > <div class="highlight">
>     > 
>     > <pre><span></span><span class="go">[Wed Jun  9 23:32:26 2010] [error] [client 192.168.1.100] File does not exist: /htdocs/favicon.ico</span>
>     > </pre>
>     > 
>     > </div>
>     > 
>     > </div>
>     > 
>     > **Example:**
>     > 
>     > <div class="highlight-console">
>     > 
>     > <div class="highlight">
>     > 
>     > <pre><span></span><span class="go">192.168.1.100 - - [21/Jan/2010:08:31:09 -0500] "GET / HTTP/1.0" 200 2212</span>
>     > </pre>
>     > 
>     > </div>
>     > 
>     > </div>
>     > 
>     > </div>
>     
>     
> 
> *   <dl class="first docutils">
>     
>     <dt>command</dt>
>     
>     
>     
>     <dd>
>     
>     This format will be the output from the command (as run by root) defined by [command](#command). Each line of output will be treated as a separate log.
>     
>     </dd>
>     
>     </dl>
>     
>     
> 
> *   <dl class="first docutils">
>     
>     <dt>full_command</dt>
>     
>     
>     
>     <dd>
>     
>     This format will be the output from the command (as run by root) defined by [command](#command). The entire output will be treated as a single log.
>     
>     </dd>
>     
>     </dl>
>     
>     
> 
> <div class="admonition warning alert alert-warning">
> 
> Warning
> 
> `<span class="pre">command</span>` and `<span class="pre">full_command</span>` cannot be used in the agent.conf, and must be configured in each system’s ossec.conf.
> 
> </div>
> 
> *   djb-multilog
> 
> *   <dl class="first docutils">
>     
>     <dt>multi-line</dt>
>     
>     
>     
>     <dd>
>     
>     This option will allow applications that log multiple lines per event to be monitored. This format requires the number of lines to be consistent. `<span class="pre">multi-line:</span>` is followed by the number of lines in each log entry. Each line will be combined with the previous lines until all lines are gathered. There may be multiple timestamps in a finalized event.
>     
>     
>     
>     **Allowed:** <log_format>multi-line: NUMBER</log_format>
>     
>     
>     
>     <dl class="last docutils">
>     
>     <dt>**Example:**</dt>
>     
>     
>     
>     <dd>
>     
>     Log messages:
>     
>     
>     
>     <div class="highlight-console">
>     
>     <div class="highlight">
>     
>     <pre><span></span><span class="go">Aug  9 14:22:47 hostname log line one</span>
>     <span class="go">Aug  9 14:22:47 hostname log line two</span>
>     <span class="go">Aug  9 14:22:47 hostname log line three</span>
>     <span class="go">Aug  9 14:22:47 hostname log line four</span>
>     <span class="go">Aug  9 14:22:47 hostname log line five</span>
>     </pre>
>     
>     </div>
>     
>     </div>
>     
>     
>     
>     Log message as analyzed by [<span class="problematic" id="id2">ossec-analysisd_</span>](#id1):
>     
>     
>     
>     <div class="last highlight-console">
>     
>     <div class="highlight">
>     
>     <pre><span></span><span class="go">Aug  9 14:22:47 hostname log line one Aug  9 14:22:47 hostname log line two Aug  9 14:22:47 hostname log line three Aug  9 14:22:47 hostname log line four Aug  9 14:22:47 hostname log line five</span>
>     </pre>
>     
>     </div>
>     
>     </div>
>     
>     </dd>
>     
>     </dl>
>     
>     </dd>
>     
>     </dl>
>     
>     
> 
> </div>

</dd>

</dl>

<span class="target" id="command"></span>

<dl class="element">

<dt id="element-command">`command`[¶](#element-command "Permalink to this definition")</dt>

<dd>

The command to be run. All output from this command will be read as one or more log messages depending on whether command or [full_command](#full-command) is used.

**Allowed:** Any commandline and arguments.

</dd>

</dl>

<span class="target" id="command-alias"></span>

<dl class="element">

<dt id="element-alias">`alias`[¶](#element-alias "Permalink to this definition")</dt>

<dd>

An alias to identify the command. This will replace the command in the log message.

For example `<span class="pre"><alias>usb-check</alias></span>` would replace:

<div class="highlight-console">

<div class="highlight">

<pre><span></span><span class="go">ossec: output: 'reg QUERY HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR':</span>
</pre>

</div>

</div>

with:

<div class="highlight-console">

<div class="highlight">

<pre><span></span><span class="go">ossec: output: 'usb-check':</span>
</pre>

</div>

</div>

**Allowed:** Any string.

</dd>

</dl>

<span class="target" id="command-frequency"></span>

<dl class="element">

<dt id="element-frequency">`frequency`[¶](#element-frequency "Permalink to this definition")</dt>

<dd>

The minimum time in seconds between command runs. The command will probably not run every `<span class="pre">frequency</span>` seconds exactly, but the time between runs will not be shorter than this setting. This is used with [command](#command) and [full_command](#full-command).

**Allowed:** Time in seconds.

</dd>

</dl>

<span class="target" id="check-diff"></span>

<dl class="element">

<dt id="element-check_diff">`check_diff`[¶](#element-check_diff "Permalink to this definition")</dt>

<dd>

The output from an event will be stored in an internal database. Every time the same event is received, the output is compared to the previous output. If the output has changed an alert will be generated.

</dd>

</dl>

<span class="target" id="only-future-events"></span>

<dl class="element">

<dt id="element-only-future-events">`only-future-events`[¶](#element-only-future-events "Permalink to this definition")</dt>

<dd>

Only used with the `<span class="pre">eventchannel</span>` log format. By default, when OSSEC starts the eventchannel log format will read all events that ossec-logcollector missed since it was last stopped. It is possible to set `<span class="pre">only-future-events</span>` to `<span class="pre">yes</span>` in order to prevent this behaviour. When set to `<span class="pre">yes</span>`, OSSEC will only receive events that occured after the start of logcollector.

<div class="highlight-console">

<div class="highlight">

<pre><span></span><span class="go"><localfile></span>
 <span class="go"><location>System</location></span>
 <span class="go"><log_format>eventchannel</log_format></span>
 <span class="go"><only-future-events>yes</only-future-events></span>
<span class="go"></localfile></span>
</pre>

</div>

</div>

</dd>

</dl>

<span class="target" id="query"></span>

<dl class="element">

<dt id="element-query">`query`[¶](#element-query "Permalink to this definition")</dt>

<dd>

Only used with the `<span class="pre">eventchannel</span>` log format. It is possible to specify an XPATH query following the event schema (see [Microsoft’s documentation](http://msdn.microsoft.com/en-us/library/windows/desktop/aa385201%28v=vs.85%29.aspx)) in order to filter the events that OSSEC will process.

For example, the following configuration will only process events with an ID of 7040:

<div class="highlight-console">

<div class="highlight">

<pre><span></span><span class="go"><localfile></span>
 <span class="go"><location>System</location></span>
 <span class="go"><log_format>eventchannel</log_format></span>
 <span class="go"><query>Event/System[EventID=7040]</query></span>
<span class="go"></localfile></span>
</pre>

</div>

</div>

</dd>

</dl>

</div>

<div class="section" id="monitoring-logs">

## Monitoring logs[¶](#monitoring-logs "Permalink to this headline")

With in OSSEC there are two major methods for monitoring logs: file and process. Each method has its own page and examples.

<div class="toctree-wrapper compound">

*   [Process Monitoring](process-monitoring.html)
    *   [Overview](process-monitoring.html#overview)
    *   [Configuration examples](process-monitoring.html#configuration-examples)
        *   [Disk space utilization (df -h) example](process-monitoring.html#disk-space-utilization-df-h-example)
        *   [Load average (uptime) Example](process-monitoring.html#load-average-uptime-example)
        *   [Alerting when output of a command changes](process-monitoring.html#alerting-when-output-of-a-command-changes)
        *   [Detecting USB Storage Usage](process-monitoring.html#detecting-usb-storage-usage)
*   [File Monitoring](file-log-monitoring.html)
    *   [Overview](file-log-monitoring.html#overview)
    *   [Configuration](file-log-monitoring.html#configuration)
    *   [Configuration examples](file-log-monitoring.html#configuration-examples)
        *   [Simple example](file-log-monitoring.html#simple-example)
        *   [Windows EventLog Example](file-log-monitoring.html#windows-eventlog-example)
        *   [Windows EventChannel Example](file-log-monitoring.html#windows-eventchannel-example)
        *   [Multiple Files Example](file-log-monitoring.html#multiple-files-example)
        *   [Date Based Example](file-log-monitoring.html#date-based-example)
        *   [IIS Logs Example](file-log-monitoring.html#iis-logs-example)

</div>

</div>

</div>

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
