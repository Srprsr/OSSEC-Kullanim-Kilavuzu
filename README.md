# OSSEC Kullanım Kılavuzu
Özellikle dağıtık yapılarda, sunucu güvenliği konusunda süreklilik sağlamak en önemli noktalardan birisidir. Zira, tüm sistemlerin bir şekilde izlenmesi ve olası anormalliklerin oldukları an tespit edilip müdahale edilmesi olası servis kesintilerini oluşmadan engellemek üzerine kurulu proaktif sistem yönetiminin başlıca kurallarından birisidir. Bu noktada network trafiğini izleyerek saldırı tespiti yapmanın yanı sıra her bir sunucu/cihaz üzerinde de bir HIDS (host-based intrusion detection) uygulaması kullanarak log monitoring, dosya bütünlük kontrolü ve rootkit tespiti gibi genel işlemler gerçekleştirilmelidir.
# OSSEC Nedir?
OSSEC, Trend Micro tarafından desteklenen, tamamen açık kaynak kodlu, standalone çalışabildiği gibi, agent/master yapısı ile merkezi yönetim de sağlayabilen bir host-based saldırı tespit sistemidir. Temel olarak log analizi, dosya bütünlük kontrolü, rootkit tespiti, gerçek zamanlı alarm üretme ve tespit edilen saldırılara karşılık active response özelliği ile aksiyonlar alma gibi görevleri yerine getiren OSSEC, hali hazırda kullanılan SIM/SIEM platformları ile de entegre edilebilmektedir.

 OSSEC, native olarak  tüm *nix ( Linux, MacOS, Solaris, HP-UX, AIX, Vmware ESX) ve Windows platformlarda çalışabilmekte, agentless modu sayesinde de router, switch gibi network cihazlarını da monitor edebilmektedir.

# TEMEL ÖZELLİKLERİ
* Unordered sub-list.
* * Unordered sub-list.
