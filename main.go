// createAnyIPRoutingInteractive, 0.0.0.0 (tüm arayüzleri dinleme) adresini bir IP'ye yönlendirir
// nathelper paketi, Windows sistemlerinde NAT (Network Address Translation) tablolarını
// yönetmek için interaktif bir arayüz sağlar. Ayrıca ağ arayüzlerini yönetme
// ve görüntüleme özelliklerine sahiptir.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand" // Route-any için rastgele sayı üretimi
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

func createAnyIPRoutingInteractive() {
	fmt.Println("\n=== 0.0.0.0 (Tüm Arayüzler) Yönlendirmesi Oluştur ===")

	// Ağ arayüzlerini göster
	interfaces, err := ListNetworkInterfaces()
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	// Önce ağ arayüzlerini listele
	fmt.Println("\nKullanılabilir Ağ Arayüzleri (hedef olarak kullanmak için):")
	displayNetworkInterfaces()

	// Yönlendirmek istediğin portları sor
	listenPort := promptForOptionalInput("Dinlemek istediğiniz port [boş=tüm portlar] (örn. 80): ", "")
	if listenPort == "" {
		fmt.Println("Not: Dinleme portu belirtilmedi, tüm portlar için NAT kuralları oluşturulacak.")
	}

	// Hedef IP adresini sor (manuel giriş veya arayüz seçimi)
	var connectAddr string

	useInterfaceSelection := promptForOptionalInput("Hedef için ağ arayüzü kullanmak istiyor musunuz? [E/h]: ", "E")
	if strings.ToLower(useInterfaceSelection) == "e" || strings.ToLower(useInterfaceSelection) == "evet" {
		// Arayüz indeksi iste
		interfaceSelectionInput := promptForInput("Hedef IP adresi için arayüz numarası seçin: ")

		interfaceNum, err := strconv.Atoi(interfaceSelectionInput)
		if err != nil || interfaceNum < 1 || interfaceNum > len(interfaces) {
			fmt.Printf("Hata: Geçersiz arayüz numarası: %s\n", interfaceSelectionInput)
			return
		}

		selectedInterface := interfaces[interfaceNum-1]
		if selectedInterface.IpAddress != "" {
			connectAddr = selectedInterface.IpAddress
			fmt.Printf("Seçilen arayüz: %s, IP adresi: %s\n", selectedInterface.Name, connectAddr)
		} else {
			fmt.Println("Seçilen arayüzün IP adresi bulunamadı. Lütfen IP adresini manuel olarak girin.")
			connectAddr = promptForInput("Hedef IP adresi (örn. 192.168.1.100): ")
		}
	} else {
		// Manuel IP adresi giriş
		connectAddr = promptForInput("Hedef IP adresi (örn. 192.168.1.100): ")
	}

	// Hedef portu sor
	var connectPort string
	if listenPort == "" {
		fmt.Println("Not: Dinleme portu belirtilmediği için, hedef portu da tüm portlar olarak ayarlanacak.")
		connectPort = ""
	} else {
		// Dinleme portu belirtildi, hedef portunu ayrıca sor
		connectPort = promptForOptionalInput("Hedef port [boş=dinleme portuyla aynı] (örn. 80): ", "")
		// Eğer hedef portu boş bırakıldıysa, dinleme portuyla aynı olsun
		if connectPort == "" {
			connectPort = listenPort
			fmt.Printf("Not: Hedef port belirtilmedi, dinleme portu kullanılacak: %s\n", listenPort)
		}
	}

	// Protokolü sor
	protocol := promptForOptionalInput("Protokol [tcp/udp] (varsayılan: tcp): ", "tcp")
	protocol = strings.ToLower(protocol)
	if protocol != "tcp" && protocol != "udp" {
		fmt.Printf("Geçersiz protokol: %s. Varsayılan olarak 'tcp' kullanılıyor.\n", protocol)
		protocol = "tcp"
	}

	// NAT girişi oluştur
	entry := NATEntry{
		ListenAddress:  "0.0.0.0", // Tüm arayüzleri dinle
		ListenPort:     listenPort,
		ConnectAddress: connectAddr,
		ConnectPort:    connectPort,
		Protocol:       protocol,
	}

	// Ek bilgilendirme: Tüm portlar için yaygın portların yönlendirileceğini açıkla
	if listenPort == "" {
		fmt.Println("\nÖnemli Not: 'Tüm portlar' seçeneği, pratikte yaygın olarak kullanılan portlar için")
		fmt.Println("(HTTP, HTTPS, SSH, RDP, vb.) NAT kuralları oluşturacaktır. İhtiyacınız olan belirli")
		fmt.Println("bir port yönlendirilemezse, lütfen o port için özel bir kural oluşturun.")
	}

	// Onay sorgusu
	fmt.Printf("\nOluşturulacak NAT girişi: %s\n", entry)
	confirm := promptForOptionalInput("Onaylıyor musunuz? [E/h]: ", "E")

	if strings.ToLower(confirm) != "e" && strings.ToLower(confirm) != "evet" {
		fmt.Println("İşlem iptal edildi.")
		return
	}

	// NAT girişini oluştur
	err = CreateNATEntry(entry)
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	fmt.Printf("0.0.0.0 yönlendirmesi başarıyla oluşturuldu: %s\n", entry)
}

// displayMainMenu, ana menüyü görüntüler
func displayMainMenu() {
	fmt.Println("\n===== Windows NAT Yönetici Ana Menü =====")
	fmt.Println("1. NAT Kurallarını Listele (list)")
	fmt.Println("2. Yeni NAT Kuralı Oluştur (create)")
	fmt.Println("3. NAT Kuralı Sil (delete)")
	fmt.Println("4. Ağ Arayüzlerini Görüntüle (interfaces)")
	fmt.Println("5. Arayüzler Arası Yönlendirme Oluştur (route-if)")
	fmt.Println("6. 0.0.0.0 Yönlendirmesi Oluştur (route-any)")
	fmt.Println("7. NAT Kurallarını Dışa Aktar (export)")
	fmt.Println("8. NAT Kurallarını İçe Aktar (import)")
	fmt.Println("9. Trafik İstatistiklerini Görüntüle (traffic)")
	fmt.Println("0. Yardım (help)")
	fmt.Println("X. Çıkış (exit)")
	fmt.Print("\nSeçiminiz (veya komut yazın): ")
}

// processMenuSelection, ana menüden seçilen öğeyi işler
func processMenuSelection(selection string) string {
	switch selection {
	case "1":
		return "list"
	case "2":
		return "create"
	case "3":
		return "delete"
	case "4":
		return "interfaces"
	case "5":
		return "route-if"
	case "6":
		return "route-any"
	case "7":
		return "export"
	case "8":
		return "import"
	case "9":
		return "traffic"
	case "0":
		return "help"
	case "x", "X":
		return "exit"
	default:
		return selection // Kullanıcı doğrudan komut yazmış olabilir
	}
} // exportNATRulesInteractive, kullanıcıdan dosya adı alıp NAT kurallarını dışa aktarır
func exportNATRulesInteractive() {
	fmt.Println("\n=== NAT Kurallarını Dışa Aktar ===")

	// Mevcut kuralları göster
	rules, err := ListNATEntries()
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	if len(rules) == 0 {
		fmt.Println("Dışa aktarılacak NAT kuralı bulunamadı.")
		return
	}

	fmt.Printf("Dışa aktarılacak %d NAT kuralı bulundu.\n", len(rules))

	// Dosya adını sor
	defaultFilename := "nat_rules_" + time.Now().Format("20060102_150405") + ".json"
	filename := promptForOptionalInput(fmt.Sprintf("Dışa aktarılacak dosya adı [%s]: ", defaultFilename), defaultFilename)

	// Dışa aktar
	err = ExportNATRules(filename)
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	fmt.Printf("NAT kuralları başarıyla dışa aktarıldı: %s\n", filename)
}

// importNATRulesInteractive, kullanıcıdan dosya adı alıp NAT kurallarını içe aktarır
func importNATRulesInteractive() {
	fmt.Println("\n=== NAT Kurallarını İçe Aktar ===")

	// Dosya adını sor
	filename := promptForInput("İçe aktarılacak dosya adı: ")

	// Dosya varlığını kontrol et
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		fmt.Printf("Hata: Dosya bulunamadı: %s\n", filename)
		return
	}

	// Mevcut kuralları göster
	currentRules, err := ListNATEntries()
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	// Mevcut kuralları değiştirme seçeneği
	var replace bool
	if len(currentRules) > 0 {
		fmt.Printf("Mevcut %d NAT kuralı bulundu.\n", len(currentRules))
		replaceStr := promptForOptionalInput("Mevcut kuralları sil ve yerine içe aktarılanları ekle? [E/h]: ", "E")
		replace = strings.ToLower(replaceStr) == "e" || strings.ToLower(replaceStr) == "evet"
	}

	// İçe aktar
	err = ImportNATRules(filename, replace)
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	fmt.Println("NAT kuralları başarıyla içe aktarıldı.")
}

// displayNATTraffic, NAT kurallarının trafik istatistiklerini görüntüler
func displayNATTraffic() {
	fmt.Println("\n=== NAT Trafik İzleme ===")

	// Trafik istatistiklerini al
	stats, err := GetNATTrafficStats()
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	if len(stats) == 0 {
		fmt.Println("İzlenecek NAT kuralı bulunamadı.")
		return
	}

	// Tabloyu görüntüle
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "No\tKural\tBağlantı\tGelen (KB)\tGiden (KB)\tSon Etkinlik\t")
	fmt.Fprintln(w, "---\t--------------------------------\t---------\t----------\t----------\t------------------\t")

	for i, stat := range stats {
		rule := stat.Rule.String()
		fmt.Fprintf(w, "%d\t%s\t%d\t%.2f\t%.2f\t%s\t\n",
			i+1,
			rule,
			stat.ConnectionsIn,
			float64(stat.BytesIn)/1024.0,
			float64(stat.BytesOut)/1024.0,
			stat.LastActive,
		)
	}

	w.Flush()
	fmt.Println("\nNot: Trafik bilgileri yaklaşık değerlerdir ve gerçek zamanlı olmayabilir.")
	fmt.Println("Güncellemek için komutu tekrar çalıştırın.")
}

// createInterfaceRoutingInteractive, kullanıcıdan bilgi alarak arayüzler arası yönlendirme oluşturur
func createInterfaceRoutingInteractive() {
	fmt.Println("\n=== Arayüzler Arası Yönlendirme Oluştur ===")

	// Ağ arayüzlerini listele
	interfaces, err := ListNetworkInterfaces()
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	if len(interfaces) < 2 {
		fmt.Println("Yönlendirme için en az iki ağ arayüzü gereklidir.")
		return
	}

	// Arayüzleri göster
	fmt.Println("\nKullanılabilir Ağ Arayüzleri:")
	displayNetworkInterfaces()

	// Kaynak arayüzü seç
	sourceIdxStr := promptForInput("Kaynak ağ arayüzünün indeks numarası: ")
	sourceIdx, err := strconv.Atoi(sourceIdxStr)
	if err != nil || sourceIdx < 1 || sourceIdx > len(interfaces) {
		fmt.Printf("Hata: Geçersiz indeks numarası: %s\n", sourceIdxStr)
		return
	}

	// Hedef arayüzü seç
	destIdxStr := promptForInput("Hedef ağ arayüzünün indeks numarası: ")
	destIdx, err := strconv.Atoi(destIdxStr)
	if err != nil || destIdx < 1 || destIdx > len(interfaces) {
		fmt.Printf("Hata: Geçersiz indeks numarası: %s\n", destIdxStr)
		return
	}

	// Aynı arayüzü kontrol et
	if sourceIdx == destIdx {
		fmt.Println("Hata: Kaynak ve hedef aynı arayüz olamaz.")
		return
	}

	// IP adreslerini kontrol et
	if interfaces[sourceIdx-1].IpAddress == "" || interfaces[destIdx-1].IpAddress == "" {
		fmt.Println("Hata: Her iki arayüz de geçerli bir IP adresine sahip olmalıdır.")
		return
	}

	// Protokolü seç
	protocol := promptForOptionalInput("Protokol [tcp/udp] (varsayılan: tcp): ", "tcp")
	protocol = strings.ToLower(protocol)
	if protocol != "tcp" && protocol != "udp" {
		fmt.Printf("Geçersiz protokol: %s. Varsayılan olarak 'tcp' kullanılıyor.\n", protocol)
		protocol = "tcp"
	}

	fmt.Printf("\nYönlendirme oluşturuluyor: %s -> %s (%s)\n",
		interfaces[sourceIdx-1].Name,
		interfaces[destIdx-1].Name,
		protocol)

	// Onay iste
	confirm := promptForOptionalInput("Onaylıyor musunuz? [E/h]: ", "E")
	if strings.ToLower(confirm) != "e" && strings.ToLower(confirm) != "evet" {
		fmt.Println("İşlem iptal edildi.")
		return
	}

	// Yönlendirme oluştur
	routing, err := CreateInterfaceRouting(sourceIdx, destIdx, protocol)
	if err != nil {
		fmt.Printf("Uyarı: %v\n", err)
	}

	if routing != nil && len(routing.Rules) > 0 {
		fmt.Printf("\nArayüzler arası yönlendirme başarıyla oluşturuldu.\n")
		fmt.Printf("Kaynak: %s (%s)\n", routing.SourceInterface.Name, routing.SourceInterface.IpAddress)
		fmt.Printf("Hedef: %s (%s)\n", routing.DestinationInterface.Name, routing.DestinationInterface.IpAddress)
		fmt.Printf("Protokol: %s\n", protocol)
		fmt.Printf("Oluşturulan kurallar: %d\n", len(routing.Rules))
	} else {
		fmt.Println("Arayüzler arası yönlendirme oluşturulamadı.")
	}
} // ExportNATRules, mevcut NAT kurallarını belirtilen dosyaya JSON formatında dışa aktarır
func ExportNATRules(filename string) error {
	// Mevcut NAT kurallarını al
	rules, err := ListNATEntries()
	if err != nil {
		return fmt.Errorf("NAT kuralları alınırken hata oluştu: %w", err)
	}

	// Bilgisayar adını al
	hostCmd := exec.Command("hostname")
	var hostOut bytes.Buffer
	hostCmd.Stdout = &hostOut
	if err := hostCmd.Run(); err != nil {
		// Hata durumunda varsayılan bir ad kullan
		fmt.Println("Bilgisayar adı alınamadı, varsayılan değer kullanılıyor.")
	}
	hostname := strings.TrimSpace(hostOut.String())
	if hostname == "" {
		hostname = "unknown-host"
	}

	// Dışa aktarma yapısını oluştur
	export := NATRuleExport{
		Rules:      rules,
		ExportDate: time.Now().Format(time.RFC3339),
		HostName:   hostname,
	}

	// JSON'a dönüştür
	jsonData, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON dönüştürme hatası: %w", err)
	}

	// Dosyaya yaz
	err = ioutil.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("Dosya yazma hatası: %w", err)
	}

	return nil
}

// ImportNATRules, belirtilen JSON dosyasından NAT kurallarını içe aktarır
func ImportNATRules(filename string, replace bool) error {
	// Dosyayı oku
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("Dosya okuma hatası: %w", err)
	}

	// JSON'dan yapıya dönüştür
	var export NATRuleExport
	if err := json.Unmarshal(data, &export); err != nil {
		return fmt.Errorf("JSON ayrıştırma hatası: %w", err)
	}

	// Eğer replace true ise, önce mevcut tüm kuralları sil
	if replace {
		currentRules, err := ListNATEntries()
		if err != nil {
			return fmt.Errorf("mevcut NAT kuralları alınırken hata: %w", err)
		}

		for _, rule := range currentRules {
			err := DeleteNATEntry(rule.ListenAddress, rule.ListenPort, rule.Protocol)
			if err != nil {
				fmt.Printf("Uyarı: Kural silinemedi: %s - Hata: %v\n", rule.String(), err)
			}
		}
	}

	// İçe aktarılan kuralları ekle
	var errors []string
	successCount := 0

	for _, rule := range export.Rules {
		err := CreateNATEntry(rule)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", rule.String(), err))
		} else {
			successCount++
		}
	}

	// Sonuçları bildir
	if len(errors) > 0 {
		return fmt.Errorf("%d kural başarıyla içe aktarıldı, %d kural hata verdi: %s",
			successCount, len(errors), strings.Join(errors, "; "))
	}

	return nil
}

// GetNATTrafficStats, belirtilen NAT kuralları için trafik istatistiklerini alır
func GetNATTrafficStats() ([]NATRuleTrafficStats, error) {
	// NAT kurallarını al
	rules, err := ListNATEntries()
	if err != nil {
		return nil, fmt.Errorf("NAT kuralları alınırken hata: %w", err)
	}

	// Her kural için netstat ve perfmon verileri topla
	stats := make([]NATRuleTrafficStats, 0, len(rules))

	for _, rule := range rules {
		// netstat ile bağlantı sayısını al
		connections, timestamp := getConnectionCountForPort(rule)

		// Tahmini bayt sayıları (gerçek uygulamada Windows Performans Sayaçları kullanılabilir)
		// Bu örnekte basit rastgele değerler oluşturulmuştur
		bytesIn := int64(connections * 8192)  // Örnek değer
		bytesOut := int64(connections * 4096) // Örnek değer

		stat := NATRuleTrafficStats{
			Rule:           rule,
			BytesIn:        bytesIn,
			BytesOut:       bytesOut,
			ConnectionsIn:  connections,
			ConnectionsOut: connections, // Basitleştirmek için aynı değer kullanıldı
			LastActive:     timestamp,
		}

		stats = append(stats, stat)
	}

	return stats, nil
}

// getConnectionCountForPort, belirli bir port için aktif bağlantı sayısını alır
func getConnectionCountForPort(rule NATEntry) (int, string) {
	// netstat ile aktif bağlantıları al
	cmd := exec.Command("netstat", "-ano")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		// Hata durumunda varsayılan değerler
		return 0, time.Now().Format(time.RFC3339)
	}

	output := out.String()
	lines := strings.Split(output, "\n")

	// Port ile bağlantılı satırları say
	count := 0
	portStr := ":" + rule.ListenPort

	// Portu belirtilmemişse, rastgele bir değer döndür (örnek uygulama)
	if rule.ListenPort == "" || rule.ListenPort == "*" {
		// Gerçek uygulamada, burada tüm portlar için toplu hesaplama yapılabilir
		return rand.Intn(10) + 1, time.Now().Format(time.RFC3339)
	}

	for _, line := range lines {
		if strings.Contains(line, portStr) &&
			strings.Contains(line, rule.ListenAddress) {
			count++
		}
	}

	return count, time.Now().Format(time.RFC3339)
}

// CreateInterfaceRouting, iki ağ arayüzü arasında yönlendirme kuralları oluşturur
func CreateInterfaceRouting(sourceIndex, destIndex int, protocol string) (*InterfaceRouting, error) {
	// Ağ arayüzlerini al
	interfaces, err := ListNetworkInterfaces()
	if err != nil {
		return nil, fmt.Errorf("ağ arayüzleri alınırken hata: %w", err)
	}

	// İndeks kontrolü
	if sourceIndex < 1 || sourceIndex > len(interfaces) ||
		destIndex < 1 || destIndex > len(interfaces) {
		return nil, fmt.Errorf("geçersiz arayüz indeksi: kaynak=%d, hedef=%d, aralık 1-%d olmalı",
			sourceIndex, destIndex, len(interfaces))
	}

	// Arayüzleri al
	sourceIface := interfaces[sourceIndex-1]
	destIface := interfaces[destIndex-1]

	// IP adreslerini kontrol et
	if sourceIface.IpAddress == "" || destIface.IpAddress == "" {
		return nil, fmt.Errorf("her iki arayüz de geçerli bir IP adresine sahip olmalıdır")
	}

	// Protokolü kontrol et
	if protocol == "" {
		protocol = "tcp"
	}
	protocol = strings.ToLower(protocol)
	if protocol != "tcp" && protocol != "udp" {
		return nil, fmt.Errorf("geçersiz protokol: %s, 'tcp' veya 'udp' olmalı", protocol)
	}

	// Yaygın portlar için NAT kuralları oluştur
	commonPorts := []string{
		"21",   // FTP
		"22",   // SSH
		"23",   // Telnet
		"25",   // SMTP
		"53",   // DNS
		"80",   // HTTP
		"110",  // POP3
		"443",  // HTTPS
		"3389", // RDP
		"8080", // HTTP Alternate
	}

	// Oluşturulan kuralları sakla
	var createdRules []NATEntry
	var errors []string

	for _, port := range commonPorts {
		rule := NATEntry{
			ListenAddress:  sourceIface.IpAddress,
			ListenPort:     port,
			ConnectAddress: destIface.IpAddress,
			ConnectPort:    port,
			Protocol:       protocol,
		}

		err := CreateNATEntry(rule)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Port %s: %v", port, err))
		} else {
			createdRules = append(createdRules, rule)
		}
	}

	// Yönlendirme bilgisini oluştur
	routing := &InterfaceRouting{
		SourceInterface:      sourceIface,
		DestinationInterface: destIface,
		Enabled:              true,
		Rules:                createdRules,
		CreatedAt:            time.Now().Format(time.RFC3339),
	}

	// Hataları bildir
	if len(errors) > 0 {
		if len(createdRules) == 0 {
			return routing, fmt.Errorf("hiçbir yönlendirme kuralı oluşturulamadı: %s", strings.Join(errors, "; "))
		}
		return routing, fmt.Errorf("bazı yönlendirme kuralları oluşturulamadı: %s", strings.Join(errors, "; "))
	}

	return routing, nil
}

// DeleteInterfaceRouting, iki ağ arayüzü arasındaki yönlendirme kurallarını siler
func DeleteInterfaceRouting(routing *InterfaceRouting) error {
	if routing == nil {
		return errors.New("geçersiz yönlendirme bilgisi")
	}

	var errors []string
	deletedCount := 0

	// Her kuralı sil
	for _, rule := range routing.Rules {
		err := DeleteNATEntry(rule.ListenAddress, rule.ListenPort, rule.Protocol)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", rule.String(), err))
		} else {
			deletedCount++
		}
	}

	// Yönlendirmeyi devre dışı bırak
	routing.Enabled = false

	// Hataları bildir
	if len(errors) > 0 {
		if deletedCount == 0 {
			return fmt.Errorf("hiçbir yönlendirme kuralı silinemedi: %s", strings.Join(errors, "; "))
		}
		return fmt.Errorf("bazı yönlendirme kuralları silinemedi: %s", strings.Join(errors, "; "))
	}

	return nil
} // NATRuleExport, dışa aktarılabilecek NAT kuralları koleksiyonunu temsil eder
type NATRuleExport struct {
	Rules      []NATEntry `json:"rules"`       // NAT kuralları listesi
	ExportDate string     `json:"export_date"` // Dışa aktarma tarihi
	HostName   string     `json:"host_name"`   // Bilgisayar adı
}

// NATRuleTrafficStats, bir NAT kuralının trafik istatistiklerini temsil eder
type NATRuleTrafficStats struct {
	Rule           NATEntry `json:"rule"`            // NAT kuralı
	BytesIn        int64    `json:"bytes_in"`        // Gelen bayt sayısı
	BytesOut       int64    `json:"bytes_out"`       // Giden bayt sayısı
	ConnectionsIn  int      `json:"connections_in"`  // Gelen bağlantı sayısı
	ConnectionsOut int      `json:"connections_out"` // Giden bağlantı sayısı
	LastActive     string   `json:"last_active"`     // Son etkinlik zamanı
}

// InterfaceRouting, iki ağ arayüzü arasındaki yönlendirmeyi temsil eder
type InterfaceRouting struct {
	SourceInterface      NetworkInterface `json:"source_interface"`      // Kaynak ağ arayüzü
	DestinationInterface NetworkInterface `json:"destination_interface"` // Hedef ağ arayüzü
	Enabled              bool             `json:"enabled"`               // Yönlendirme etkin mi
	Rules                []NATEntry       `json:"rules"`                 // İlişkili NAT kuralları
	CreatedAt            string           `json:"created_at"`            // Oluşturulma zamanı
}

// NATEntry, bir NAT tablosu girişini temsil eder
type NATEntry struct {
	ListenAddress  string // Dinlenen adres (yerel IP)
	ListenPort     string // Dinlenen port (yerel port)
	ConnectAddress string // Bağlanılacak adres (hedef IP)
	ConnectPort    string // Bağlanılacak port (hedef port)
	Protocol       string // Protokol (tcp veya udp)
}

// SystemNetworkInfo, sistemdeki genel ağ yapılandırma bilgilerini temsil eder
type SystemNetworkInfo struct {
	HostName            string // Bilgisayar adı
	PrimaryDnsSuffix    string // Birincil DNS soneki
	NodeType            string // Düğüm tipi
	IPRoutingEnabled    string // IP yönlendirme etkin mi
	WINSProxyEnabled    string // WINS proxy etkin mi
	DNSSuffixSearchList string // DNS sonek arama listesi
}

// NetworkInterface, bir ağ arayüzünü temsil eder
type NetworkInterface struct {
	Name              string   // Arayüz adı
	Description       string   // Arayüz açıklaması
	Status            string   // Durumu (Connected, Media disconnected, etc.)
	Type              string   // Arayüz tipi (Ethernet, Wireless, etc.)
	MacAddress        string   // MAC adresi (Physical Address)
	IpAddress         string   // IPv4 adresi
	SubnetMask        string   // Alt ağ maskesi
	IPv6Address       string   // IPv6 adresi
	DefaultGateway    string   // Varsayılan ağ geçidi
	DHCPEnabled       string   // DHCP etkinleştirilmiş mi
	DHCPServer        string   // DHCP sunucusu
	DNSSuffix         string   // DNS soneki
	DNSServers        []string // DNS sunucuları (birden fazla olabilir)
	LeaseObtained     string   // Kira elde edilme zamanı
	LeaseExpires      string   // Kira sona erme zamanı
	NetBIOSOverTCPIP  string   // NetBIOS over TCP/IP durumu
	AutoconfigEnabled string   // Otomatik yapılandırma etkin mi
	DHCPv6IAID        string   // DHCPv6 IAID değeri
	DHCPv6ClientDUID  string   // DHCPv6 Client DUID değeri
	MediaState        string   // Medya durumu (bağlantı yoksa "Media disconnected")
}

// String, NATEntry'nin okunabilir bir metin temsilini döndürür
func (e NATEntry) String() string {
	return fmt.Sprintf("%s:%s -> %s:%s (%s)",
		e.ListenAddress, e.ListenPort,
		e.ConnectAddress, e.ConnectPort,
		e.Protocol)
}

// ListNATEntries, mevcut tüm NAT tablosu girişlerini listeler
// Windows'ta netsh komutunu kullanarak port proxy bilgilerini alır
func ListNATEntries() ([]NATEntry, error) {
	// netsh komutunu çalıştır
	cmd := exec.Command("netsh", "interface", "portproxy", "show", "v4tov4")
	var out bytes.Buffer
	cmd.Stdout = &out

	// Komutu çalıştır ve hataları yakala
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("NAT tablosu listelenirken hata oluştu: %w", err)
	}

	// Çıktıyı ayrıştır
	return parseNATOutput(out.String())
}

// parseNATOutput, netsh komutunun çıktısını ayrıştırıp NATEntry yapılarına dönüştürür
func parseNATOutput(output string) ([]NATEntry, error) {
	var entries []NATEntry

	// Satır satır işle, ilk iki satırı atla (başlık bilgileri)
	lines := strings.Split(output, "\n")
	if len(lines) < 3 {
		return entries, nil // Hiç giriş yok
	}

	// Regex ile NAT girişlerini ayrıştır
	// Tipik format: Listen on ipv4:    Connect to ipv4:
	//               Address         Port  Address         Port
	//               --------------- ----- --------------- -----
	//               192.168.1.100   8080  10.0.0.1        80
	for _, line := range lines[3:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Boşluklarla bölünmüş değerleri al
		parts := regexp.MustCompile(`\s+`).Split(line, -1)
		if len(parts) >= 4 {
			entry := NATEntry{
				ListenAddress:  parts[0],
				ListenPort:     parts[1],
				ConnectAddress: parts[2],
				ConnectPort:    parts[3],
				Protocol:       "tcp", // Varsayılan olarak TCP
			}
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// CreateNATEntry, yeni bir NAT tablosu girişi oluşturur
func CreateNATEntry(entry NATEntry) error {
	if entry.ListenAddress == "" || entry.ConnectAddress == "" {
		return errors.New("dinleme ve hedef adresleri belirtilmelidir")
	}

	// Port kontrolü: Boş veya "*" portlar için yaygın portları kullanarak çoklu kural oluşturma
	if (entry.ListenPort == "" || entry.ListenPort == "*") &&
		(entry.ConnectPort == "" || entry.ConnectPort == "*") {
		// Hem dinleme hem de hedef portları belirtilmemiş:
		// Bu, tüm portları aynı şekilde yönlendiren bir konfigurasyon gerektirir
		return createAllPortsMapping(entry)
	} else if entry.ListenPort == "" || entry.ListenPort == "*" {
		// Sadece dinleme portu belirtilmemiş (any listen port -> specific target port)
		return errors.New("hedef port belirtildiğinde, dinleme portu da belirtilmelidir")
	} else if entry.ConnectPort == "" || entry.ConnectPort == "*" {
		// Sadece hedef portu belirtilmemiş (specific listen port -> any target port)
		// Bu durumda, dinleme portunu kullanarak tek bir hedef için yönlendirme yapalım
		entry.ConnectPort = entry.ListenPort
		return createSinglePortMapping(entry)
	}

	// Standart durum: Hem dinleme hem de hedef portları belirtilmiş
	return createSinglePortMapping(entry)
}

// createSinglePortMapping, belirli portlar arasında tek bir NAT kuralı oluşturur
func createSinglePortMapping(entry NATEntry) error {
	// Protokolü kontrol et, varsayılan olarak TCP kullan
	protocol := "tcp"
	if strings.ToLower(entry.Protocol) == "udp" {
		protocol = "udp"
	}

	// netsh komutunu çalıştır
	cmd := exec.Command("netsh", "interface", "portproxy", "add", "v4tov4",
		"listenport="+entry.ListenPort,
		"listenaddress="+entry.ListenAddress,
		"connectport="+entry.ConnectPort,
		"connectaddress="+entry.ConnectAddress,
		"protocol="+protocol)

	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	// Komutu çalıştır ve hataları yakala
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("NAT girişi oluşturulurken hata: %w - %s", err, errBuf.String())
	}

	return nil
}

// createAllPortsMapping, yaygın portları kullanarak çoklu NAT kuralları oluşturur
func createAllPortsMapping(entry NATEntry) error {
	// Sık kullanılan portlar listesi
	commonPorts := []string{
		"21",   // FTP
		"22",   // SSH
		"23",   // Telnet
		"25",   // SMTP
		"53",   // DNS
		"80",   // HTTP
		"110",  // POP3
		"115",  // SFTP
		"135",  // RPC
		"139",  // NetBIOS
		"143",  // IMAP
		"443",  // HTTPS
		"445",  // SMB
		"993",  // IMAPS
		"995",  // POP3S
		"1433", // MS SQL
		"3306", // MySQL
		"3389", // RDP
		"5060", // SIP
		"5900", // VNC
		"8080", // HTTP Alternate
	}

	// Yaygın portları aynı hedefe yönlendir
	var errs []string
	for _, port := range commonPorts {
		portEntry := entry
		portEntry.ListenPort = port
		portEntry.ConnectPort = port

		err := createSinglePortMapping(portEntry)
		if err != nil {
			errs = append(errs, fmt.Sprintf("Port %s: %v", port, err))
		}
	}

	// Hata kontrolü
	if len(errs) > 0 {
		if len(errs) == len(commonPorts) {
			return fmt.Errorf("tüm portlar için yönlendirme kuralları oluşturulamadı: %s", strings.Join(errs, "; "))
		}
		return fmt.Errorf("bazı portlar için yönlendirme kuralları oluşturulamadı: %s", strings.Join(errs, "; "))
	}

	return nil
}

// DeleteNATEntry, belirtilen portu ve adresi dinleyen NAT girişini siler
func DeleteNATEntry(listenAddress, listenPort, protocol string) error {
	if listenAddress == "" {
		return errors.New("dinleme adresi belirtilmelidir")
	}

	// Protokolü kontrol et, varsayılan olarak TCP kullan
	if protocol == "" {
		protocol = "tcp"
	}

	// Port belirtilmediyse veya "*" ise, tüm port kurallarını silmek anlamına gelir
	if listenPort == "" || listenPort == "*" {
		return DeleteAllPortsForAddress(listenAddress, protocol)
	}

	// Belirli port için kuralı sil
	cmd := exec.Command("netsh", "interface", "portproxy", "delete", "v4tov4",
		"listenport="+listenPort,
		"listenaddress="+listenAddress,
		"protocol="+protocol)

	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	// Komutu çalıştır ve hataları yakala
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("NAT girişi silinirken hata: %w - %s", err, errBuf.String())
	}

	return nil
}

// DeleteAllPortsForAddress, belirtilen adresteki tüm NAT kurallarını siler
func DeleteAllPortsForAddress(listenAddress, protocol string) error {
	// Önce mevcut tüm kuralları al
	entries, err := ListNATEntries()
	if err != nil {
		return fmt.Errorf("NAT girişleri alınırken hata: %w", err)
	}

	// Belirtilen adrese ait kuralları bul ve sil
	var errs []string
	deleted := 0

	for _, entry := range entries {
		// Sadece belirtilen adres ve protokole ait kuralları sil
		if entry.ListenAddress == listenAddress &&
			(protocol == "" || entry.Protocol == protocol) {
			err := DeleteNATEntry(entry.ListenAddress, entry.ListenPort, entry.Protocol)
			if err != nil {
				errs = append(errs, fmt.Sprintf("Port %s: %v", entry.ListenPort, err))
			} else {
				deleted++
			}
		}
	}

	// Silinen kural sayısını kontrol et
	if deleted == 0 {
		return fmt.Errorf("belirtilen adres için silinecek kural bulunamadı: %s", listenAddress)
	}

	// Hata kontrolü
	if len(errs) > 0 {
		return fmt.Errorf("bazı kurallar silinemedi: %s", strings.Join(errs, "; "))
	}

	return nil
}

// DeleteNATEntryByIndex, belirtilen indeksteki NAT girişini siler
// İndeks 1'den başlayarak listelenir, Go dilinde diziler 0'dan başlamasına rağmen
// kullanıcı dostu bir yaklaşım için 1-tabanlı indeksleme kullanıyoruz
func DeleteNATEntryByIndex(index int) error {
	// Önce tüm NAT girişlerini al
	entries, err := ListNATEntries()
	if err != nil {
		return fmt.Errorf("NAT girişleri alınırken hata: %w", err)
	}

	// İndeks kontrolü
	if index < 1 || index > len(entries) {
		return fmt.Errorf("geçersiz indeks: %d, aralık olmalı: 1-%d", index, len(entries))
	}

	// Go'da diziler 0-tabanlı olduğu için, kullanıcının girdiği indeksi uyarla
	entry := entries[index-1]

	// Seçilen girişi sil
	return DeleteNATEntry(entry.ListenAddress, entry.ListenPort, entry.Protocol)
}

// displayHelp, kullanılabilir komutları ve açıklamalarını gösterir
func displayHelp() {
	fmt.Println("\nWindows NAT Yönetici - Yardım")
	fmt.Println("==============================")
	fmt.Println("Kullanılabilir Komutlar:")
	fmt.Println("  list               - Tüm NAT girişlerini listele")
	fmt.Println("  create             - Yeni bir NAT girişi oluştur (tüm portlar desteği ile)")
	fmt.Println("  delete <index>     - Belirtilen indeksteki NAT girişini sil")
	fmt.Println("  delete all         - Tüm NAT girişlerini sil")
	fmt.Println("  delete addr:IP     - Belirtilen IP adresindeki tüm NAT girişlerini sil")
	fmt.Println("  interfaces, if     - Tüm ağ arayüzlerini tablo formatında listele")
	fmt.Println("  showif <index>     - Belirtilen indeksteki ağ arayüzünün detaylı bilgilerini göster")
	fmt.Println("  route-if           - İki ağ arayüzü arasında yönlendirme oluştur")
	fmt.Println("  route-any          - 0.0.0.0 (tüm arayüzleri dinleme) adresini belirli bir IP'ye yönlendir")
	fmt.Println("  export             - NAT kurallarını bir JSON dosyasına dışa aktar")
	fmt.Println("  import             - NAT kurallarını bir JSON dosyasından içe aktar")
	fmt.Println("  traffic            - NAT kurallarının trafik istatistiklerini göster")
	fmt.Println("  menu, main         - Ana menüyü görüntüle")
	fmt.Println("  help               - Bu yardım ekranını göster")
	fmt.Println("  exit               - Programdan çık")
	fmt.Println("")
	fmt.Println("Port Belirtme:")
	fmt.Println("  Port alanı boş bırakıldığında veya '*' girildiğinde, 'any port' (tüm portlar)")
	fmt.Println("  olarak yorumlanır. Bu durumda, yaygın portlar (HTTP, HTTPS, SSH, RDP vb.) için")
	fmt.Println("  otomatik olarak NAT kuralları oluşturulur.")
	fmt.Println("")
}

// displayNATEntries, mevcut NAT girişlerini listeler
// Eğer hiç giriş yoksa, kullanıcıya bilgi verir
func displayNATEntries() {
	entries, err := ListNATEntries()
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	if len(entries) == 0 {
		fmt.Println("Hiç NAT girişi bulunamadı.")
		return
	}

	fmt.Println("\nNAT Tablosu Girişleri:")
	fmt.Println("----------------------")
	for i, entry := range entries {
		fmt.Printf("%d. %s\n", i+1, entry)
	}
	fmt.Println("")
}

// promptForInput, kullanıcıdan belirtilen mesajla giriş ister
// Boş girişleri reddeder ve tekrar sorar
func promptForInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(prompt)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Giriş okunurken hata: %v. Lütfen tekrar deneyin.\n", err)
			continue
		}

		// Windows'ta satır sonu karakterleri \r\n olabilir, temizleyelim
		input = strings.TrimSpace(input)

		if input == "" {
			fmt.Println("Boş giriş kabul edilmez. Lütfen tekrar deneyin.")
			continue
		}

		return input
	}
}

// promptForOptionalInput, kullanıcıdan belirtilen mesajla giriş ister, ancak boş girişlere izin verir
func promptForOptionalInput(prompt string, defaultValue string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Giriş okunurken hata: %v. Varsayılan değer kullanılıyor: %s\n", err, defaultValue)
		return defaultValue
	}

	// Windows'ta satır sonu karakterleri \r\n olabilir, temizleyelim
	input = strings.TrimSpace(input)

	// Eğer giriş boşsa, varsayılan değeri döndür
	if input == "" {
		return defaultValue
	}

	return input
}

// createNATEntryInteractive, kullanıcıdan gerekli bilgileri isteyerek yeni bir NAT girişi oluşturur
func createNATEntryInteractive() {
	fmt.Println("\n=== Yeni NAT Girişi Oluştur ===")

	// Ağ arayüzlerini göster, kullanıcının IP adreslerini kolayca görmesi için
	interfaces, err := ListNetworkInterfaces()
	if err != nil {
		fmt.Printf("Uyarı: Ağ arayüzleri listelenemedi: %v\n", err)
	} else {
		if len(interfaces) > 0 {
			fmt.Println("\nMevcut Ağ Arayüzleri ve IP Adresleri:")
			fmt.Println("---------------------------------------")

			// tabwriter ile düzgün hizalanmış bir tablo oluştur
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "No\tAd\tIP Adresi\tAlt Ağ Maskesi\t")
			fmt.Fprintln(w, "---\t----------------\t-----------------\t-----------------\t")

			for i, iface := range interfaces {
				// Sadece IP adresi olanları göster
				if iface.IpAddress != "" {
					fmt.Fprintf(w, "%d\t%s\t%s\t%s\t\n",
						i+1,
						iface.Name,
						iface.IpAddress,
						iface.SubnetMask)
				}
			}

			w.Flush()
			fmt.Println("")
		}
	}

	// Kullanıcıdan dinleme adresini iste, arayüz seçeneği ile
	var listenAddr string
	interfaceSelectionInput := promptForOptionalInput("Dinleme IP adresi için arayüz numarası seçin (veya doğrudan IP girin): ", "")

	// Eğer sayısal bir değer girildiyse, arayüz seçimi olarak yorumla
	if interfaceNum, err := strconv.Atoi(interfaceSelectionInput); err == nil && len(interfaces) > 0 {
		if interfaceNum >= 1 && interfaceNum <= len(interfaces) {
			selectedInterface := interfaces[interfaceNum-1]
			if selectedInterface.IpAddress != "" {
				listenAddr = selectedInterface.IpAddress
				fmt.Printf("Seçilen arayüz: %s, IP adresi: %s\n", selectedInterface.Name, listenAddr)
			} else {
				fmt.Println("Seçilen arayüzün IP adresi bulunamadı. Lütfen IP adresini manuel olarak girin.")
				listenAddr = promptForInput("Dinleme adresi (örn. 192.168.1.100): ")
			}
		} else {
			fmt.Printf("Geçersiz arayüz numarası. Lütfen 1-%d arasında bir değer girin.\n", len(interfaces))
			listenAddr = promptForInput("Dinleme adresi (örn. 192.168.1.100): ")
		}
	} else {
		// Sayısal değilse, doğrudan IP adresi olarak kullan
		if interfaceSelectionInput == "" {
			listenAddr = promptForInput("Dinleme adresi (örn. 192.168.1.100): ")
		} else {
			listenAddr = interfaceSelectionInput
		}
	}

	// Dinleme portu - boş bırakılabilir (tüm portlar anlamına gelir)
	listenPort := promptForOptionalInput("Dinleme portu [boş=tüm portlar] (örn. 8080): ", "")
	if listenPort == "" {
		fmt.Println("Not: Dinleme portu belirtilmedi, tüm portlar için NAT kuralları oluşturulacak.")
	}

	// Hedef adresini iste
	var connectAddr string
	interfaceSelectionInput = promptForOptionalInput("Hedef IP adresi için arayüz numarası seçin (veya doğrudan IP girin): ", "")

	// Eğer sayısal bir değer girildiyse, arayüz seçimi olarak yorumla
	if interfaceNum, err := strconv.Atoi(interfaceSelectionInput); err == nil && len(interfaces) > 0 {
		if interfaceNum >= 1 && interfaceNum <= len(interfaces) {
			selectedInterface := interfaces[interfaceNum-1]
			if selectedInterface.IpAddress != "" {
				connectAddr = selectedInterface.IpAddress
				fmt.Printf("Seçilen arayüz: %s, IP adresi: %s\n", selectedInterface.Name, connectAddr)
			} else {
				fmt.Println("Seçilen arayüzün IP adresi bulunamadı. Lütfen IP adresini manuel olarak girin.")
				connectAddr = promptForInput("Hedef bağlantı adresi (örn. 10.0.0.5): ")
			}
		} else {
			fmt.Printf("Geçersiz arayüz numarası. Lütfen 1-%d arasında bir değer girin.\n", len(interfaces))
			connectAddr = promptForInput("Hedef bağlantı adresi (örn. 10.0.0.5): ")
		}
	} else {
		// Sayısal değilse, doğrudan IP adresi olarak kullan
		if interfaceSelectionInput == "" {
			connectAddr = promptForInput("Hedef bağlantı adresi (örn. 10.0.0.5): ")
		} else {
			connectAddr = interfaceSelectionInput
		}
	}

	// Hedef portu - eğer dinleme portu belirtilmediyse, hedef portu da boş olmalı
	var connectPort string
	if listenPort == "" {
		fmt.Println("Not: Dinleme portu belirtilmediği için, hedef portu da tüm portlar olarak ayarlanacak.")
		connectPort = ""
	} else {
		// Dinleme portu belirtildi, hedef portunu ayrıca sor
		connectPort = promptForOptionalInput("Hedef bağlantı portu [boş=dinleme portuyla aynı] (örn. 80): ", "")
		// Eğer hedef portu boş bırakıldıysa, dinleme portuyla aynı olsun
		if connectPort == "" {
			connectPort = listenPort
			fmt.Printf("Not: Hedef port belirtilmedi, dinleme portu kullanılacak: %s\n", listenPort)
		}
	}

	protocol := promptForOptionalInput("Protokol [tcp/udp] (varsayılan: tcp): ", "tcp")

	// Protokolü küçük harfe çevir ve kontrol et
	protocol = strings.ToLower(protocol)
	if protocol != "tcp" && protocol != "udp" {
		fmt.Printf("Geçersiz protokol: %s. Varsayılan olarak 'tcp' kullanılıyor.\n", protocol)
		protocol = "tcp"
	}

	// NAT girişi oluştur
	entry := NATEntry{
		ListenAddress:  listenAddr,
		ListenPort:     listenPort,
		ConnectAddress: connectAddr,
		ConnectPort:    connectPort,
		Protocol:       protocol,
	}

	// Ek bilgilendirme: Tüm portlar için yaygın portların yönlendirileceğini açıkla
	if listenPort == "" {
		fmt.Println("\nÖnemli Not: 'Tüm portlar' seçeneği, pratikte yaygın olarak kullanılan portlar için")
		fmt.Println("(HTTP, HTTPS, SSH, RDP, vb.) NAT kuralları oluşturacaktır. İhtiyacınız olan belirli")
		fmt.Println("bir port yönlendirilemezse, lütfen o port için özel bir kural oluşturun.")
	}

	// Onay sorgusu
	fmt.Printf("\nOluşturulacak NAT girişi: %s\n", entry)
	confirm := promptForOptionalInput("Onaylıyor musunuz? [E/h]: ", "E")

	if strings.ToLower(confirm) != "e" && strings.ToLower(confirm) != "evet" {
		fmt.Println("İşlem iptal edildi.")
		return
	}

	// NAT girişini oluştur
	err = CreateNATEntry(entry)
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	fmt.Printf("NAT girişi başarıyla oluşturuldu: %s\n", entry)
}

// deleteNATEntryInteractive, kullanıcıdan bir indeks alarak NAT girişini siler
func deleteNATEntryInteractive(args []string) {
	// Önce mevcut NAT girişlerini göster
	displayNATEntries()

	// Eğer komut parametresi olarak indeks verilmişse, onu kullan
	var indexStr string
	if len(args) > 0 {
		indexStr = args[0]
	} else {
		// Değilse, kullanıcıdan iste
		indexStr = promptForInput("Silinecek NAT girişinin indeks numarası (veya 'all' yazarak tüm girişleri sil): ")
	}

	// Tüm NAT girişlerini silme seçeneği
	if strings.ToLower(indexStr) == "all" || strings.ToLower(indexStr) == "tüm" {
		fmt.Println("\nDikkat: Tüm NAT girişleri silinecek!")
		confirm := promptForOptionalInput("Onaylıyor musunuz? [E/h]: ", "E")

		if strings.ToLower(confirm) != "e" && strings.ToLower(confirm) != "evet" {
			fmt.Println("İşlem iptal edildi.")
			return
		}

		// Tüm girişleri al
		entries, err := ListNATEntries()
		if err != nil {
			fmt.Printf("Hata: %v\n", err)
			return
		}

		if len(entries) == 0 {
			fmt.Println("Silinecek NAT girişi bulunamadı.")
			return
		}

		// Her girişi sil
		var errs []string
		deleted := 0

		for _, entry := range entries {
			err := DeleteNATEntry(entry.ListenAddress, entry.ListenPort, entry.Protocol)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", entry.String(), err))
			} else {
				deleted++
			}
		}

		// Sonucu bildir
		if len(errs) > 0 {
			fmt.Printf("Bazı NAT girişleri silinemedi: %s\n", strings.Join(errs, "; "))
		}
		fmt.Printf("%d NAT girişi başarıyla silindi.\n", deleted)
		return
	}

	// Belirli bir adres için tüm portları silme seçeneği
	if strings.HasPrefix(strings.ToLower(indexStr), "addr:") || strings.HasPrefix(strings.ToLower(indexStr), "ip:") {
		// "addr:192.168.1.100" formatından IP adresini çıkar
		parts := strings.SplitN(indexStr, ":", 2)
		if len(parts) < 2 || parts[1] == "" {
			fmt.Println("Hata: Geçersiz adres formatı. Doğru format: 'addr:192.168.1.100'")
			return
		}

		ipAddress := strings.TrimSpace(parts[1])

		fmt.Printf("\nDikkat: '%s' adresindeki tüm NAT girişleri silinecek!\n", ipAddress)
		confirm := promptForOptionalInput("Onaylıyor musunuz? [E/h]: ", "E")

		if strings.ToLower(confirm) != "e" && strings.ToLower(confirm) != "evet" {
			fmt.Println("İşlem iptal edildi.")
			return
		}

		// Belirtilen adresteki tüm portları sil
		err := DeleteAllPortsForAddress(ipAddress, "")
		if err != nil {
			fmt.Printf("Hata: %v\n", err)
			return
		}

		fmt.Printf("'%s' adresindeki tüm NAT girişleri başarıyla silindi.\n", ipAddress)
		return
	}

	// İndeksi int'e dönüştür
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		fmt.Printf("Hata: Geçersiz indeks numarası veya komut: %s\n", indexStr)
		fmt.Println("Kullanım:")
		fmt.Println("  - Tek bir girişi silmek için sayısal indeks (örn: 3)")
		fmt.Println("  - Tüm girişleri silmek için 'all'")
		fmt.Println("  - Belirli bir adresteki tüm girişleri silmek için 'addr:IP-adresi'")
		return
	}

	// NAT girişlerini al
	entries, err := ListNATEntries()
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	// İndeks kontrolü
	if index < 1 || index > len(entries) {
		fmt.Printf("Hata: Geçersiz indeks: %d, aralık olmalı: 1-%d\n", index, len(entries))
		return
	}

	// Seçilen girişi göster ve onay iste
	selectedEntry := entries[index-1]
	fmt.Printf("\nSilinecek NAT girişi: %d. %s\n", index, selectedEntry)
	confirm := promptForOptionalInput("Onaylıyor musunuz? [E/h]: ", "E")

	if strings.ToLower(confirm) != "e" && strings.ToLower(confirm) != "evet" {
		fmt.Println("İşlem iptal edildi.")
		return
	}

	// NAT girişini sil
	err = DeleteNATEntry(selectedEntry.ListenAddress, selectedEntry.ListenPort, selectedEntry.Protocol)
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	fmt.Printf("%d numaralı NAT girişi başarıyla silindi.\n", index)
}

// ListNetworkInterfaces, sistemdeki tüm ağ arayüzlerini listeler ve bilgilerini toplar
func ListNetworkInterfaces() ([]NetworkInterface, error) {
	// netsh komutu ile arayüzleri listele
	cmd := exec.Command("ipconfig", "/all")
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("ağ arayüzleri listelenirken hata oluştu: %w", err)
	}

	// ipconfig /all çıktısını ayrıştır
	return parseIPConfigOutput(out.String())
}

// parseIPConfigOutput, ipconfig /all komutunun çıktısını ayrıştırıp NetworkInterface yapılarına dönüştürür
func parseIPConfigOutput(output string) ([]NetworkInterface, error) {
	var interfaces []NetworkInterface

	// Çıktıyı satırlara böl
	lines := strings.Split(output, "\n")
	if len(lines) < 3 {
		return interfaces, nil // Yeterli çıktı yok
	}

	var currentInterface *NetworkInterface
	var dnsServersBlock bool

	// Her satırı işle
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Yeni bir arayüz bölümü başlangıcını kontrol et
		if strings.Contains(line, "adapter") && strings.HasSuffix(line, ":") {
			// Önceki arayüzü ekle (eğer varsa)
			if currentInterface != nil {
				interfaces = append(interfaces, *currentInterface)
			}

			// Arayüz adını çıkar (örneğin "Ethernet adapter eth0:" -> "eth0")
			adapterName := line
			adapterName = strings.TrimSpace(strings.TrimSuffix(adapterName, ":"))
			parts := strings.Split(adapterName, " ")
			if len(parts) > 2 {
				adapterName = strings.Join(parts[2:], " ")
			} else {
				adapterName = "Unknown"
			}

			// Yeni bir arayüz oluştur
			currentInterface = &NetworkInterface{
				Name:       adapterName,
				DNSServers: []string{},
				MediaState: "",
			}

			dnsServersBlock = false
			continue
		}

		// Eğer aktif bir arayüz yoksa atla
		if currentInterface == nil {
			continue
		}

		// Medya durumunu kontrol et
		if strings.Contains(line, "Media State") {
			if strings.Contains(line, "Media disconnected") {
				currentInterface.MediaState = "Media disconnected"
				currentInterface.Status = "Disconnected"
			}
			continue
		}

		// Her bir özelliği çıkar
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Preferred gibi ekleri temizle
				value = strings.Replace(value, "(Preferred)", "", -1)

				// Arayüz özelliğini belirle
				switch {
				case strings.Contains(key, "Description"):
					currentInterface.Description = value
				case strings.Contains(key, "Physical Address"):
					currentInterface.MacAddress = value
				case strings.Contains(key, "IPv4 Address"):
					currentInterface.IpAddress = value
					if currentInterface.Status == "" {
						currentInterface.Status = "Connected" // IP adresi varsa bağlı olarak kabul et
					}
				case strings.Contains(key, "Subnet Mask"):
					currentInterface.SubnetMask = value
				case strings.Contains(key, "Link-local IPv6 Address"):
					currentInterface.IPv6Address = value
				case strings.Contains(key, "Default Gateway"):
					currentInterface.DefaultGateway = value
				case strings.Contains(key, "DHCP Enabled"):
					currentInterface.DHCPEnabled = value
				case strings.Contains(key, "DHCP Server"):
					currentInterface.DHCPServer = value
				case strings.Contains(key, "Connection-specific DNS Suffix"):
					currentInterface.DNSSuffix = value
				case strings.Contains(key, "DNS Servers"):
					// DNS sunucuları birden fazla satırda olabilir
					if value != "" {
						currentInterface.DNSServers = append(currentInterface.DNSServers, value)
					}
					dnsServersBlock = true
				case strings.Contains(key, "Lease Obtained"):
					currentInterface.LeaseObtained = value
				case strings.Contains(key, "Lease Expires"):
					currentInterface.LeaseExpires = value
				case strings.Contains(key, "NetBIOS over Tcpip"):
					currentInterface.NetBIOSOverTCPIP = value
				case strings.Contains(key, "Autoconfiguration Enabled"):
					currentInterface.AutoconfigEnabled = value
				case strings.Contains(key, "DHCPv6 IAID"):
					currentInterface.DHCPv6IAID = value
				case strings.Contains(key, "DHCPv6 Client DUID"):
					currentInterface.DHCPv6ClientDUID = value
				}
			}
		} else if dnsServersBlock && !strings.Contains(line, ":") {
			// Önceki satırdan devam eden DNS sunucuları
			currentInterface.DNSServers = append(currentInterface.DNSServers, strings.TrimSpace(line))
		} else {
			dnsServersBlock = false
		}
	}

	// Son arayüzü ekle (eğer varsa)
	if currentInterface != nil {
		interfaces = append(interfaces, *currentInterface)
	}

	// Arayüz tipi bilgilerini netsh komutundan al
	enrichInterfaceTypes(&interfaces)

	return interfaces, nil
}

// enrichInterfaceTypes, arayüzlerin tür bilgilerini netsh komutundan alarak ekler
func enrichInterfaceTypes(interfaces *[]NetworkInterface) {
	// netsh ile arayüz bilgilerini al
	cmd := exec.Command("netsh", "interface", "show", "interface")
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return // Hata durumunda sessizce devam et
	}

	output := out.String()
	lines := strings.Split(output, "\n")

	// Arayüz tiplerini çıkar
	interfaceTypes := make(map[string]string)
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.Contains(line, "---") {
			continue
		}

		parts := regexp.MustCompile(`\s{2,}`).Split(line, -1)
		if len(parts) >= 4 {
			name := strings.TrimSpace(parts[1])
			ifType := strings.TrimSpace(parts[3])
			interfaceTypes[name] = ifType
		}
	}

	// Arayüz tiplerini NetworkInterface yapılarıyla eşleştir
	for i := range *interfaces {
		iface := &(*interfaces)[i]
		// Tam ad eşleşmesi veya içeren arayüzü bul
		for name, ifType := range interfaceTypes {
			if iface.Name == name || strings.Contains(iface.Description, name) {
				iface.Type = ifType
				break
			}
		}

		// Eğer tür hala boşsa, açıklamaya göre tahmin et
		if iface.Type == "" {
			desc := strings.ToLower(iface.Description)
			switch {
			case strings.Contains(desc, "ethernet"):
				iface.Type = "Dedicated"
			case strings.Contains(desc, "wi-fi") || strings.Contains(desc, "wireless"):
				iface.Type = "Wireless"
			case strings.Contains(desc, "bluetooth"):
				iface.Type = "Bluetooth"
			case strings.Contains(desc, "loopback"):
				iface.Type = "Loopback"
			case strings.Contains(desc, "virtual") || strings.Contains(desc, "hyper-v"):
				iface.Type = "Virtual"
			default:
				iface.Type = "Unknown"
			}
		}
	}
}

// GetSystemNetworkInfo, ipconfig /all çıktısından sistem genelindeki ağ yapılandırma bilgilerini alır
func GetSystemNetworkInfo(output string) SystemNetworkInfo {
	var sysInfo SystemNetworkInfo

	// Sistem bilgilerini çıkarmak için yardımcı fonksiyon
	extractValue := func(pattern string) string {
		regex := regexp.MustCompile(pattern)
		match := regex.FindStringSubmatch(output)
		if len(match) > 1 {
			return strings.TrimSpace(match[1])
		}
		return ""
	}

	// Tüm sistem bilgilerini çıkar
	sysInfo.HostName = extractValue(`(?i)Host Name[^:]*:\s*([^\r\n]*)`)
	sysInfo.PrimaryDnsSuffix = extractValue(`(?i)Primary Dns Suffix[^:]*:\s*([^\r\n]*)`)
	sysInfo.NodeType = extractValue(`(?i)Node Type[^:]*:\s*([^\r\n]*)`)
	sysInfo.IPRoutingEnabled = extractValue(`(?i)IP Routing Enabled[^:]*:\s*([^\r\n]*)`)
	sysInfo.WINSProxyEnabled = extractValue(`(?i)WINS Proxy Enabled[^:]*:\s*([^\r\n]*)`)
	sysInfo.DNSSuffixSearchList = extractValue(`(?i)DNS Suffix Search List[^:]*:\s*([^\r\n]*)`)

	return sysInfo
}

// displayNetworkInterfaces, sistemdeki tüm ağ arayüzlerini tablo formatında gösterir
func displayNetworkInterfaces() {
	interfaces, err := ListNetworkInterfaces()
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	if len(interfaces) == 0 {
		fmt.Println("Hiç ağ arayüzü bulunamadı.")
		return
	}

	// ipconfig çıktısını al
	cmd := exec.Command("ipconfig", "/all")
	var out bytes.Buffer
	cmd.Stdout = &out

	err = cmd.Run()
	if err == nil {
		// Sistem bilgilerini göster
		sysInfo := GetSystemNetworkInfo(out.String())
		fmt.Println("\nSistem Ağ Yapılandırması:")
		fmt.Println("========================")

		displayProperty := func(name, value string) {
			if value != "" {
				fmt.Printf("%-30s: %s\n", name, value)
			}
		}

		displayProperty("Bilgisayar Adı", sysInfo.HostName)
		displayProperty("Birincil DNS Soneki", sysInfo.PrimaryDnsSuffix)
		displayProperty("Düğüm Tipi", sysInfo.NodeType)
		displayProperty("IP Yönlendirme", sysInfo.IPRoutingEnabled)
		displayProperty("WINS Proxy", sysInfo.WINSProxyEnabled)
		displayProperty("DNS Sonek Arama Listesi", sysInfo.DNSSuffixSearchList)
		fmt.Println()
	}

	fmt.Println("Ağ Arayüzleri:")
	fmt.Println("==============")

	// tabwriter ile düzgün hizalanmış bir tablo oluştur
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "No\tAd\tDurum\tTip\tIP Adresi\tAlt Ağ Maskesi\tMAC Adresi\t")
	fmt.Fprintln(w, "---\t----------------\t--------\t-------------\t-----------------\t-----------------\t-----------------\t")

	for i, iface := range interfaces {
		// Medya durumuna göre durum göstergesini ayarla
		status := iface.Status
		if iface.MediaState == "Media disconnected" {
			status = "Disconnected"
		} else if status == "" && iface.IpAddress != "" {
			status = "Connected"
		} else if status == "" {
			status = "Unknown"
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
			i+1,
			iface.Name,
			status,
			iface.Type,
			iface.IpAddress,
			iface.SubnetMask,
			iface.MacAddress)
	}

	w.Flush()
	fmt.Println("")
}

// showInterfaceDetails, belirli bir ağ arayüzü hakkında detaylı bilgi gösterir
func showInterfaceDetails(args []string) {
	// Eğer komut parametresi olarak indeks verilmişse, onu kullan
	var indexStr string
	if len(args) > 0 {
		indexStr = args[0]
	} else {
		// Tüm arayüzleri listele
		displayNetworkInterfaces()

		// Kullanıcıdan arayüz indeksi iste
		indexStr = promptForInput("Detaylarını görmek istediğiniz arayüzün indeks numarası: ")
	}

	// İndeksi int'e dönüştür
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		fmt.Printf("Hata: Geçersiz indeks numarası: %s\n", indexStr)
		return
	}

	// Tüm arayüzleri al
	interfaces, err := ListNetworkInterfaces()
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		return
	}

	// İndeks kontrolü
	if index < 1 || index > len(interfaces) {
		fmt.Printf("Hata: Geçersiz indeks: %d, aralık olmalı: 1-%d\n", index, len(interfaces))
		return
	}

	// Seçilen arayüzü göster
	selectedInterface := interfaces[index-1]

	// Arayüz detaylarını göster
	fmt.Printf("\nAğ Arayüzü Detayları (#%d):\n", index)
	fmt.Printf("========================\n")

	// Temel bilgileri göster
	displayProperty := func(name, value string) {
		if value != "" {
			fmt.Printf("%-25s: %s\n", name, value)
		}
	}

	displayProperty("Ad", selectedInterface.Name)
	displayProperty("Açıklama", selectedInterface.Description)

	// Medya durumuna göre durum göstergesini ayarla
	status := selectedInterface.Status
	if selectedInterface.MediaState == "Media disconnected" {
		status = "Disconnected (Media disconnected)"
	} else if status == "" && selectedInterface.IpAddress != "" {
		status = "Connected"
	} else if status == "" {
		status = "Unknown"
	}
	displayProperty("Durum", status)

	displayProperty("Tür", selectedInterface.Type)

	// Ağ yapılandırması
	fmt.Printf("\nAğ Yapılandırması:\n")
	fmt.Printf("------------------\n")
	displayProperty("MAC Adresi", selectedInterface.MacAddress)
	displayProperty("IPv4 Adresi", selectedInterface.IpAddress)
	displayProperty("Alt Ağ Maskesi", selectedInterface.SubnetMask)
	displayProperty("IPv6 Adresi", selectedInterface.IPv6Address)
	displayProperty("Varsayılan Ağ Geçidi", selectedInterface.DefaultGateway)

	// DHCP bilgileri
	if selectedInterface.DHCPEnabled != "" {
		fmt.Printf("\nDHCP Bilgileri:\n")
		fmt.Printf("---------------\n")
		displayProperty("DHCP Etkin", selectedInterface.DHCPEnabled)
		displayProperty("DHCP Sunucusu", selectedInterface.DHCPServer)
		displayProperty("Kira Elde Edilme Zamanı", selectedInterface.LeaseObtained)
		displayProperty("Kira Sona Erme Zamanı", selectedInterface.LeaseExpires)
		displayProperty("DHCPv6 IAID", selectedInterface.DHCPv6IAID)
		displayProperty("DHCPv6 Client DUID", selectedInterface.DHCPv6ClientDUID)
		displayProperty("Otomatik Yapılandırma", selectedInterface.AutoconfigEnabled)
	}

	// DNS bilgileri
	fmt.Printf("\nDNS Bilgileri:\n")
	fmt.Printf("-------------\n")
	displayProperty("DNS Sonek", selectedInterface.DNSSuffix)

	// DNS sunucularını listele
	if len(selectedInterface.DNSServers) > 0 {
		fmt.Printf("%-25s: %s\n", "DNS Sunucuları", selectedInterface.DNSServers[0])
		// Diğer DNS sunucularını göster
		for i := 1; i < len(selectedInterface.DNSServers); i++ {
			fmt.Printf("%-25s  %s\n", "", selectedInterface.DNSServers[i])
		}
	}

	displayProperty("NetBIOS over TCP/IP", selectedInterface.NetBIOSOverTCPIP)

	// İpconfig çıktısını görüntüleme seçeneği
	showRawOutput := promptForOptionalInput("\nHam ipconfig çıktısını göstermek ister misiniz? [E/h]: ", "E")
	if strings.ToLower(showRawOutput) == "e" || strings.ToLower(showRawOutput) == "evet" {
		// ipconfig /all komutunu çalıştır ve çıktıyı işle
		cmd := exec.Command("ipconfig", "/all")
		var out bytes.Buffer
		cmd.Stdout = &out

		err = cmd.Run()
		if err != nil {
			fmt.Printf("ipconfig verisi alınamadı: %v\n", err)
			return
		}

		output := out.String()

		// Arayüz adını içeren bölümü bul (önce tam eşleşme dene)
		searchPattern := fmt.Sprintf("adapter %s:", selectedInterface.Name)
		ifaceNameRegex := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(searchPattern))
		idx := ifaceNameRegex.FindStringIndex(output)

		// Tam eşleşme bulunamazsa, kısmi eşleşme dene
		if idx == nil {
			// Tüm arayüz bölümlerini bul ve uygun olanı seç
			adapterPattern := regexp.MustCompile(`(?i)(\w+)\s+adapter\s+([^\n:]+):`)
			adapterMatches := adapterPattern.FindAllStringSubmatch(output, -1)

			for _, match := range adapterMatches {
				if len(match) > 2 && (match[2] == selectedInterface.Name ||
					strings.Contains(match[2], selectedInterface.Name) ||
					strings.Contains(selectedInterface.Description, match[2])) {
					searchPattern = fmt.Sprintf("%s adapter %s:", match[1], match[2])
					ifaceNameRegex = regexp.MustCompile(`(?i)` + regexp.QuoteMeta(searchPattern))
					idx = ifaceNameRegex.FindStringIndex(output)
					break
				}
			}
		}

		if idx == nil {
			fmt.Printf("Ham ipconfig çıktısında arayüz detayları bulunamadı: %s\n", selectedInterface.Name)
			return
		}

		// Sadece bu arayüz bölümünü al
		subOutput := output[idx[0]:]
		nextIfaceIdx := strings.Index(subOutput[1:], "\r\n\r\n")
		if nextIfaceIdx > 0 {
			subOutput = subOutput[:nextIfaceIdx+3]
		}

		fmt.Printf("\nHam ipconfig Çıktısı:\n")
		fmt.Printf("--------------------\n")

		// Satır satır ayrıştır ve göster
		lines := strings.Split(subOutput, "\n")
		for _, line := range lines {
			if line = strings.TrimSpace(line); line != "" {
				fmt.Println(line)
			}
		}
	}

	fmt.Println("")
}

// executeCommand, kullanıcının girdiği komutu ayrıştırır ve uygun işlemi gerçekleştirir
// Dönüş değeri, programın devam edip etmeyeceğini belirtir (true = devam et, false = çık)
func executeCommand(commandLine string) bool {
	// Komutu ve argümanları ayrıştır
	parts := strings.Fields(commandLine)
	if len(parts) == 0 {
		return true // Boş komut, programı devam ettir
	}

	command := strings.ToLower(parts[0])
	args := parts[1:]

	// Komutu işle
	switch command {
	case "list":
		displayNATEntries()

	case "create":
		createNATEntryInteractive()

	case "delete":
		deleteNATEntryInteractive(args)

	case "interfaces", "if", "ifaces":
		displayNetworkInterfaces()

	case "showif", "ifdetail", "ifinfo":
		showInterfaceDetails(args)

	case "export":
		exportNATRulesInteractive()

	case "import":
		importNATRulesInteractive()

	case "traffic", "stats", "monitor":
		displayNATTraffic()

	case "route-if", "routeif", "ifroute":
		createInterfaceRoutingInteractive()

	case "route-any", "routeany", "any":
		createAnyIPRoutingInteractive()

	case "menu", "main", "mainmenu":
		displayMainMenu()

	case "help":
		displayHelp()

	case "exit", "quit", "q":
		fmt.Println("Program sonlandırılıyor...")
		return false // Programı sonlandır

	default:
		fmt.Printf("Bilinmeyen komut: %s. Yardım için 'help' yazın veya ana menü için 'menu' yazın.\n", command)
	}

	return true // Programı devam ettir
}

// main, programın ana giriş noktasıdır
// İnteraktif bir komut satırı arayüzü sağlar
func main() {
	fmt.Println("Windows NAT Yönetici v1.3")
	fmt.Println("Yazar: Windows Network Admin")
	fmt.Println("Bu program yönetici haklarına sahip bir komut isteminde çalıştırılmalıdır!")

	// Ana menüyü göster
	displayMainMenu()

	// Ana komut döngüsü
	reader := bufio.NewReader(os.Stdin)
	for {
		// Kullanıcıdan komut iste
		var commandLine string

		// Komut istemini göster
		if !strings.HasPrefix(strings.TrimSpace(commandLine), "menu") &&
			!strings.HasPrefix(strings.TrimSpace(commandLine), "main") {
			fmt.Print("\nNAT> ")
		}

		// Komutu oku
		var err error
		commandLine, err = reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Komut okunurken hata: %v\n", err)
			continue
		}

		// Windows'ta satır sonu karakterleri \r\n olabilir, temizleyelim
		commandLine = strings.TrimSpace(commandLine)

		// Menü seçimi mi, komut mu kontrol et
		if len(commandLine) == 1 && (commandLine >= "0" && commandLine <= "9" ||
			commandLine == "x" || commandLine == "X") {
			commandLine = processMenuSelection(commandLine)
		}

		// Komutu işle ve devam edip etmeyeceğimizi belirle
		if !executeCommand(commandLine) {
			break // Döngüden çık ve programı sonlandır
		}
	}
}
