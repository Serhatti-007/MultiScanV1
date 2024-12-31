#!/bin/bash

echo "----------------------------------------"
echo "MultiScanV1 Kurulum Başlıyor..."
echo "----------------------------------------"

# Gerekli bağımlılıkları yükle
echo "Gerekli Python kütüphaneleri yükleniyor..."
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "----------------------------------------"
    echo "Kurulum Tamamlandı!"
    echo "Programı çalıştırmak için aşağıdaki komutu kullanabilirsiniz:"
    echo "python scanner.py"
    echo "----------------------------------------"
else
    echo "Hata: Bağımlılık yükleme sırasında bir sorun oluştu."
    echo "Lütfen pip ve internet bağlantınızı kontrol edin."
fi
