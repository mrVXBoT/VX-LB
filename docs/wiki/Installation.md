# نصب، به‌روزرسانی و ورود

## پیش‌نیازها

میزبان مدیریت: Linux با x86_64 یا aarch64، CPython 3.10 تا 3.14، ماژول venv و glibc حداقل 2.34 برای wheelhouse همراه پروژه. Alpine/musl با این بسته پشتیبانی نمی‌شود. Ubuntu 22.04/24.04 و Debian 12/13 با Python مناسب نمونه‌های قابل استفاده‌اند. نصب سرویس و اعمال تنظیمات شبکه به root یا sudo نیاز دارد؛ اجرای سرویس‌های مدیریت‌شده روی نودها به systemd وابسته است.

میزبان مدیریت باید به SSH سرورهای دو سمت دسترسی داشته باشد. آفلاین‌بودن مخزن نصب، نیاز به اتصال SSH، ماژول کرنل یا بسته‌های سیستم‌عامل موتور را حذف نمی‌کند.

## نصب تک‌خطی آنلاین

روی میزبان مدیریت اجرا کنید:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mrVXBoT/VX-LB/main/install.sh)
```

مسیر معمول نصب `/opt/vx-lb` است و فرمان `vx-lb` ساخته می‌شود. نصب‌کننده مراحل، زمان سپری‌شده و مسیر لاگ خصوصی `/tmp/vx-lb-install.*.log` را نشان می‌دهد. خطای نصب را با همان لاگ بررسی کنید.

## نصب از checkout

```bash
git clone https://github.com/mrVXBoT/VX-LB.git
cd VX-LB
bash install.sh
./run.sh
```

نصب محلی از payload تأییدشدهٔ همراه استفاده می‌کند. نصب تازهٔ تک‌خطی برای دریافت کد به اینترنت نیاز دارد.

## راه‌اندازی پنل

```bash
vx-lb --set-web-password
vx-lb --web
ssh -L 8088:127.0.0.1:8088 root@YOUR_MANAGEMENT_SERVER
```

فرمان SSH را روی دستگاه خودتان اجرا کنید؛ سپس `http://127.0.0.1:8088` را در مرورگر همان دستگاه باز کنید. پنل به‌صورت پیش‌فرض روی `127.0.0.1:8088` گوش می‌دهد. تغییر `VX_LB_WEB_HOST` آن را روی آدرس دیگری bind می‌کند؛ این کار جای HTTPS و کنترل دسترسی را نمی‌گیرد. `VX_LB_WEB_PASSWORD` فقط برای bootstrap اولیه کاربرد دارد. پشت HTTPS، تنظیم `VX_LB_WEB_SECURE_COOKIE=1` را متناسب با استقرار انجام دهید.

## به‌روزرسانی و نصب دوباره

ابتدا از [داده‌ها](Security-and-Backup.md) نسخهٔ پشتیبان بگیرید و منتظر پایان عملیات فعال بمانید.

```bash
bash /opt/vx-lb/install.sh --check
bash /opt/vx-lb/install.sh --update
```

`--update` دریافت آنلاین و fast-forward صریح است؛ تغییرات محلی یا تاریخچهٔ واگرا را reset نمی‌کند. نصب دوبارهٔ بدون دانلود با `bash /opt/vx-lb/install.sh` یا `--offline` انجام می‌شود. `--offline` و `--update` هم‌زمان مجاز نیستند. بعد از به‌روزرسانی کد، پنل را از بخش تنظیمات restart کنید تا فرایند جدید کد را بارگذاری کند؛ تعویض فایل‌ها به‌تنهایی فرایند در حال اجرا را عوض نمی‌کند.

## نصب آفلاین

روی دستگاه آماده، کیت و checksum را بسازید:

```bash
bash scripts/build_offline_kit.sh /tmp/vxlb-offline.tar.gz
```

هر دو فایل را منتقل کنید، checksum را بررسی و در پوشهٔ تازه استخراج کنید:

```bash
sha256sum -c vxlb-offline.tar.gz.sha256
mkdir -p /opt/vx-lb
tar -xzf vxlb-offline.tar.gz -C /opt/vx-lb
bash /opt/vx-lb/install.sh --check
bash /opt/vx-lb/install.sh
```

اگر نصب قبلی دارید، روی مسیر غیرخالی استخراج نکنید؛ کیت را در مسیر تازه باز کنید و داده را جدا منتقل کنید. کیت شامل اطلاعات زنده و رمزها نیست. بسته‌های سیستم‌عامل مثل Python/venv و نیازمندی‌های کرنل را قبل از قطع اینترنت آماده کنید. جزئیات سازگاری و خطاها در [راهنمای آفلاین مخزن](https://github.com/mrVXBoT/VX-LB/blob/main/docs/offline-install.md) آمده است.

## بررسی سرویس‌ها

```bash
vx-lb --list-capabilities
sudo systemctl status vx-lb-watchdog
sudo journalctl -u vx-lb-watchdog -n 100 --no-pager
```

خاموش‌بودن watchdog با خاموش‌بودن همهٔ تونل‌ها یکسان نیست؛ سرویس تونل روی سرورهای مقصد و سرویس پایش میزبان مدیریت مستقل‌اند.
