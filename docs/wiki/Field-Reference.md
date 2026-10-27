# مرجع فیلدهای پنل

این صفحه مستقیماً از HTML فرم‌ها تولید می‌شود. مقدارها، پیش‌فرض **رابط** هستند و ممکن است منطق JavaScript یا تخصیص خودکار در اجرا آن‌ها را تغییر دهد. required/disabled و نمایش فیلدهای وابسته نیز پویاست؛ جدول، اجازهٔ تحمیل گزینهٔ نامعتبر به API نیست. گزینه‌های غیرفعال و placeholderهای قدیمی، قابلیت عملیاتی ایجاد نمی‌کنند. رمزها و دادهٔ inventory در تولید این مرجع خوانده نمی‌شوند.

برای معنی فیلدهای هر موتور به صفحهٔ آن و برای فیلدهای قدیمی پردازش بسته به [گزینه‌های غیرفعال](Packet-Profiles.md) رجوع کنید. اعداد MTU واقعی فرم ممکن است با default رجیستری تفاوت داشته باشند.

## صفحه اصلی

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| رمز عبور ورود به پنل · `password` | `password`؛ محرمانه؛ در راهنما ثبت نمی‌شود |   |
## استخرهای لودبالانسر

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| pool-search · `pool-search` | `search`؛ خالی/پویا |   |
| pool-engine-filter · `pool-engine-filter` | `select`؛ خالی/پویا |  ``: همهٔ موتورها |
## مخزن سرورها (Inventory)

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| server-search · `server-search` | `search`؛ خالی/پویا |   |
## رکوردهای DNS

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| cf-record-search · `cf-record-search` | `search`؛ خالی/پویا |   |
| cf-record-type-filter · `cf-record-type-filter` | `select`؛ خالی/پویا |  ``: همه انواع؛ ``: A؛ ``: AAAA؛ ``: CNAME؛ ``: TXT؛ ``: MX؛ ``: SRV؛ ``: CAA؛ ``: NS؛ ``: PTR |
## امنیت و رمز عبور

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| رمز عبور جدید · `new-pass-input` | `password`؛ محرمانه؛ در راهنما ثبت نمی‌شود |   |
## تنظیمات عمومی Cloudflare (پیش‌فرض)

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| API Token کلودفلر · `cf-global-token` | `password`؛ محرمانه؛ در راهنما ثبت نمی‌شود |   |
| Zone ID · `cf-global-zone` | `text`؛ خالی/پویا |   |
| ساب‌دومین پیش‌فرض (مثلاً lb.example.com) · `cf-global-sub` | `text`؛ خالی/پویا |   |
## اتصال دامنه اختصاصی و CDN به داشبورد

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| دامنه یا ساب‌دامین داشبورد · `dash-domain-input` | `text`؛ خالی/پویا |   |
| حالت اتصال SSL و گواهینامه · `dash-ssl-mode` | `select`؛ خالی/پویا |  `cloudflare`: Cloudflare Full SSL (پشت CDN با پورت 8443 یا 2052)؛ `letsencrypt`: Let's Encrypt خودکار (Certbot مستقیم / بدون پروکسی CDN) |
## افزودن پورت ورودی کاربران

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| شماره پورت ورودی (مثلاً 443 یا 2053) · `new-port-input` | `number`؛ خالی/پویا | حداقل 1، حداکثر 65535  |
## افزودن سرور به مخزن

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| نام دلخواه (مثلاً ir-mci یا kh-de) · `server-name-input` | `text`؛ خالی/پویا |   |
| آدرس IP سرور · `server-ip-input` | `text`؛ خالی/پویا |   |
| آدرس IPv6 عمومی (اختیاری) · `server-ipv6-input` | `text`؛ خالی/پویا |   |
| پورت SSH · `server-port-input` | `number`؛ 22 |   |
| نام کاربری · `server-user-input` | `text`؛ root |   |
| رمز عبور SSH · `server-pass-input` | `password`؛ محرمانه؛ در راهنما ثبت نمی‌شود |   |
## زمان‌بندی چرخش خودکار IP

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| rotation-enabled · `rotation-enabled` | `checkbox`؛ خالی/پویا |   |
| نوع زمان‌بندی · `rotation-mode` | `select`؛ خالی/پویا |  `interval`: دوره‌ای (هر چند دقیقه)؛ `daily`: روزانه در ساعت مشخص |
| بازهٔ چرخش (دقیقه) · `rotation-interval-val` | `number`؛ خالی/پویا | حداقل 5، حداکثر 10080  |
| ساعت چرخش روزانه (HH:MM) · `rotation-daily-val` | `time`؛ 03:00 |   |
## ایجاد استخر لودبالانسر جدید

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| نام استخر (مثلاً VIP-LB) · `new-pool-name` | `text`؛ خالی/پویا |   |
| انتخاب سرور مقصد خارج · `new-pool-kharej` | `select`؛ خالی/پویا |   |
| موتور تونل · `new-pool-engine` | `select`؛ backpack |  `backpack`: BackPack؛ `waterwall`: WaterWall؛ `gost`: GOST؛ `frp`: FRP؛ `hedioum`: Hedioum؛ `rathole`: Rathole؛ `paqet`: Paqet؛ `kernel`: تونل‌های شبکه و کرنل؛ `spoof`: پردازش بسته (DPI Spoof)؛ `other`: وب و تونل DNS |
| روش انتقال یا پروفایل · `new-pool-proto` | `select`؛ tcp |  `tcp`: TCP؛ `stealth`: Stealth (Noise)؛ `pck`: PCK (Raw TCP)؛ `kcp`: KCP؛ `wss`: WSS (WebSocket + TLS)؛ `quic`: QUIC |
| پورت ترجیحی اتصال به سرور خارج · `waterwall-outer-port` | `number`؛ 443 | حداقل 1، حداکثر 65535  |
| مسیر WaterWall روی هر دو سرور · `waterwall-binary` | `text`؛ /usr/local/bin/waterwall |   |
| رمز عبور مشترک Trojan (حداقل ۸ نویسه) · `waterwall-trojan-password` | `text`؛ خالی/پویا |   |
| بسته‌بندی TLS (نیازمند گواهی) · `waterwall-trojan-tls` | `checkbox`؛ خالی/پویا |   |
| دامنهٔ TLS سرور خارج · `waterwall-server-name` | `text`؛ خالی/پویا |   |
| مسیر گواهی · `waterwall-certificate` | `text`؛ خالی/پویا |   |
| مسیر کلید خصوصی · `waterwall-key` | `text`؛ خالی/پویا |   |
| رمز مشترک Reality (۱ تا ۳۲ بایت) · `waterwall-reality-password` | `text`؛ خالی/پویا |   |
| دامنهٔ بازدیدکننده برای استتار · `waterwall-reality-sni` | `text`؛ www.microsoft.com |   |
| مخفی تونل معکوس · `waterwall-reverse-secret` | `text`؛ خالی/پویا |   |
| رمز فریم BGP (اختیاری) · `waterwall-bgp4-password` | `text`؛ خالی/پویا |   |
| رمز عبور مشترک (حداقل ۸ نویسه) · `gost-password` | `text`؛ خالی/پویا |   |
| پورت ترجیحی اتصال به سرور خارج · `gost-outer-port` | `number`؛ 8443 | حداقل 1، حداکثر 65535  |
| مسیر GOST روی هر دو سرور · `gost-binary` | `text`؛ /usr/local/bin/gost |   |
| توکن احراز هویت (حداقل ۸ نویسه) · `frp-token` | `text`؛ خالی/پویا |   |
| پورت اتصال frpc↔frps (پیش‌فرض 7000) · `frp-port` | `number`؛ 7000 | حداقل 1، حداکثر 65535  |
| Persona (هویت استتار) · `hedioum-persona` | `select`؛ auto |  `auto`: auto؛ `cpanel`: cpanel؛ `directadmin`: directadmin؛ `devops`: devops |
| دامنهٔ اختیاری (Let's Encrypt واقعی) · `hedioum-domain` | `text`؛ خالی/پویا |   |
| جابه‌جایی sshd به پورت decoy (--move-ssh) · `hedioum-move-ssh` | `checkbox`؛ خالی/پویا |   |
| DNS forwarder روی :53 (فقط در حالت TUN) · `hedioum-tun-dns` | `checkbox`؛ خالی/پویا |   |
| پروتکل فوروارد هر پورت (type سرویس) · `rathole-proto` | `select`؛ tcp |  `tcp`: tcp؛ `udp`: udp |
| توکن احراز هویت (حداقل ۸ نویسه) · `rathole-token` | `text`؛ خالی/پویا |   |
| پورت کنترل سرور↔کلاینت (پیش‌فرض 2333) · `rathole-port` | `number`؛ 2333 | حداقل 1، حداکثر 65535  |
| WebSocket روی TLS (فقط در روش websocket) · `rathole-ws-tls` | `checkbox`؛ خالی/پویا |   |
| مسیر PKCS#12 روی سرور (ایران) · `rathole-pkcs12` | `text`؛ خالی/پویا |   |
| رمز PKCS#12 · `rathole-pkcs12-password` | `password`؛ محرمانه؛ در راهنما ثبت نمی‌شود |   |
| گواهی ریشه (trusted_root) روی کلاینت (خارج) · `rathole-trusted-root` | `text`؛ خالی/پویا |   |
| TLS hostname (اختیاری) · `rathole-hostname` | `text`؛ خالی/پویا |   |
| پورت تونل Paqet (سرور↔کلاینت) · `paqet-port` | `number`؛ 8888 | حداقل 1، حداکثر 65535  |
| کلید مخفی Paqet · `paqet-key` | `text`؛ خالی/پویا |   |
| حالت KCP · `paqet-kcp-mode` | `select`؛ fast |  `normal`: normal؛ `fast`: fast؛ `fast2`: fast2؛ `fast3`: fast3 |
| اتصال‌های موازی KCP · `paqet-conn` | `number`؛ 1 | حداقل 1، حداکثر 64  |
| MTU کانال KCP (1280-1500) · `paqet-mtu` | `number`؛ 1280 | حداقل 1280، حداکثر 1500  |
| MTU اینترفیس TUN (1200 تا 1420، پیش‌فرض 1280) · `new-pool-tun-mtu` | `number`؛ 1280 | حداقل 1200، حداکثر 1420  |
| نوع حامل DC6 · `new-pool-dc6-carrier` | `select`؛ ip6gre |  `ip6gre`: ip6gre (RFC 7676 - استاندارد با کمترین سربار)؛ `ip6ip6`: ip6ip6 (RFC 2473 - کپسوله‌سازی مستقیم)؛ `sit`: sit (IPv6 in IPv4) |
| MTU حامل DC6 (1280 تا 1440، پیش‌فرض 1280) · `new-pool-dc6-mtu` | `number`؛ 1280 | حداقل 1280، حداکثر 1440  |
| MTU لینک GRE · `new-pool-gre-mtu` | `number`؛ 1280 | حداقل 576، حداکثر 1400  |
| شناسه شبکه مجازی VNI (اختیاری، 1 تا 16777215) · `new-pool-geneve-vni` | `number`؛ خالی/پویا | حداقل 1، حداکثر 16777215  |
| MTU اینترفیس Geneve (576 تا 1420) · `new-pool-geneve-mtu` | `number`؛ 1280 | حداقل 576، حداکثر 1420  |
| روش پیاده‌سازی VXLAN (3 پروفایل مرجع) · `new-pool-vxlan-method` | `select`؛ p2p |  `p2p`: 1. نقطه به نقطه (P2P Unicast - بدون بریج)؛ `bridge_pointip`: 2. بریج لینوکس با اشاره به IP ریموت (Bridge + IP Pointing)؛ `fdb_bridge`: 3. بریج لینوکس با جدول فورواردینگ (Bridge + FDB Unicast) |
| شناسه شبکه مجازی VNI (1 تا 16777215) · `new-pool-vxlan-vni` | `number`؛ 1000 | حداقل 1، حداکثر 16777215  |
| پورت مقصد UDP (پیش‌فرض 4789) · `new-pool-vxlan-port` | `number`؛ 4789 | حداقل 1، حداکثر 65535  |
| MTU اینترفیس VXLAN (576 تا 1450، پیش‌فرض 1280) · `new-pool-vxlan-mtu` | `number`؛ 1280 | حداقل 576، حداکثر 1450  |
| نام بریج اختصاصی (اختیاری؛ برای روش‌های 2 و 3) · `new-pool-vxlan-bridge` | `text`؛ خالی/پویا |   |
| شناسه شبکه مجازی VNI (اختیاری، 1 تا 16777215) · `new-pool-vxsec-vni` | `number`؛ خالی/پویا | حداقل 1، حداکثر 16777215  |
| پورت مقصد UDP (پیش‌فرض 4789) · `new-pool-vxsec-port` | `number`؛ 4789 | حداقل 1، حداکثر 65535  |
| MTU اینترفیس VXLAN+IPsec (576 تا 1400) · `new-pool-vxsec-mtu` | `number`؛ 1280 | حداقل 576، حداکثر 1400  |
| MTU اینترفیس GRE6 (1200 تا 1440، پیش‌فرض 1280) · `new-pool-gre6-mtu` | `number`؛ 1280 | حداقل 1200، حداکثر 1440  |
| MTU اینترفیس IP6IP6 (1280 تا 1460، پیش‌فرض 1280) · `new-pool-ip6ip6-mtu` | `number`؛ 1280 | حداقل 1280، حداکثر 1460  |
| پورت شنود WireGuard (UDP Listen Port، پیش‌فرض 51820) · `new-pool-wireguard-port` | `number`؛ 51820 | حداقل 1، حداکثر 65535  |
| MTU اینترفیس WireGuard (576 تا 1420، پیش‌فرض 1280) · `new-pool-wireguard-mtu` | `number`؛ 1280 | حداقل 576، حداکثر 1420  |
| تولید کلید پیش‌مشترک (PresharedKey) جهت مقاومت کوانتومی/متقارن · `new-pool-wireguard-psk` | `checkbox`؛ خالی/پویا |   |
| دامنه / ساب‌دامین تونل DNS (الزامی) · `slipstream-domain` | `text`؛ خالی/پویا |   |
| DNS Resolvers (با کاما جدا کنید) · `slipstream-resolvers` | `text`؛ 1.1.1.1:53, 8.8.8.8:53 |   |
| پورت شنود DNS سرور خارج (پیش‌فرض 53) · `slipstream-dns-port` | `number`؛ 53 | حداقل 1، حداکثر 65535  |
| سقف نرخ DNS برای هر IP منبع (QPS) · `slipstream-rate-limit` | `number`؛ 1000 | حداقل 10، حداکثر 2000  |
| نام دامنهٔ جعلی SNI (سایت‌های مجاز/داخلی) · `spoof-fake-sni` | `text`؛ www.shaparak.ir |   |
| اختلاف هاپ برای برآورد Auto-TTL · `spoof-ttl-delta` | `number`؛ 3 | حداقل 1، حداکثر 15  |
| لیست آی‌پی‌های چرخشی جعل مبدأ (ParsaKSH / راند-رابین با کاما) · `spoof-ip-list` | `text`؛ 2.188.21.10, 185.143.232.10 |   |
| آی‌پی قرینه جعلی مقصد (Peer Spoof IP) · `spoof-peer-ip` | `text`؛ 104.16.132.229 |   |
| ریزولورهای DNS آپلود (QS-Tunnel / HYPERION-X) · `spoof-dns-resolvers` | `text`؛ 8.8.8.8, 1.1.1.1, 10.202.10.202 |   |
| آی‌پی جعلی دانلود مستقیم سرور خارج (Fake Send IP) · `spoof-fake-send-ip` | `text`؛ 4.2.2.4 |   |
| کلید احراز هویت هاست تاریک (HYPERION-X Knock Key) · `spoof-knock-key` | `text`؛ خالی/پویا |   |
| پورت‌های سرویس ورودی کاربران (با کاما جدا کنید) · `new-pool-ports` | `text`؛ 443, 2053 |   |
## افزودن سرور ایران به استخر

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| انتخاب سرور ایران از مخزن · `select-iran-node-to-add` | `select`؛ خالی/پویا |   |
## تنظیمات DNS کلودفلر استخر

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| Cloudflare API Token · `pool-cf-token` | `password`؛ محرمانه؛ در راهنما ثبت نمی‌شود |   |
| Zone ID · `pool-cf-zone` | `text`؛ خالی/پویا |   |
| محدودهٔ مدیریت DNS · `pool-cf-scope` | `select`؛ خالی/پویا |  `single`: یک رکورد مشخص، شامل wildcard؛ `all_subdomains`: همهٔ ساب‌دامین‌های دارای رکورد A |
| نام رکورد یا دامنهٔ اصلی · `pool-cf-sub` | `text`؛ خالی/پویا |   |
## تغییر مرحله‌ای نوع تونل

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| موتور تونل · `transport-change-engine` | `select`؛ خالی/پویا |  `backpack`: BackPack؛ `waterwall`: WaterWall؛ `gost`: GOST؛ `frp`: FRP؛ `hedioum`: Hedioum؛ `rathole`: Rathole؛ `paqet`: Paqet؛ `kernel`: تونل‌های شبکه و کرنل؛ `spoof`: پردازش بسته — استخر جداگانه بسازید (غیرفعال)؛ `other`: وب و تونل DNS |
| روش انتقال یا پروفایل جدید · `transport-target` | `select`؛ خالی/پویا |  ``: نوع جدید را انتخاب کنید (غیرفعال) |
| شناسهٔ VNI (خالی: خودکار) · `transport-overlay-vni` | `number`؛ خالی/پویا | حداقل 1، حداکثر 16777215  |
| پورت UDP برای VXLAN · `transport-overlay-port` | `number`؛ 4789 | حداقل 1، حداکثر 65535  |
| پورت UDP برای WireGuard · `transport-wireguard-port` | `number`؛ 51820 | حداقل 1، حداکثر 65535  |
| کلید مشترک اضافی (PSK) · `transport-wireguard-psk` | `checkbox`؛ خالی/پویا |   |
| مسیر گواهی PKCS#12 روی سرور ایران · `transport-rathole-pkcs12` | `text`؛ خالی/پویا |   |
| رمز گواهی PKCS#12 · `transport-rathole-password` | `password`؛ محرمانه؛ در راهنما ثبت نمی‌شود |   |
| مسیر گواهی ریشه روی سرور خارج · `transport-rathole-root` | `text`؛ خالی/پویا |   |
| نام میزبان گواهی TLS · `transport-rathole-hostname` | `text`؛ خالی/پویا |   |
| نام دامنهٔ جعلی SNI · `transport-spoof-fake-sni` | `text`؛ www.shaparak.ir |   |
| اختلاف هاپ Auto-TTL · `transport-spoof-ttl-delta` | `number`؛ 3 | حداقل 1، حداکثر 10  |
| لیست آی‌پی‌های چرخشی مبدأ · `transport-spoof-ip-list` | `text`؛ 2.188.21.10, 185.143.232.10 |   |
| آی‌پی قرینه جعلی مقصد · `transport-spoof-peer-ip` | `text`؛ 104.16.132.229 |   |
| ریزولورهای DNS آپلود · `transport-spoof-dns-resolvers` | `text`؛ 8.8.8.8, 1.1.1.1, 10.202.10.202 |   |
| آی‌پی جعلی دانلود مستقیم · `transport-spoof-fake-send-ip` | `text`؛ 4.2.2.4 |   |
| کلید هاست تاریک HYPERION-X · `transport-spoof-knock-key` | `text`؛ خالی/پویا |   |
| شارد داده FEC (Data Shards) · `transport-fec-data` | `number`؛ 10 | حداقل 1، حداکثر 20  |
| شارد تصحیح خطا FEC (Parity Shards) · `transport-fec-parity` | `number`؛ 3 | حداقل 1، حداکثر 10  |
| نوع حامل DC6 · `transport-dc6-carrier` | `select`؛ sit |  `sit`: sit (IPv6 in IPv4 - سازگار با آدرس‌های IPv4)؛ `ip6gre`: ip6gre (RFC 7676 - نیازمند آدرس‌های IPv6 عمومی دو طرف)؛ `ip6ip6`: ip6ip6 (RFC 2473 - نیازمند آدرس‌های IPv6 عمومی دو طرف) |
| MTU حامل DC6 (1280 تا 1440، پیش‌فرض 1280) · `transport-dc6-mtu` | `number`؛ 1280 | حداقل 1280، حداکثر 1440  |
| MTU اینترفیس · `transport-mtu-input` | `number`؛ 1400 | حداقل 576، حداکثر 1500  |
| دامنهٔ واگذارشدهٔ DNS · `transport-slipstream-domain` | `text`؛ خالی/پویا |   |
| Resolverها (با کاما جدا شوند) · `transport-slipstream-resolvers` | `text`؛ 1.1.1.1,8.8.8.8 |   |
## تنظیمات لینک GRE

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| MTU لینک خصوصی · `gre-settings-mtu` | `number`؛ خالی/پویا | حداقل 576، حداکثر 1400  |
## ماتریس لینک‌های WireGuard

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| پورت پایهٔ UDP (هر زوج یک پورت مستقل) · `matrix-port` | `number`؛ 51820 | حداقل 1، حداکثر 65535  |
| MTU خصوصی · `matrix-mtu` | `number`؛ 1400 | حداقل 576، حداکثر 1440  |
## تنظیمات Slipstream

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| دامنهٔ واگذارشدهٔ DNS · `slipstream-settings-domain` | `text`؛ خالی/پویا |   |
| Resolverها با کاما جدا شوند · `slipstream-settings-resolvers` | `text`؛ خالی/پویا |   |
| پورت عمومی DNS · `slipstream-settings-port` | `number`؛ خالی/پویا | حداقل 1، حداکثر 65535  |
| سقف QPS هر IP منبع · `slipstream-settings-rate` | `number`؛ خالی/پویا | حداقل 10، حداکثر 2000  |
## تنظیمات اینترفیس VXLAN + IPsec

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| MTU اینترفیس خصوصی (576 تا 1400) · `vxsec-settings-mtu` | `number`؛ خالی/پویا | حداقل 576، حداکثر 1400  |
## تنظیمات اینترفیس Geneve

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| MTU اینترفیس خصوصی (576 تا 1420) · `geneve-settings-mtu` | `number`؛ خالی/پویا | حداقل 576، حداکثر 1420  |
## تنظیمات و وضعیت VXLAN

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| MTU اینترفیس (576 تا 1450) · `vxlan-settings-mtu` | `number`؛ خالی/پویا | حداقل 576، حداکثر 1450  |
## تنظیمات اینترفیس GRE6

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| MTU اینترفیس GRE6 (1200 تا 1440) · `gre6-settings-mtu` | `number`؛ خالی/پویا | حداقل 1200، حداکثر 1440  |
## تنظیمات اینترفیس IP6IP6

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| MTU اینترفیس IP6IP6 (1280 تا 1460) · `ip6ip6-settings-mtu` | `number`؛ خالی/پویا | حداقل 1280، حداکثر 1460  |
## تنظیمات و آزمون WireGuard

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| MTU اینترفیس WireGuard (576 تا 1420) · `wireguard-settings-mtu` | `number`؛ خالی/پویا | حداقل 576، حداکثر 1420  |
## افزودن توکن Cloudflare

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| نام پروفایل · `cf-profile-label` | `text`؛ خالی/پویا |   |
| API Token · `cf-profile-token` | `password`؛ محرمانه؛ در راهنما ثبت نمی‌شود |   |
## ویرایش پروفایل

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| نام پروفایل · `cf-edit-profile-label` | `text`؛ خالی/پویا |   |
| چرخش توکن (اختیاری) · `cf-edit-profile-token` | `password`؛ محرمانه؛ در راهنما ثبت نمی‌شود |   |
## رکورد DNS

| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |
| --- | --- | --- |
| نوع رکورد · `cf-record-type` | `select`؛ خالی/پویا |  `A`: A؛ `AAAA`: AAAA؛ `CNAME`: CNAME؛ `TXT`: TXT؛ `MX`: MX؛ `SRV`: SRV؛ `CAA`: CAA |
| نام · `cf-record-name` | `text`؛ خالی/پویا |   |
| محتوا · `cf-record-content` | `text`؛ خالی/پویا |   |
| اولویت (Priority) · `cf-record-priority` | `number`؛ 10 | حداقل 0، حداکثر 65535  |
| TTL · `cf-record-ttl` | `select`؛ خالی/پویا |  `1`: Auto؛ `60`: 1 دقیقه؛ `300`: 5 دقیقه؛ `1800`: 30 دقیقه؛ `3600`: 1 ساعت؛ `86400`: 1 روز |
| cf-record-proxied · `cf-record-proxied` | `checkbox`؛ خالی/پویا |   |
