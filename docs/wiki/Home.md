# راهنمای جامع فارسی VX-LB

این راهنما برای نصب، انتخاب تونل و مدیریت روزمرهٔ پنل است. منبع آن کد پنل، آداپتورها و رجیستری قابلیت‌های همین نسخه است؛ وجود یک نام در رجیستری، به معنی آماده‌بودن آن در فرم ساخت استخر نیست.

## از کجا شروع کنم؟

1. [نصب و به‌روزرسانی](Installation.md): پیش‌نیاز میزبان، نصب تک‌خطی، نصب آفلاین و ورود امن.
2. [اولین استخر](Quickstart.md): ثبت سرورها، انتخاب موتور و پروفایل، پورت‌ها و آزمون نتیجه.
3. [راهنمای پنل](Panel.md): تمام بخش‌ها، موبایل، دسکتاپ و تنظیمات سیستم.
4. [ساخت، تغییر و حذف](Pools-and-Operations.md): مراحل زنده، قفل تغییرات، بازگردانی و خطاها.

## انتخاب موتور و پروفایل

| خانواده | محتوای راهنما |
| --- | --- |
| [BackPack](BackPack.md) | TCP، Noise، Raw TCP، KCP، WSS و QUIC |
| [WaterWall](WaterWall.md) | HalfDuplex، Reverse، Trojan، Bgp4 و Reality |
| [GOST](GOST.md) | همهٔ ۱۳ پروفایل Shadowsocks، obfs4، gRPC، SSH و حامل‌های KCP/QUIC |
| [FRP](FRP.md) | انتقال TCP، UDP و حالت ترکیبی |
| [Hedioum](Hedioum.md) | SOCKS5، TUN، Gateway و Personaها |
| [Rathole](Rathole.md) | TCP، TLS، Noise و WebSocket |
| [Paqet](Paqet.md) | انتقال پورت، چهار حالت KCP و پارامترهای شبکه |
| [کرنل و شبکه](Kernel-Tunnels.md) | WireGuard، TUN، GRE/IPsec، GRE6، IP6IP6، VXLAN، DC6 و Geneve/IPsec |
| [وب و DNS](Web-and-DNS.md) | WS، HTTP/HTTPS CONNECT و Slipstream |
| [پردازش بسته](Packet-Profiles.md) | پنج پروفایل آزمایشی و فهرست گزینه‌های غیرفعال |

## قابلیت‌های پنل

- [Cloudflare و DNS](Cloudflare-and-DNS.md): توکن‌ها، Zone، رکوردها، اتصال DNS استخر، failover و چرخش IP.
- [پایش و عیب‌یابی اتصال](Monitoring.md): سلامت، تأخیر، لاگ، BBR و تشخیص دادهٔ قدیمی.
- [لینک خصوصی و ماتریس](Private-Links.md): اتصال زوج‌های انتخابی مستقل از استخر.
- [امنیت و پشتیبان‌گیری](Security-and-Backup.md): رمز پنل، SSH، گواهی‌ها، داده و بازیابی.
- [رفع خطا و پرسش‌های رایج](Troubleshooting.md).
- [مرجع تمام فیلدهای فرم‌ها](Field-Reference.md) و [رجیستری کامل قابلیت‌ها](Capability-Reference.md).
- [نگهداری و انتشار Wiki](Maintainers.md).

## معنی وضعیت پشتیبانی

`verified` یعنی رجیستری برای همان موتور شواهد آزمون ثبت کرده است؛ تضمین سرعت یا کارکرد روی همهٔ دیتاسنترها نیست. `experimental` به آزمون روی سرورهای خودتان نیاز دارد. `unsupported` غیرفعال است. در حالت production، موتور آزمایشی بدون مجوز صریح عملیاتی پذیرفته نمی‌شود؛ گزینهٔ override همه‌جا در پنل وجود ندارد.

رمزنگاری را برای هر پروفایل جدا بررسی کنید: مثلاً TCP سادهٔ BackPack و Rathole، VXLAN خام، GRE6، IP6IP6 و DC6 به‌تنهایی محرمانگی ایجاد نمی‌کنند. سازگاری CDN و عبور از اختلال نیز به مسیر واقعی وابسته است.
