# WatTunnel

WatTunnel (JohnWatsoon/WatTunnel) پورت‌های کاربران را از ایران به `127.0.0.1` خارج می‌برد. ایران کلاینت است و پورت سرویس را منتشر می‌کند؛ خارج سرور است. حامل بین دو سمت یکی از پروفایل‌های زیر است. رمزنگاری این مسیر ChaCha20-Poly1305 با کلید مشترک و تبادل X25519 هر نشست است. ترافیک بین کاربر و ایران هرچه خود سرویس باشد باقی می‌ماند.

باینری پین‌شدهٔ v3.1.2 فقط وقتی قبول می‌شود که SHA-256 آن با انتشار رسمی یکی باشد. اگر روی سرور همان جمع‌آزمایی باشد دوباره آپلود نمی‌شود؛ وگرنه از `bin/<arch>/wattun` یا از همان انتشار، بعد از تطبیق جمع‌آزمایی، نصب می‌شود. ICMP و Fortress به `CAP_NET_RAW` نیاز دارند. آمار فقط روی `127.0.0.1` سرو می‌شود.

حالت مستقیم چند نود ایران را با یک واحد سرور روی خارج نگه می‌دارد. حالت معکوس ICMP، UDP، UDP-DNS و Fortress فقط یک نود ایران دارد، چون خارج یک سوکت مشترک می‌بندد. حامل‌های معکوس TCP و TLS و WebSocket و HTTP/2 و gRPC برای هر نود یک شماره‌گیر جدا روی خارج دارند.

پایشگر اتصال روی ایران پورت‌های فایل `client-*.yml` را هم می‌خواند، همان فایلی که پورت‌های BackPack را می‌خواند. لاگ داشبورد journal واحد کلاینت و دنبالهٔ `/var/log/vxlb-user-connections.log` را با هم نشان می‌دهد. سلامت واچ‌داگ از `/stats` همان کلاینت می‌آید. `alive` با `last_rx_age_ms` تازه‌تر از ۴۵ ثانیه سالم است. سنِ نبودن یا منفی (هنوز بسته‌ای نرسیده) لینک را سالم نشان نمی‌دهد.

## انتخاب و اجرای این خانواده

در «استخرها ← استخر جدید» خانوادهٔ WatTunnel و یکی از حامل‌ها را انتخاب کنید. پورت سرویس کاربران جدا از پورت حامل است. حالت معکوس یعنی خارج به ایران وصل می‌شود و ایران جریان را شروع نمی‌کند. ثبت درخواست را از نتیجهٔ استقرار جدا بدانید.

نام‌های زیر عین شناسهٔ `profile` هستند.

## icmp

<!-- profile:wattunnel:wattunnel:icmp -->

شناسهٔ انتقال: `wattunnel`؛ profile: `icmp`.

وقتی فقط ping عبور می‌کند. نوع درخواست `echo`، `timestamp`، `info` یا `mask` است و دو سمت باید یکی باشند.

## udp

<!-- profile:wattunnel:wattunnel:udp -->

شناسهٔ انتقال: `wattunnel`؛ profile: `udp`.

حامل UDP با کمترین تأخیر وقتی UDP باز است. پورت پیش‌فرض حامل 4443 است و آدرس طرف مقابل `IP:port` است.

## udp-dns

<!-- profile:wattunnel:wattunnel:udp-dns -->

شناسهٔ انتقال: `wattunnel`؛ profile: `udp-dns`.

همان حامل `udp` با شکل DNS. پورت پیش‌فرض 53 است و سرور به IP خودش بایند می‌شود، نه به `:53`. هر دو سمت باید این پروفایل را داشته باشند.

## tcp

<!-- profile:wattunnel:wattunnel:tcp -->

شناسهٔ انتقال: `wattunnel`؛ profile: `tcp`.

حامل TCP که شروع اتصال را شبیه ClientHello می‌کند (`tcp-mimic`). Fake SNI اختیاری است.

## tls

<!-- profile:wattunnel:wattunnel:tls -->

شناسهٔ انتقال: `wattunnel`؛ profile: `tls`.

حامل TLS شبیه HTTPS. SNI و اثر انگشت ClientHello (`fp`) قابل تنظیم است.

## ws

<!-- profile:wattunnel:wattunnel:ws -->

شناسهٔ انتقال: `wattunnel`؛ profile: `ws`.

WebSocket بدون TLS. مسیر `path` در دو سمت یکی است.

## wss

<!-- profile:wattunnel:wattunnel:wss -->

شناسهٔ انتقال: `wattunnel`؛ profile: `wss`.

WebSocket روی TLS. برای مسیری که فقط HTTPS عبور می‌کند.

## h2

<!-- profile:wattunnel:wattunnel:h2 -->

شناسهٔ انتقال: `wattunnel`؛ profile: `h2`.

HTTP/2 روی TLS. برای عبور از Cloudflare این حالت مناسب نیست؛ آنجا `wss` یا `grpc` را انتخاب کنید.

## h2c

<!-- profile:wattunnel:wattunnel:h2c -->

شناسهٔ انتقال: `wattunnel`؛ profile: `h2c`.

HTTP/2 بدون TLS، معمولاً پشت پروکسی که TLS را خودش تمام می‌کند.

## grpc

<!-- profile:wattunnel:wattunnel:grpc -->

شناسهٔ انتقال: `wattunnel`؛ profile: `grpc`.

حامل gRPC. درخواست‌ها به `path` به‌علاوهٔ `/Tun` می‌روند.

## fortress

<!-- profile:wattunnel:wattunnel:fortress -->

شناسهٔ انتقال: `wattunnel`؛ profile: `fortress`.

پیوند `icmp+tcp+tls+wss+udp` در یک نشست. پورت پایه برای UDP است و TCP و TLS و WSS سه پورت بعدی را می‌گیرند.

## پایش و لاگ

واچ‌داگ هر دو واحد `vxlb-wattun-c-*` و `vxlb-wattun-s-*` را فعال می‌خواهد، بعد `/stats` کلاینت را می‌خواند. `alive` با دریافت تازه یعنی `HEALTHY`. سکوت طولانی یعنی `DEGRADED` یا `DOWN`. RTT همان `srtt_ms` است.

خطوط `USER_SESSION_ACTIVE` و `CLEAN_FLOW` پایشگر اتصال‌اند. خطوط `no reply from the server` و `lost contact` از journal خود WatTunnel هستند و در داشبورد به‌عنوان خطا نشان داده می‌شوند.

پروتکل فوروارد سرویس `tcp`، `udp` یا `both` است و به حامل ربطی ندارد.
