# مرجع کامل قابلیت‌ها و تفاوت رجیستری با پنل

این صفحه از `core/capabilities.py` و کاتالوگ واقعی `web/app.js` تولید می‌شود. عدد MTU این جدول مقدار رجیستری است؛ مقدار پیش‌فرض و محدودیت **فرم استقرار** را از [مرجع فیلدها](Field-Reference.md) بخوانید. امنیت ثبت‌شده برای یک خانواده الزاماً امنیت همهٔ پروفایل‌های آن نیست. نام در رجیستری، ثبت آداپتور، امکان ساخت در پنل و آزمون واقعی چهار موضوع جدا هستند.

آداپتورهای توسعه مثل TrustTunnel، Backhaul و Hysteria2 ممکن است کانفیگ تولید کنند ولی probe/modify/rollback زندهٔ تأییدشده نداشته باشند. برای آن‌ها فرمان نصب یا پشتیبانی پنل اختراع نشده است. گزینه‌های لایه‌ای و قدیمی نیز صرفاً با وجود کلاس Python، آمادهٔ استقرار عمومی محسوب نمی‌شوند.

کاتالوگ `transports_13.py` در این نسخه فقط هفت شناسهٔ `tcp, ws, wss, http, https, tun, dc6` دارد. XHTTP، XHTTPS و NOVA گزینهٔ فعال فرم فعلی نیستند؛ توضیح قدیمی یک فایل، مدرک فعال‌بودن آن‌ها نیست.

## `backpack` — BackPack

موتور چندحاملی BackPack؛ امنیت هر حالت جدا بررسی شود

- وضعیت: **تأییدشده در رجیستری**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L4`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `tls`؛ ماژول/نیازمندی: `ماژول اختصاصی ثبت نشده`.
- MTU پیش‌فرض رجیستری: `1420`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Production baseline engine tested across 6 transports

## `waterwall` — WaterWall

زنجیره‌های پروتکلی WaterWall با پنج حالت پنل

- وضعیت: **آزمایشی**؛ مسیر راهنما: [WaterWall](WaterWall.md).
- لایه: `L4`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `noise`؛ ماژول/نیازمندی: `ماژول اختصاصی ثبت نشده`.
- MTU پیش‌فرض رجیستری: `1350`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Trojan/Reality/Reverse/HalfDuplex/Bgp4 chains generated from WaterWall protocol nodes; TCP verified, UDP on Trojan

## `trusttunnel` — TrustTunnel

آداپتور endpoint/client با TUN یا SOCKS5 و مدیریت گواهی؛ در منوی ساخت فعلی نیست

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `tls`؛ ماژول/نیازمندی: `tun`.
- MTU پیش‌فرض رجیستری: `1360`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Isolated adapter integration ready for test environment verification

## `slipstream` — Slipstream

حامل DNS آزمایشی بر زیردامنه واگذارشده و رله امن

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Web-and-DNS](Web-and-DNS.md).
- لایه: `L7`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `tls13`؛ ماژول/نیازمندی: `xt_hashlimit`.
- MTU پیش‌فرض رجیستری: `1200`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1`.
- دلیل وضعیت در منبع: Experimental DNS carrier with mutual TLS and owned per-source UDP rate limiting; public DNS and independent-host SSH acceptance pending

## `backhaul` — Backhaul

آداپتور حامل‌های TCP/TCPMUX/WS/WSS/UDP؛ در منوی ساخت فعلی نیست

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L4`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `tls`؛ ماژول/نیازمندی: `ماژول اختصاصی ثبت نشده`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Adapter created; profile compatibility verified against official releases

## `frp` — FRP

پراکسی معکوس FRP؛ سه حالت فوروارد در پنل

- وضعیت: **آزمایشی**؛ مسیر راهنما: [FRP](FRP.md).
- لایه: `L4`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `tls`؛ ماژول/نیازمندی: `ماژول اختصاصی ثبت نشده`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1, 1:M, N:M`.
- دلیل وضعیت در منبع: Standard frpc/frps adapter with multi-transport negotiation

## `hedioum` — Hedioum Pool Tunnel

حالت‌های SOCKS5، TUN و gateway با Persona قابل انتخاب

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Hedioum](Hedioum.md).
- لایه: `L4`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `tls`؛ ماژول/نیازمندی: `ماژول اختصاصی ثبت نشده`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1, 1:M, N:M`.
- دلیل وضعیت در منبع: Self-sufficient multi-protocol mimicry pool multiplexer

## `rathole` — Rathole

پراکسی معکوس با حامل TCP، TLS، Noise یا WebSocket

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Rathole](Rathole.md).
- لایه: `L4`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `noise`؛ ماژول/نیازمندی: `ماژول اختصاصی ثبت نشده`.
- MTU پیش‌فرض رجیستری: `1420`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: High-concurrency Rust-based tunnel adapter with Noise transport encryption

## `paqet` — Paqet

انتقال پورت با KCP روی بسته خام و تنظیم interface/MAC

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Paqet](Paqet.md).
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `noise`؛ ماژول/نیازمندی: `raw_socket, bpf`.
- MTU پیش‌فرض رجیستری: `1280`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Raw-packet KCP engine (hanselime/paqet); awaiting operational validation on live endpoints

## `gost` — GOST

زنجیره‌های پراکسی و سیزده پروفایل اختصاصی پنل

- وضعیت: **آزمایشی**؛ مسیر راهنما: [GOST](GOST.md).
- لایه: `L4`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `tls`؛ ماژول/نیازمندی: `ماژول اختصاصی ثبت نشده`.
- MTU پیش‌فرض رجیستری: `1380`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1, N:M`.
- دلیل وضعیت در منبع: Supports validated proxy chaining combinations

## `hysteria2` — Hysteria 2

آداپتور QUIC با کنترل ازدحام و port hopping؛ در منوی ساخت فعلی نیست

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L4`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `tls`؛ ماژول/نیازمندی: `ماژول اختصاصی ثبت نشده`.
- MTU پیش‌فرض رجیستری: `1350`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Adapter with bidirectional UDP reachability verification and port hopping

## `gre_ipv4` — GRE IPv4 + IPsec

GRE روی IPv4 با IPsec اجباری در مسیر مدیریت‌شده

- وضعیت: **تأییدشده در رجیستری**؛ مسیر راهنما: [Kernel-Tunnels](Kernel-Tunnels.md).
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `ipsec`؛ ماژول/نیازمندی: `gre, xfrm_user, af_key`.
- MTU پیش‌فرض رجیستری: `1280`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Isolated lab tested with ESP packet capture, rekeying, and plaintext drop verification

## `ip6ip6` — IP6IP6

کپسوله‌سازی IPv6 در IPv6 بدون رمزنگاری داخلی

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Kernel-Tunnels](Kernel-Tunnels.md).
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `ip6_tunnel`.
- MTU پیش‌فرض رجیستری: `1280`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1, N:M`.
- دلیل وضعیت در منبع: Native IPv6 tunnel adapter with return route validation

## `gre6` — GRE6 (IPv6 GRE)

GRE بر بستر IPv6 بدون رمزنگاری داخلی

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Kernel-Tunnels](Kernel-Tunnels.md).
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `ip6_gre`.
- MTU پیش‌فرض رجیستری: `1280`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: GRE over IPv6 carrier adapter

## `gretap` — GRETAP (Layer 2 Ethernet over GRE)

پل اترنت لایه ۲ روی GRE/IPv4؛ گزینه توسعه خارج از منوی ساخت

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L2`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `gre, bridge`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Layer 2 bridge tunnel with loop prevention

## `gre6tap` — GRE6TAP (Layer 2 Ethernet over IPv6 GRE)

پل اترنت لایه ۲ روی GRE/IPv6؛ خارج از منوی ساخت

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L2`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `ip6_gre, bridge`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Layer 2 bridge tunnel over IPv6 carrier

## `gre6tap_ipsec` — GRE6TAP + IPsec

پل GRE6TAP به‌همراه IPsec؛ خارج از منوی ساخت

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L2`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv6`.
- رمزنگاری رجیستری: `ipsec`؛ ماژول/نیازمندی: `ip6_gre, bridge, xfrm_user`.
- MTU پیش‌فرض رجیستری: `1340`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Layer 2 encrypted tunnel with separate tunnel state and IPsec SA management

## `sit` — SIT / 6in4

حمل IPv6 روی IPv4؛ در پنل از انتخاب carrier در DC6 استفاده می‌شود

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `sit`.
- MTU پیش‌فرض رجیستری: `1440`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1`.
- دلیل وضعیت در منبع: Configured 6in4 tunnel connecting IPv6 islands over IPv4

## `6to4_unicast` — 6TO4 Unicast

6to4 با مقصد مشخص؛ خارج از منوی ساخت فعلی

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `sit`.
- MTU پیش‌فرض رجیستری: `1440`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1`.
- دلیل وضعیت در منبع: Explicitly configured unicast endpoints; strictly distinct from deprecated anycast

## `6to4_anycast` — 6TO4 Anycast (Deprecated - RFC 7526)

6to4 anycast قدیمی؛ غیرفعال و قابل توصیه برای استقرار نیست

- وضعیت: **غیرفعال**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `sit`.
- MTU پیش‌فرض رجیستری: `1440`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1`.
- دلیل وضعیت در منبع: Officially deprecated by IETF RFC 7526 due to operational risks, blackholing, and spoofing vulnerabilities. Disabled by default.

## `anycast` — Public Anycast (requires owned prefix + routing)

مفهوم مسیریابی Anycast؛ موتور تونل عملیاتی این نسخه نیست

- وضعیت: **غیرفعال**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `ماژول اختصاصی ثبت نشده`.
- MTU پیش‌فرض رجیستری: `1500`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `N:M`.
- دلیل وضعیت در منبع: Requires operator-owned public prefix, routing/BGP control and a concrete use-case definition; not an in-panel tunnel and disabled until those prerequisites are defined.

## `vxlan` — VXLAN (Single / Multi-Server)

overlay لایه ۲ روی UDP، بدون رمزنگاری یا احراز هویت داخلی

- وضعیت: **تأییدشده در رجیستری**؛ مسیر راهنما: [Kernel-Tunnels](Kernel-Tunnels.md).
- لایه: `L2`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `vxlan, bridge`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1, N:M`.
- دلیل وضعیت در منبع: Unencrypted RFC 7348 overlay; kernel link test verified. Use vxlan_ipsec for encrypted production links.

## `vxlan_ipsec` — VXLAN + IPsec

VXLAN حفاظت‌شده با IPsec ESP و کنترل عبور خام

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Kernel-Tunnels](Kernel-Tunnels.md).
- لایه: `L2`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `ipsec`؛ ماژول/نیازمندی: `vxlan, xfrm_user`.
- MTU پیش‌فرض رجیستری: `1280`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Encrypted VXLAN tunnels with PSK IKEv2, fail-closed plaintext guard, and automatic SA management

## `geneve` — Geneve

overlay خام Geneve در رجیستری؛ پنل مسیر Geneve+IPsec را ارائه می‌کند

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L2`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `geneve, bridge`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1, N:M`.
- دلیل وضعیت در منبع: RFC 8926 compliant Geneve overlay with dynamic VNI and MTU tuning

## `geneve_ipsec` — Geneve + IPsec

Geneve همراه حفاظت IPsec ESP

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Kernel-Tunnels](Kernel-Tunnels.md).
- لایه: `L2`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `ipsec`؛ ماژول/نیازمندی: `geneve, bridge, xfrm_user`.
- MTU پیش‌فرض رجیستری: `1280`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1, N:M`.
- دلیل وضعیت در منبع: Encrypted Geneve tunnels with automatic SA key rotation and policy validation

## `geneve_gre6` — Geneve + GRE6 (Hybrid)

ترکیب لایه‌ای Geneve روی GRE6؛ خارج از منوی ساخت فعلی

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L2`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `geneve, ip6_gre, bridge`.
- MTU پیش‌فرض رجیستری: `1320`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Multi-tier encapsulation testing Path MTU and layered dependency teardown order

## `geneve_gre6_native` — Geneve + GRE6 Native IPv6

ترکیب Geneve/GRE6 روی IPv6 بومی؛ خارج از منوی ساخت فعلی

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L2`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `geneve, ip6_gre, bridge`.
- MTU پیش‌فرض رجیستری: `1376`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Order-aware 2-tier setup and teardown over native IPv6

## `geneve_gre6_ipv4` — Geneve + GRE6 over IPv4 (SIT)

ترکیب SIT/GRE6/Geneve برای حامل IPv4؛ خارج از منوی ساخت فعلی

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L2`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `sit, ip6_gre, geneve, bridge`.
- MTU پیش‌فرض رجیستری: `1358`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: 3-tier encapsulation with full Path MTU cascade and reverse teardown

## `wireguard` — WireGuard

تونل کلیدعمومی WireGuard بر UDP؛ آزمایشی در رجیستری

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Kernel-Tunnels](Kernel-Tunnels.md).
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `wireguard`؛ ماژول/نیازمندی: `wireguard`.
- MTU پیش‌فرض رجیستری: `1280`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1, N:M`.
- دلیل وضعیت در منبع: Cryptokey routing, AllowedIPs, keepalive, and private link peering

## `wireguard_hybrid` — WireGuard + Camouflage (AmneziaWG / UDP2RAW)

گونه ترکیبی WireGuard؛ خارج از منوی ساخت فعلی

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `wireguard`؛ ماژول/نیازمندی: `wireguard`.
- MTU پیش‌فرض رجیستری: `1360`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Tested obfuscation overlay mitigating standard WireGuard handshake fingerprints

## `wireguard_amnezia` — WireGuard + AmneziaWG Obfuscation

گونه Amnezia WireGuard؛ خارج از منوی ساخت فعلی

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `wireguard`؛ ماژول/نیازمندی: `wireguard`.
- MTU پیش‌فرض رجیستری: `1380`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: DPI-resistant WireGuard handshake obfuscation with custom Jc/Jmin/Jmax/S1/S2/H1-H4 parameters

## `wireguard_udp2raw` — WireGuard + udp2raw Fake TCP

WireGuard روی حامل udp2raw؛ خارج از منوی ساخت فعلی

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `wireguard`؛ ماژول/نیازمندی: `wireguard, raw_socket`.
- MTU پیش‌فرض رجیستری: `1360`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: 2-tier stack: raw fake TCP tunnel wrapping WireGuard UDP packets

## `erspan` — ERSPAN + IPsec

حمل فریم آینه‌سازی Ethernet با حفاظت IPsec در رجیستری؛ خارج از منوی ساخت

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L2`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `ipsec`؛ ماژول/نیازمندی: `erspan, xfrm_user`.
- MTU پیش‌فرض رجیستری: `1340`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1`.
- دلیل وضعیت در منبع: Bidirectional forwarding verified with dedicated session ID and ESP security

## `eoip` — EOIP (Ethernet over IP)

Ethernet over IP؛ خارج از منوی ساخت و بدون رمزنگاری داخلی

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L2`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `eoip, bridge`.
- MTU پیش‌فرض رجیستری: `1420`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Userspace/kernel EOIP adapter with tunnel ID and bridge peering

## `l2tp` — L2TP (Layer 2 Tunneling Protocol)

تونل لایه ۲ همراه IPsec؛ خارج از منوی ساخت فعلی

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L2`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `ipsec`؛ ماژول/نیازمندی: `l2tp_core, l2tp_netlink, xfrm_user`.
- MTU پیش‌فرض رجیستری: `1380`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: L2TP over UDP 1701 with tunnel and session pairing

## `isatap` — ISATAP (Intra-Site Automatic Tunnel Addressing)

انتقال IPv6 روی IPv4 با ISATAP؛ خارج از منوی ساخت فعلی

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `sit`.
- MTU پیش‌فرض رجیستری: `1440`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1`.
- دلیل وضعیت در منبع: ISATAP router/client peering with IPv4-embedded IPv6 prefixes

## `tcp` — Standard TCP

تعریف عمومی حامل TCP؛ با امنیت همه پروفایل‌های BackPack یکی نیست

- وضعیت: **تأییدشده در رجیستری**؛ مسیر راهنما: [BackPack](BackPack.md).
- لایه: `L4`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `tcp_bbr`.
- MTU پیش‌فرض رجیستری: `1420`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: سرورهای بدون اختلال پورت با نیاز به کمترین مصرف CPU و تأخیر پایه

## `ws` — WebSocket (Plaintext)

تعریف حامل WebSocket بدون TLS

- وضعیت: **تأییدشده در رجیستری**؛ مسیر راهنما: [Web-and-DNS](Web-and-DNS.md).
- لایه: `L7`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `ماژول اختصاصی ثبت نشده`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: استفاده پشت ریورس‌پروکسی‌ها، وب‌سرورهای داخلی و سناریوهای شبکه محلی

## `wss` — WebSocket + TLS 1.3

تعریف حامل WebSocket روی TLS

- وضعیت: **تأییدشده در رجیستری**؛ مسیر راهنما: [BackPack](BackPack.md).
- لایه: `L7`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `tls`؛ ماژول/نیازمندی: `ماژول اختصاصی ثبت نشده`.
- MTU پیش‌فرض رجیستری: `1380`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: عبور مطمئن از CDN (کلودفلر، آروان) با شبیه‌سازی اثرانگشت مرورگر کروم

## `http` — HTTP/1.1 CONNECT + mTLS

HTTP CONNECT با کانال داده احرازشده؛ به معنی HTTP/2 عمومی نیست

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Web-and-DNS](Web-and-DNS.md).
- لایه: `L7`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `tls`؛ ماژول/نیازمندی: `ماژول اختصاصی ثبت نشده`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: حامل CONNECT با هویت اختصاصی mTLS؛ آزمون TCP/UDP پیش از فعال‌شدن؛ بدون ادعای HTTP/2 یا استتار مرورگر

## `https` — HTTPS CONNECT + mTLS

HTTPS CONNECT با TLS/mTLS؛ به معنی XHTTP یا HTTP/3 نیست

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Web-and-DNS](Web-and-DNS.md).
- لایه: `L7`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `tls`؛ ماژول/نیازمندی: `ماژول اختصاصی ثبت نشده`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: حامل CONNECT با هویت اختصاصی mTLS؛ آزمون TCP/UDP پیش از فعال‌شدن؛ بدون ادعای HTTP/2 یا استتار مرورگر

## `tun` — Linux Kernel L3 TUN

رابط لایه ۳ TUN روی حامل UDP/Noise مدیریت‌شده

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Kernel-Tunnels](Kernel-Tunnels.md).
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `noise`؛ ماژول/نیازمندی: `tun, xt_TCPMSS`.
- MTU پیش‌فرض رجیستری: `1280`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: مسیریابی کامل پکت‌های IP بدون اثر منفی TCP-over-TCP و سربار لایه اپلیکیشن

## `dc6` — Direct Connect IPv6 Carrier

انتخاب حامل IP6GRE، IP6IP6 یا SIT، بدون رمزنگاری داخلی

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Kernel-Tunnels](Kernel-Tunnels.md).
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `ip6_tunnel, ip6_gre, sit, xt_TCPMSS`.
- MTU پیش‌فرض رجیستری: `1280`؛ حداقل رجیستری: `1280`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: لینک خصوصی بدون رمزنگاری؛ GRE6/IP6IP6 روی IPv6 عمومی یا SIT روی IPv4 عمومی؛ نیازمند آزمون مسیر

## `spoof` — Spoof Tunnel Suite

خانواده پردازش بسته آزمایشی؛ انتخاب یک پروفایل مدیریت‌شده لازم است

- وضعیت: **آزمایشی**؛ مسیر راهنما: در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید.
- لایه: `L7`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `tls13`؛ ماژول/نیازمندی: `nfnetlink_queue, iptables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Managed mTLS TCP/UDP, owned NFQUEUE and required wire-effect verification; live acceptance pending

## `fake-sni` — Fake SNI Injection

تزریق ClientHello جعلی با کنترل و شاهد بسته

- وضعیت: **تأییدشده در رجیستری**؛ مسیر راهنما: [Packet-Profiles](Packet-Profiles.md).
- لایه: `L7`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `tls13`؛ ماژول/نیازمندی: `nfnetlink_queue, iptables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Verified Fake SNI injection with managed mTLS TCP/UDP and owned NFQUEUE packet processing

## `split-tls` — TLS Record & TCP MultiSplit

تقسیم رکورد TLS و بی‌نظمی TCP در حامل احرازشده

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Packet-Profiles](Packet-Profiles.md).
- لایه: `L7`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `tls13`؛ ماژول/نیازمندی: `nfnetlink_queue, iptables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Managed mTLS TCP/UDP, owned NFQUEUE and required wire-effect verification; live acceptance pending

## `hop-ttl-injection` — Hop-Count Windowing

بسته جعلی با TTL محدود و برآورد مسیر

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Packet-Profiles](Packet-Profiles.md).
- لایه: `L7`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `tls13`؛ ماژول/نیازمندی: `nfnetlink_queue, iptables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Managed mTLS TCP/UDP, owned NFQUEUE and required wire-effect verification; live acceptance pending

## `tcp-state-desync` — TCP State Desync

تغییر آزمایشی وضعیت TCP با RST/OOB و پذیرش مبتنی بر شواهد

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Packet-Profiles](Packet-Profiles.md).
- لایه: `L7`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `tls13`؛ ماژول/نیازمندی: `nfnetlink_queue, iptables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Managed mTLS TCP/UDP, owned NFQUEUE and required wire-effect verification; live acceptance pending

## `l3-ip-spoof` — L3 Source-IP Spoofing

نام رزروشده/آزمایشی فاقد مسیر عملیاتی پذیرفته‌شده در این نسخه؛ غیرفعال

- وضعیت: **غیرفعال**؛ مسیر راهنما: [Packet-Profiles](Packet-Profiles.md).
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `raw_socket, nftables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: No managed bidirectional runtime and data verification implemented

## `l7-header-mutation` — HTTP/WS Header Mutation

تغییر حروف نام هدر Host روی CONNECT

- وضعیت: **آزمایشی**؛ مسیر راهنما: [Packet-Profiles](Packet-Profiles.md).
- لایه: `L7`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4`.
- رمزنگاری رجیستری: `tls13`؛ ماژول/نیازمندی: `nfnetlink_queue, iptables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: Managed mTLS TCP/UDP, owned NFQUEUE and required wire-effect verification; live acceptance pending

## `udp-raw-spoof` — Raw UDP / QUIC Spoofing

نام رزروشده/آزمایشی فاقد مسیر عملیاتی پذیرفته‌شده در این نسخه؛ غیرفعال

- وضعیت: **غیرفعال**؛ مسیر راهنما: [Packet-Profiles](Packet-Profiles.md).
- لایه: `L4`؛ پروتکل‌های ثبت‌شده: `udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `noise`؛ ماژول/نیازمندی: `raw_socket, nftables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: No managed bidirectional runtime and data verification implemented

## `dns-spoof` — DNS Anti-Poisoning

نام رزروشده/آزمایشی فاقد مسیر عملیاتی پذیرفته‌شده در این نسخه؛ غیرفعال

- وضعیت: **غیرفعال**؛ مسیر راهنما: [Packet-Profiles](Packet-Profiles.md).
- لایه: `L7`؛ پروتکل‌های ثبت‌شده: `udp, tcp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `raw_socket, nftables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: No managed bidirectional runtime and data verification implemented

## `spoof-tcp-syn` — ParsaKSH TCP-SYN Spoof

نام رزروشده/آزمایشی فاقد مسیر عملیاتی پذیرفته‌شده در این نسخه؛ غیرفعال

- وضعیت: **غیرفعال**؛ مسیر راهنما: [Packet-Profiles](Packet-Profiles.md).
- لایه: `L4`؛ پروتکل‌های ثبت‌شده: `tcp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `raw_socket, nftables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: No managed bidirectional runtime and data verification implemented

## `spoof-udp-raw` — ParsaKSH UDP Spoof

نام رزروشده/آزمایشی فاقد مسیر عملیاتی پذیرفته‌شده در این نسخه؛ غیرفعال

- وضعیت: **غیرفعال**؛ مسیر راهنما: [Packet-Profiles](Packet-Profiles.md).
- لایه: `L4`؛ پروتکل‌های ثبت‌شده: `udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `raw_socket, nftables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: No managed bidirectional runtime and data verification implemented

## `spoof-icmp` — ParsaKSH ICMP Spoof

نام رزروشده/آزمایشی فاقد مسیر عملیاتی پذیرفته‌شده در این نسخه؛ غیرفعال

- وضعیت: **غیرفعال**؛ مسیر راهنما: [Packet-Profiles](Packet-Profiles.md).
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `none`؛ ماژول/نیازمندی: `raw_socket, nftables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: No managed bidirectional runtime and data verification implemented

## `qs-dns-hybrid` — QS-Tunnel Hybrid

نام رزروشده/آزمایشی فاقد مسیر عملیاتی پذیرفته‌شده در این نسخه؛ غیرفعال

- وضعیت: **غیرفعال**؛ مسیر راهنما: [Packet-Profiles](Packet-Profiles.md).
- لایه: `L7`؛ پروتکل‌های ثبت‌شده: `udp, tcp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `tls`؛ ماژول/نیازمندی: `raw_socket, nftables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: No managed bidirectional runtime and data verification implemented

## `hyperion-x` — HYPERION-X Tri-Vector

نام رزروشده/آزمایشی فاقد مسیر عملیاتی پذیرفته‌شده در این نسخه؛ غیرفعال

- وضعیت: **غیرفعال**؛ مسیر راهنما: [Packet-Profiles](Packet-Profiles.md).
- لایه: `L3`؛ پروتکل‌های ثبت‌شده: `tcp, udp`؛ خانواده آدرس: `ipv4, ipv6`.
- رمزنگاری رجیستری: `noise`؛ ماژول/نیازمندی: `raw_socket, nftables`.
- MTU پیش‌فرض رجیستری: `1400`؛ حداقل رجیستری: `1200`؛ توپولوژی ثبت‌شده: `1:1, N:1`.
- دلیل وضعیت در منبع: No managed bidirectional runtime and data verification implemented
