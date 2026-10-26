#!/usr/bin/env python3
"""Build/check documentation references from public source constants, never inventory."""
import argparse
import ast
import json
from pathlib import Path
import subprocess
import sys
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.capabilities import CAPABILITIES_CATALOG  # noqa: E402

FAMILY_PAGES = {'backpack':'BackPack', 'waterwall':'WaterWall', 'gost':'GOST',
                'frp':'FRP', 'hedioum':'Hedioum', 'rathole':'Rathole', 'paqet':'Paqet',
                'kernel':'Kernel-Tunnels', 'spoof':'Packet-Profiles', 'other':'Web-and-DNS'}


def ui_catalog():
    script = """const fs=require('node:fs'),vm=require('node:vm');
const s=fs.readFileSync(process.argv[1],'utf8');
const a=s.indexOf('const MANAGED_PACKET_TRANSPORTS =');
const b=s.indexOf('const TRANSPORT_TO_ENGINE =',a);
if(a<0||b<0)throw Error('UI catalog boundaries missing');
process.stdout.write(vm.runInNewContext(s.slice(a,b)+';JSON.stringify(ENGINE_TRANSPORTS)'));
"""
    return json.loads(subprocess.check_output(['node','-e',script,str(ROOT/'web/app.js')],text=True))


def profile_key(group, profile):
    return ':'.join([group, profile['value'], profile.get('mode') or profile.get('profile') or 'default'])


class FormFields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = []
        self.labels = {}
        self.label = None
        self.select = None
        self.option = None
        self.textarea = None
        self.section = 'صفحه اصلی'
        self.heading = None
        self.heading_text = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ('h3','h4'):
            self.heading = tag
            self.heading_text = []
        if tag == 'label' and attrs.get('for'):
            self.label = attrs['for']
            self.labels[self.label] = ''
        if tag in ('input','select','textarea') and attrs.get('id'):
            record = {'id':attrs['id'],'tag':tag,'section':self.section,'type':attrs.get('type','text'),
                      'default':attrs.get('value',''),'required':'required' in attrs,
                      'min':attrs.get('min',''),'max':attrs.get('max',''),
                      'placeholder':attrs.get('placeholder',''),'options':[]}
            if record['type'] in ('password','hidden') or any(word in record['id'].lower() for word in ('password','token','secret','knock','key','psk')):
                record['default'] = ''
            self.fields.append(record)
            if tag == 'select': self.select = record
            if tag == 'textarea': self.textarea = record
        if tag == 'option' and self.select is not None:
            self.option = {'value':attrs.get('value',''),'label':'','selected':'selected' in attrs,
                           'disabled':'disabled' in attrs}
            self.select['options'].append(self.option)
            if 'selected' in attrs: self.select['default'] = attrs.get('value','')

    def handle_data(self, text):
        if self.label: self.labels[self.label] += text
        if self.heading: self.heading_text.append(text)
        if self.option is not None: self.option['label'] += text

    def handle_endtag(self, tag):
        if tag == self.heading:
            self.section = ' '.join(''.join(self.heading_text).split())
            self.heading = None
        if tag == 'label': self.label = None
        if tag == 'option': self.option = None
        if tag == 'select': self.select = None
        if tag == 'textarea': self.textarea = None


def cell(value):
    return str(value).replace('|', '\\|').replace('\n',' ').strip()


def source_dict(filename, name):
    for statement in ast.parse((ROOT/filename).read_text()).body:
        if isinstance(statement,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in statement.targets):
            return ast.literal_eval(statement.value)
    raise ValueError(f'Missing constant {name}')


def render(catalog):
    aliases = {'gre':'gre_ipv4'}
    by_id = {}
    for group, family in catalog.items():
        for profile in family['transports']:
            by_id.setdefault(aliases.get(profile['value'],profile['value']),[]).append(FAMILY_PAGES[group])
    translations = {
      'backpack':'موتور چندحاملی BackPack؛ امنیت هر حالت جدا بررسی شود',
      'waterwall':'زنجیره‌های پروتکلی WaterWall با پنج حالت پنل',
      'trusttunnel':'آداپتور endpoint/client با TUN یا SOCKS5 و مدیریت گواهی؛ در منوی ساخت فعلی نیست',
      'backhaul':'آداپتور حامل‌های TCP/TCPMUX/WS/WSS/UDP؛ در منوی ساخت فعلی نیست',
      'hysteria2':'آداپتور QUIC با کنترل ازدحام و port hopping؛ در منوی ساخت فعلی نیست',
      'frp':'پراکسی معکوس FRP؛ سه حالت فوروارد در پنل',
      'hedioum':'حالت‌های SOCKS5، TUN و gateway با Persona قابل انتخاب',
      'rathole':'پراکسی معکوس با حامل TCP، TLS، Noise یا WebSocket',
      'paqet':'انتقال پورت با KCP روی بسته خام و تنظیم interface/MAC',
      'gost':'زنجیره‌های پراکسی و سیزده پروفایل اختصاصی پنل',
      'slipstream':'حامل DNS آزمایشی بر زیردامنه واگذارشده و رله امن',
      'gre_ipv4':'GRE روی IPv4 با IPsec اجباری در مسیر مدیریت‌شده',
      'ip6ip6':'کپسوله‌سازی IPv6 در IPv6 بدون رمزنگاری داخلی',
      'gre6':'GRE بر بستر IPv6 بدون رمزنگاری داخلی',
      'gretap':'پل اترنت لایه ۲ روی GRE/IPv4؛ گزینه توسعه خارج از منوی ساخت',
      'gre6tap':'پل اترنت لایه ۲ روی GRE/IPv6؛ خارج از منوی ساخت',
      'gre6tap_ipsec':'پل GRE6TAP به‌همراه IPsec؛ خارج از منوی ساخت',
      'sit':'حمل IPv6 روی IPv4؛ در پنل از انتخاب carrier در DC6 استفاده می‌شود',
      '6to4_unicast':'6to4 با مقصد مشخص؛ خارج از منوی ساخت فعلی',
      '6to4_anycast':'6to4 anycast قدیمی؛ غیرفعال و قابل توصیه برای استقرار نیست',
      'anycast':'مفهوم مسیریابی Anycast؛ موتور تونل عملیاتی این نسخه نیست',
      'vxlan':'overlay لایه ۲ روی UDP، بدون رمزنگاری یا احراز هویت داخلی',
      'vxlan_ipsec':'VXLAN حفاظت‌شده با IPsec ESP و کنترل عبور خام',
      'geneve':'overlay خام Geneve در رجیستری؛ پنل مسیر Geneve+IPsec را ارائه می‌کند',
      'geneve_ipsec':'Geneve همراه حفاظت IPsec ESP',
      'geneve_gre6':'ترکیب لایه‌ای Geneve روی GRE6؛ خارج از منوی ساخت فعلی',
      'geneve_gre6_native':'ترکیب Geneve/GRE6 روی IPv6 بومی؛ خارج از منوی ساخت فعلی',
      'geneve_gre6_ipv4':'ترکیب SIT/GRE6/Geneve برای حامل IPv4؛ خارج از منوی ساخت فعلی',
      'wireguard':'تونل کلیدعمومی WireGuard بر UDP؛ آزمایشی در رجیستری',
      'wireguard_hybrid':'گونه ترکیبی WireGuard؛ خارج از منوی ساخت فعلی',
      'wireguard_amnezia':'گونه Amnezia WireGuard؛ خارج از منوی ساخت فعلی',
      'wireguard_udp2raw':'WireGuard روی حامل udp2raw؛ خارج از منوی ساخت فعلی',
      'erspan':'حمل فریم آینه‌سازی Ethernet با حفاظت IPsec در رجیستری؛ خارج از منوی ساخت',
      'eoip':'Ethernet over IP؛ خارج از منوی ساخت و بدون رمزنگاری داخلی',
      'l2tp':'تونل لایه ۲ همراه IPsec؛ خارج از منوی ساخت فعلی',
      'isatap':'انتقال IPv6 روی IPv4 با ISATAP؛ خارج از منوی ساخت فعلی',
      'tcp':'تعریف عمومی حامل TCP؛ با امنیت همه پروفایل‌های BackPack یکی نیست',
      'ws':'تعریف حامل WebSocket بدون TLS', 'wss':'تعریف حامل WebSocket روی TLS',
      'http':'HTTP CONNECT با کانال داده احرازشده؛ به معنی HTTP/2 عمومی نیست',
      'https':'HTTPS CONNECT با TLS/mTLS؛ به معنی XHTTP یا HTTP/3 نیست',
      'tun':'رابط لایه ۳ TUN روی حامل UDP/Noise مدیریت‌شده',
      'dc6':'انتخاب حامل IP6GRE، IP6IP6 یا SIT، بدون رمزنگاری داخلی',
      'spoof':'خانواده پردازش بسته آزمایشی؛ انتخاب یک پروفایل مدیریت‌شده لازم است',
      'fake-sni':'تزریق ClientHello جعلی با کنترل و شاهد بسته',
      'split-tls':'تقسیم رکورد TLS و بی‌نظمی TCP در حامل احرازشده',
      'hop-ttl-injection':'بسته جعلی با TTL محدود و برآورد مسیر',
      'tcp-state-desync':'تغییر آزمایشی وضعیت TCP با RST/OOB و پذیرش مبتنی بر شواهد',
      'l7-header-mutation':'تغییر حروف نام هدر Host روی CONNECT',
    }
    disabled = {'l3-ip-spoof','udp-raw-spoof','dns-spoof','spoof-tcp-syn','spoof-udp-raw','spoof-icmp','qs-dns-hybrid','hyperion-x'}
    for identifier in disabled: translations[identifier] = 'نام رزروشده/آزمایشی فاقد مسیر عملیاتی پذیرفته‌شده در این نسخه؛ غیرفعال'
    statuses = {'verified':'تأییدشده در رجیستری','experimental':'آزمایشی','unsupported':'غیرفعال'}
    lines = ['# مرجع کامل قابلیت‌ها و تفاوت رجیستری با پنل','',
      'این صفحه از `core/capabilities.py` و کاتالوگ واقعی `web/app.js` تولید می‌شود. عدد MTU این جدول مقدار رجیستری است؛ مقدار پیش‌فرض و محدودیت **فرم استقرار** را از [مرجع فیلدها](Field-Reference.md) بخوانید. امنیت ثبت‌شده برای یک خانواده الزاماً امنیت همهٔ پروفایل‌های آن نیست. نام در رجیستری، ثبت آداپتور، امکان ساخت در پنل و آزمون واقعی چهار موضوع جدا هستند.','',
      'آداپتورهای توسعه مثل TrustTunnel، Backhaul و Hysteria2 ممکن است کانفیگ تولید کنند ولی probe/modify/rollback زندهٔ تأییدشده نداشته باشند. برای آن‌ها فرمان نصب یا پشتیبانی پنل اختراع نشده است. گزینه‌های لایه‌ای و قدیمی نیز صرفاً با وجود کلاس Python، آمادهٔ استقرار عمومی محسوب نمی‌شوند.','',
      'کاتالوگ `transports_13.py` در این نسخه فقط هفت شناسهٔ `tcp, ws, wss, http, https, tun, dc6` دارد. XHTTP، XHTTPS و NOVA گزینهٔ فعال فرم فعلی نیستند؛ توضیح قدیمی یک فایل، مدرک فعال‌بودن آن‌ها نیست.','']
    for identifier, cap in CAPABILITIES_CATALOG.items():
        if identifier not in translations: raise ValueError('Missing Persian explanation: '+identifier)
        links = ', '.join(f'[{page}]({page}.md)' for page in sorted(set(by_id.get(identifier,[])))) or 'در منوی مستقل ساخت فعلی نیست؛ توضیح بالا را بخوانید'
        lines += [f'## `{identifier}` — {cap.display_name}', '', translations[identifier], '',
          f'- وضعیت: **{statuses[cap.support_status]}**؛ مسیر راهنما: {links}.',
          f'- لایه: `{cap.layer}`؛ پروتکل‌های ثبت‌شده: `{", ".join(cap.supported_protocols)}`؛ خانواده آدرس: `{", ".join(cap.address_families)}`.',
          f'- رمزنگاری رجیستری: `{cap.encryption_type}`؛ ماژول/نیازمندی: `{", ".join(cap.kernel_requirements) or "ماژول اختصاصی ثبت نشده"}`.',
          f'- MTU پیش‌فرض رجیستری: `{cap.default_mtu}`؛ حداقل رجیستری: `{cap.min_mtu}`؛ توپولوژی ثبت‌شده: `{", ".join(cap.supported_topologies)}`.',
          f'- دلیل وضعیت در منبع: {cap.status_reason}', '']
    parser = FormFields()
    parser.feed((ROOT/'web/index.html').read_text())
    fields = [f for f in parser.fields if f['type'] != 'hidden']
    f_lines = ['# مرجع فیلدهای پنل','',
      'این صفحه مستقیماً از HTML فرم‌ها تولید می‌شود. مقدارها، پیش‌فرض **رابط** هستند و ممکن است منطق JavaScript یا تخصیص خودکار در اجرا آن‌ها را تغییر دهد. required/disabled و نمایش فیلدهای وابسته نیز پویاست؛ جدول، اجازهٔ تحمیل گزینهٔ نامعتبر به API نیست. گزینه‌های غیرفعال و placeholderهای قدیمی، قابلیت عملیاتی ایجاد نمی‌کنند. رمزها و دادهٔ inventory در تولید این مرجع خوانده نمی‌شوند.','',
      'برای معنی فیلدهای هر موتور به صفحهٔ آن و برای فیلدهای قدیمی پردازش بسته به [گزینه‌های غیرفعال](Packet-Profiles.md) رجوع کنید. اعداد MTU واقعی فرم ممکن است با default رجیستری تفاوت داشته باشند.','']
    section = None
    for f in fields:
        if f['section'] != section:
            section=f['section']; f_lines += [f'## {section}', '', '| فیلد / شناسه | نوع و پیش‌فرض فرم | محدودیت / گزینه‌ها |','| --- | --- | --- |']
        label = ' '.join(parser.labels.get(f['id'],f['id']).split())
        default = f['default'] if f['type'] != 'password' else 'محرمانه؛ در راهنما ثبت نمی‌شود'
        bounds = '، '.join(x for x in [f"حداقل {f['min']}" if f['min'] else '',f"حداکثر {f['max']}" if f['max'] else ''] if x)
        choices = '؛ '.join(f"`{o['value']}`: {cell(o['label'])}"+(' (غیرفعال)' if o['disabled'] else '') for o in f['options'])
        f_lines.append(f"| {cell(label)} · `{f['id']}` | `{f['type'] if f['tag']=='input' else f['tag']}`؛ {cell(default) or 'خالی/پویا'} | {cell(bounds)} {choices} |")
    manifest = {'ui_groups':catalog, 'capability_ids':sorted(CAPABILITIES_CATALOG), 'field_ids':[f['id'] for f in fields],
                'family_pages':FAMILY_PAGES}
    return {'Capability-Reference.md':'\n'.join(lines).rstrip()+'\n', 'Field-Reference.md':'\n'.join(f_lines).rstrip()+'\n',
            'catalog.json':json.dumps(manifest,ensure_ascii=False,indent=2)+'\n'}


def check_coverage(catalog):
    errors=[]
    for group,family in catalog.items():
        file=ROOT/'docs/wiki'/f'{FAMILY_PAGES[group]}.md'
        text=file.read_text() if file.exists() else ''
        for profile in family['transports']:
            marker=f'<!-- profile:{profile_key(group,profile)} -->'
            if marker not in text: errors.append(f'Undocumented profile {profile_key(group,profile)}')
    # Nested modes are not separate engine dropdown entries, but still need prose.
    constants = [
        ('core/gost_engine.py', 'PROFILES', 'GOST'),
        ('core/paqet_engine.py', 'KCP_MODES', 'Paqet'),
        ('core/hedioum_engine.py', 'MODES', 'Hedioum'),
        ('core/hedioum_engine.py', 'PERSONAS', 'Hedioum'),
        ('core/frp_engine.py', 'MODES', 'FRP'),
        ('core/rathole_engine.py', 'TRANSPORTS', 'Rathole'),
        ('core/rathole_engine.py', 'SERVICE_PROTOCOLS', 'Rathole'),
        ('core/waterwall_modes.py', 'MODES', 'WaterWall'),
    ]
    for filename, constant, page in constants:
        text = (ROOT/'docs/wiki'/f'{page}.md').read_text()
        for value in source_dict(filename, constant):
            if f'`{value}`' not in text:
                errors.append(f'Undocumented {constant} value {value} in {page}')
    fields = FormFields()
    fields.feed((ROOT/'web/index.html').read_text())
    kernel = (ROOT/'docs/wiki/Kernel-Tunnels.md').read_text()
    for field in fields.fields:
        if field['id'] in ('new-pool-vxlan-method', 'new-pool-dc6-carrier'):
            for option in field['options']:
                if f"`{option['value']}`" not in kernel:
                    errors.append(f"Undocumented nested kernel option {option['value']}")
    if errors: raise ValueError('\n'.join(errors))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    catalog=ui_catalog()
    generated=render(catalog)
    for filename,content in generated.items():
        target=ROOT/'docs/wiki'/filename
        if args.check:
            if not target.exists() or target.read_text()!=content: raise ValueError('Outdated reference: '+filename)
        else: target.write_text(content)
    check_coverage(catalog)
    print(f"Documentation covers {sum(len(f['transports']) for f in catalog.values())} UI profile entries, {len(CAPABILITIES_CATALOG)} capability entries")

if __name__=='__main__': main()
