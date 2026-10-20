/* Authored copy for the redesigned shell and data states. Domain data stays separate. */
window.panelCopy = {
  shell: {
    storyTitle: 'تمام مسیرها.', storyAccent: 'یک نقطهٔ کنترل.',
    storyHint: 'از نودهای ایران تا سرور مقصد؛ شبکه را یک‌جا مدیریت کنید.',
    welcome: 'به اتاق کنترل خوش آمدید', welcomeHint: 'برای مدیریت شبکه، وارد پنل VX LB شوید.',
    domain: 'دامنه‌های اتصال استخرها', health: 'سلامت نودها', healthy: 'نود سالم',
    healthyLegend: 'سالم', pendingLegend: 'آماده / آزمایشی', issueLegend: 'اختلال',
    statusError: 'دریافت وضعیت ناموفق بود. اطلاعات نمایش‌داده‌شده ممکن است قدیمی باشد.',
    retry: 'تلاش دوباره'
  },
  routes: {global: 'پیش‌فرض عمومی', missing: 'دامنه تنظیم نشده', enabled: 'فیل‌اور فعال', disabled: 'فیل‌اور غیرفعال', copy: 'کپی دامنه', none: 'دامنه‌ای ثبت نشده؛ DNS را از تنظیمات استخر پیکربندی کنید.'},
  kickers: {pools: 'NETWORK OVERVIEW', servers: 'SERVER INVENTORY', watchdog: 'WATCHDOG MONITOR', settings: 'PANEL SETTINGS', cloudflare: 'CLOUDFLARE MANAGER'},
  pages: {
    pools: ['نمای کلی شبکه', 'وضعیت مسیرها، سرورها و استخرهای شما در یک نگاه.'],
    servers: ['سرورهای شما', 'سرورهای ورودی ایران و مقصدهای خارج را مدیریت کنید.'],
    watchdog: ['پایش و فیل‌اور', 'سلامت مسیرها، وضعیت DNS و رخدادهای شبکه را دنبال کنید.'],
    settings: ['تنظیمات پنل', 'امنیت حساب و پیش‌فرض‌های اتصال Cloudflare را تنظیم کنید.'],
    cloudflare: ['مدیریت Cloudflare', 'توکن‌ها، Zoneها و رکوردهای DNS را در یک نقطه کنترل کنید.']
  },
  connected: 'متصل · به‌روزرسانی خودکار',
  disconnected: 'ارتباط با سرور قطع شده',
  noPools: 'شبکه از اینجا شروع می‌شود',
  noPoolsHint: 'ابتدا سرورها را ثبت کنید، سپس اولین استخر را بسازید.',
  createPool: 'ساخت اولین استخر',
  noServers: 'هنوز سروری در این بخش نیست',
  noServersHint: 'یک سرور اضافه کنید یا فیلتر دیگری را انتخاب کنید.',
  addServer: 'افزودن سرور',
  unchecked: 'در انتظار پایش',
  noNodes: 'نودی برای پایش ثبت نشده',
  stable: 'نودهای پایش‌شده سالم‌اند',
  issue: 'برخی نودها دچار اختلال‌اند',
  waiting: 'برخی نودها در انتظار تأییدند',
  dnsReady: 'فیل‌اور DNS پیکربندی شده',
  dnsMissing: 'DNS هنوز پیکربندی نشده',
  loading: 'در حال دریافت اطلاعات',
  loadFailed: 'دریافت اطلاعات ناموفق بود',
  retry: 'تلاش دوباره',
  translateReason: function(text) {
    if (!text) return 'در حال بررسی سلامت';
    let s = String(text).trim();
    if (s === 'Awaiting checks' || s === 'در حال بررسی') return 'در انتظار پایش';
    if (s === 'force-cleared by operator') return 'پاکسازی دستی توسط مدیر';
    if (s.startsWith('SSH unreachable')) {
      return s.replace('SSH unreachable; current health cannot be verified', 'عدم دسترسی به SSH؛ امکان سنجش سلامت نود وجود ندارد');
    }
    if (s.startsWith('Tunnel control channel is disconnected')) {
      return 'کانال کنترلی تونل قطع است؛ فعال بودن سرویس به معنای عبور ترافیک نیست';
    }
    if (s.startsWith('Telemetry window unavailable')) {
      return 'داده‌های تله‌متری در دسترس نیست؛ وضعیت فیلترینگ نامشخص است';
    }
    if (s.startsWith('Probationary recovery trial')) {
      return 'آزمایش دوره‌ای بازیابی سلامت (پایان زمان انتظار 15 دقیقه؛ در حال بررسی عبور ترافیک)';
    }
    if (s.startsWith('Retaining filtered state')) {
      return s.replace('Retaining filtered state (cooldown remaining:', 'تداوم وضعیت فیلتر (زمان باقی‌مانده تا تست مجدد:')
              .replace('s)', ' ثانیه)');
    }
    if (s.startsWith('Previous health expired: no fresh bidirectional flow evidence; current health unverified')) {
      return 'انقضای وضعیت سلامت قبلی: عدم ثبت ترافیک دوطرفه جدید؛ نیازمند اتصال کاربر';
    }
    if (s.startsWith('No recent traffic across pool ports')) {
      return s.replace('No recent traffic across pool ports', 'بدون ترافیک اخیر در پورت‌های استخر')
              .replace('(Awaiting connections)', '(در انتظار اتصال کاربر)');
    }
    if (s.startsWith('Verified healthy on port(s)')) {
      return s.replace('Verified healthy on port(s)', 'پایش موفق در پورت(های)')
              .replace('(Port(s)', '(پورت‌های')
              .replace('idle/monitoring)', 'در حال پایش/آماده‌به‌کار)')
              .replace('idle)', 'بدون ترافیک)');
    }
    if (s.startsWith('Partial impairment on port(s)')) {
      return s.replace('Partial impairment on port(s)', 'اختلال جزئی در پورت(های)')
              .replace('; whole-node filtering unverified', '؛ اختلال کل نود تأیید نشده');
    }
    if (s.startsWith('Partial or unconfirmed impairment on port(s)')) {
      return s.replace('Partial or unconfirmed impairment on port(s)', 'اختلال جزئی یا مشکوک در پورت(های)')
              .replace('; whole-node filtering unverified', '؛ اختلال کل نود تأیید نشده');
    }
    if (s.startsWith('Fresh bidirectional flow')) {
      return s.replace('Fresh bidirectional flow', 'تبادل فعال دوطرفه')
              .replace('session(s)', 'اتصال')
              .replace('significant stalls', 'قطعی معنادار')
              .replace('isolated client disconnect(s)', 'قطعی موردی کاربر')
              .replace('client(s) stalled', 'کاربر با کندی یا قطعی');
    }
    if (s.startsWith('Suspected transport stalls:')) {
      return s.replace('Suspected transport stalls:', 'احتمال توقف ترانسپورت:')
              .replace('unique connection(s)', 'اتصال مجزا')
              .replace('independent client(s)', 'کاربر مستقل')
              .replace('confirmation', 'تأیید');
    }
    if (s.startsWith('Transport impairment confirmed across')) {
      return s.replace('Transport impairment confirmed across', 'اختلال انتقال تأییدشده در')
              .replace('independent clients and', 'کاربر مستقل و')
              .replace('checks; cause unverified', 'بررسی متوالی؛ علت نامشخص');
    }
    if (s.startsWith('No fresh bidirectional flow or failure evidence; health unverified')) {
      return 'بدون ترافیک دوطرفه جدید؛ نیازمند اتصال کاربر برای تأیید سلامت';
    }
    if (s.startsWith('Impaired on port(s)')) {
      return s.replace('Impaired on port(s)', 'اختلال در پورت(های)');
    }
    return s;
  }
};
