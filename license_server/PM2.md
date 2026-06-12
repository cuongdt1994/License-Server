# Chay License Server voi PM2

## Cai dat lan dau

Chay cac lenh trong thu muc `license_server`:

```powershell
npm install
$env:LICENSE_SESSION_SECRET="doi-chuoi-bi-mat-dai-it-nhat-32-ky-tu"
$env:LICENSE_TCP_SECRET="12345678901234567890123456789012"
$env:LICENSE_WEB_USER="admin"
$env:LICENSE_WEB_PASS="doi-mat-khau-manh"
npm run pm2:start
npm run pm2:save
```

`ecosystem.config.js` mac dinh dung:

- Web UI: `WEB_PORT=5000`
- TCP license: `TCP_PORT=27015`
- Bind host: `LICENSE_BIND_HOST=0.0.0.0`
- Session cookie HTTPS flag: `LICENSE_COOKIE_SECURE=0`
- TCP encryption secret: `LICENSE_TCP_SECRET` phai dung 32 byte UTF-8
- Data rieng ngoai source: `../runtime/license-server-data`
- Log PM2: `../runtime/logs`

## Lenh van hanh

```powershell
npm run pm2:restart
npm run pm2:logs
npm run pm2:stop
```

Sau khi doi env, dung:

```powershell
npm run pm2:restart
```

Lenh nay goi `pm2 reload ecosystem.config.js --update-env` de PM2 doc lai bien moi.

## Kiem tra suc khoe

Mo:

```text
http://127.0.0.1:5000/health
```

JSON tra ve co `runtime.web_port`, `runtime.tcp_port`, `runtime.data_dir`, `runtime.pm2` va `runtime.warnings`.
Neu `runtime.warnings` bao thieu `LICENSE_SESSION_SECRET`, hay dat secret co it nhat 32 ky tu de session khong bi mat sau restart.

## Ghi chu production

- Nen dat `LICENSE_SESSION_SECRET`, `LICENSE_WEB_USER`, `LICENSE_WEB_PASS` bang bien moi truong that cua may chu.
- Nen dat `LICENSE_TCP_SECRET` rieng cho production va dong bo secret nay voi client license.
- Khong dat `LICENSE_DATA_DIR` trong thu muc source neu deploy bang copy/rebuild.
- Neu dung firewall, mo ca port web va TCP license.
- Neu Web UI chay sau HTTPS reverse proxy, dat `LICENSE_COOKIE_SECURE=1`.
- Sau khi server boot on dinh, chay `npm run pm2:save` de PM2 phuc hoi sau reboot.
