# Chạy License Server với PM2 (TLS-only + SQLite)

## Cài đặt lần đầu

Chạy các lệnh trong thư mục `license_server`:

```powershell
npm install
$env:LICENSE_SESSION_SECRET="chuoi-bi-mat-it-nhat-48-ky-tu-rat-dai-va-ngau-nhien"
$env:LICENSE_TCP_SECRET="hex:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
$env:LICENSE_WEB_USER="admin"
$env:LICENSE_WEB_PASS="mat-khau-manh-it-nhat-10-ky-tu"
$env:LICENSE_TLS_KEY_FILE="C:\certs\license-server.key"
$env:LICENSE_TLS_CERT_FILE="C:\certs\license-server.crt"
npm run pm2:start
npm run pm2:save
```

`ecosystem.config.js` mặc định dùng:

- Web UI: `WEB_PORT=5000`
- TLS license: `TCP_PORT=27015` (TLS trên cùng port, raw TCP đã bị loại bỏ)
- Bind host: `LICENSE_BIND_HOST=0.0.0.0`
- Session cookie HTTPS flag: `LICENSE_COOKIE_SECURE=0`
- Data riêng ngoài source: `../runtime/license-server-data`
- Log PM2: `../runtime/logs`

## Yêu cầu bắt buộc

- **LICENSE_SESSION_SECRET**: phải có ít nhất **48 byte** UTF-8. Bắt buộc phải set qua env.
- **LICENSE_TLS_KEY_FILE / LICENSE_TLS_CERT_FILE**: File TLS key và certificate. Bắt buộc.
- **LICENSE_TLS_CA_FILE**: (tùy chọn) CA certificate cho mTLS.
- **LICENSE_TCP_SECRET**: (tùy chọn) 32 byte hoặc 64 hex chars. Nếu không set, server dùng embedded key đồng bộ với client.

## Lệnh vận hành

```powershell
npm run pm2:restart
npm run pm2:logs
npm run pm2:stop
```

Sau khi đổi env, dùng:

```powershell
npm run pm2:restart
```

Lệnh này gọi `pm2 reload ecosystem.config.js --update-env` để PM2 đọc lại biến mới.

## Kiểm tra sức khỏe

Mở:

```text
http://127.0.0.1:5000/health
```

JSON trả về có `transport.tls_listening`, `transport.tls_port`, `transport.certificate_valid_to`, `database.driver`, `database.ok`.

## Ghi chú production

- TLS certificate là bắt buộc. Raw TCP trên port 27015 đã bị loại bỏ hoàn toàn.
- `LICENSE_SESSION_SECRET` bắt buộc set qua env (≥48 byte). Không còn tự sinh secret.
- Nếu đổi `LICENSE_TCP_SECRET`, phải đồng bộ secret này với client license.
- Không đặt `LICENSE_DATA_DIR` trong thư mục source nếu deploy bằng copy/rebuild.
- Nếu dùng firewall, mở cả port web và TLS license (mặc định 27015).
- Nếu Web UI chạy sau HTTPS reverse proxy, đặt `LICENSE_COOKIE_SECURE=1`.
- Sau khi server boot ổn định, chạy `npm run pm2:save` để PM2 phục hồi sau reboot.
- Backup SQLite được tự động tạo hàng ngày lúc 3:00 AM, giữ tối đa 30 bản.
- Để reload TLS certificate không cần restart: gửi signal `SIGHUP` tới process (`pm2 reload` hoặc `kill -HUP <pid>`).
