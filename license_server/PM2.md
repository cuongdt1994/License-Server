# Chạy License Server với PM2 (TLS-only + SQLite)

## Cài đặt lần đầu

Chạy các lệnh trong thư mục `license_server`:

```bash
npm install

# Chỉ 2 thứ bắt buộc: TLS cert + admin tài khoản lần đầu
export LICENSE_TLS_KEY_FILE="/var/www/License-Server/certs/license-server.key"
export LICENSE_TLS_CERT_FILE="/var/www/License-Server/certs/license-server.crt"
export LICENSE_WEB_USER="admin"
export LICENSE_WEB_PASS="mat-khau-manh-it-nhat-10-ky-tu"

# Session secret sẽ tự sinh + lưu SQLite nếu không set
# Muốn tự set thì export LICENSE_SESSION_SECRET="chuoi-48-ky-tu..."

npm run pm2:start
npm run pm2:save
```

## Tự động

| Cấu hình | Cần set env? | Ghi chú |
|---|---|---|
| `LICENSE_TLS_KEY_FILE` | **Có** | TLS certificate key |
| `LICENSE_TLS_CERT_FILE` | **Có** | TLS certificate |
| `LICENSE_WEB_USER` / `LICENSE_WEB_PASS` | Chỉ lần đầu | Sau setup lưu vào SQLite, lần sau không cần |
| `LICENSE_SESSION_SECRET` | Không | Tự sinh + lưu SQLite. Chỉ set env nếu muốn override |
| `LICENSE_TCP_SECRET` | Không | Mặc định dùng embedded key (tương thích client) |

## Lệnh vận hành

```bash
npm run pm2:restart   # reload env + code mới
npm run pm2:logs      # xem log
npm run pm2:stop      # dừng
npm run pm2:save      # lưu process list để auto-restore sau reboot
```

## Kiểm tra sức khỏe

```
http://127.0.0.1:5000/health
```

JSON: `transport.tls_listening`, `transport.certificate_valid_to`, `database.driver`, `database.ok`.

## Ghi chú production

- TLS certificate là bắt buộc. Raw TCP trên port 27015 đã bị loại bỏ.
- Session secret tự động sinh + lưu SQLite. Không lo mất session sau restart.
- Admin credentials lưu SQLite sau lần setup đầu. Có thể đổi mật khẩu trong Settings.
- Backup SQLite tự động hàng ngày lúc 3:00 AM, giữ tối đa 30 bản.
- Reload TLS certificate không cần restart: `pm2 reload license-server` hoặc `kill -HUP <pid>`.
- Nếu Web UI chạy sau HTTPS reverse proxy, đặt `LICENSE_COOKIE_SECURE=1`.
- Không đặt `LICENSE_DATA_DIR` trong thư mục source.
