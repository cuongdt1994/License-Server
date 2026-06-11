module.exports = {
  apps: [
    {
      name: "license-server",
      script: "server.js",
      cwd: "/var/www/License-Server/license_server",
      instances: 1,
      exec_mode: "fork",
      env: {
        NODE_ENV: "production",

        LICENSE_DATA_DIR: "/var/lib/license-server",

        LICENSE_WEB_USER: "cuongdt",
        LICENSE_WEB_PASS: "chemgiovn@123pP",
        LICENSE_SESSION_SECRET: "DoiChuoiRandomThatDai_64_ky_tu_tro_len"
      }
    }
  ]
};