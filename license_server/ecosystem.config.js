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
        LICENSE_SESSION_SECRET: "9f4f305143fe63935dc35d2c2fb6f56add030216dfb8a63ee208fe50874b5b7a"
      }
    }
  ]
};