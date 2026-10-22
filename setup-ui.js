export function renderSetupPage() {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>راه‌اندازی خودکار EchoSec</title>
  <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0f172a;
      --card: #1e293b;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --success: #10b981;
      --danger: #ef4444;
      --border: #334155;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Vazirmatn', sans-serif; }
    body {
      background-color: var(--bg);
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 2rem;
    }
    .container {
      background-color: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 2.5rem;
      width: 100%;
      max-width: 600px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
    }
    .header { text-align: center; margin-bottom: 2rem; }
    .header h1 { font-size: 1.8rem; color: var(--text); margin-bottom: 0.5rem; }
    .header p { color: var(--text-muted); font-size: 0.95rem; }
    .form-group { margin-bottom: 1.5rem; }
    .form-group label {
      display: block;
      margin-bottom: 0.5rem;
      color: var(--text);
      font-weight: 500;
      font-size: 0.95rem;
    }
    .form-group input {
      width: 100%;
      padding: 0.8rem 1rem;
      background-color: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text);
      font-size: 1rem;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .form-group input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
    }
    .form-group small {
      display: block;
      margin-top: 0.4rem;
      color: var(--text-muted);
      font-size: 0.8rem;
    }
    .btn {
      width: 100%;
      padding: 1rem;
      background-color: var(--primary);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 1.1rem;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.2s;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
    }
    .btn:hover { background-color: var(--primary-hover); }
    .btn:disabled { background-color: var(--border); cursor: not-allowed; }
    .alert {
      padding: 1rem;
      border-radius: 8px;
      margin-bottom: 1.5rem;
      font-size: 0.95rem;
      display: none;
    }
    .alert-error { background-color: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
    .alert-success { background-color: rgba(16, 185, 129, 0.1); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
    .spinner {
      display: none;
      width: 20px;
      height: 20px;
      border: 3px solid rgba(255,255,255,0.3);
      border-radius: 50%;
      border-top-color: white;
      animation: spin 1s ease-in-out infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .log-box {
      margin-top: 1.5rem;
      background-color: #000;
      border-radius: 8px;
      padding: 1rem;
      font-family: monospace;
      font-size: 0.85rem;
      color: #a78bfa;
      max-height: 200px;
      overflow-y: auto;
      display: none;
      direction: ltr;
      text-align: left;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🚀 راه‌اندازی خودکار EchoSec</h1>
      <p>اطلاعات زیر را وارد کنید تا ربات، دیتابیس و تنظیمات ساخته شوند.</p>
    </div>

    <div id="alertBox" class="alert"></div>

    <form id="setupForm">
      <div class="form-group">
        <label>Cloudflare Account ID</label>
        <input type="text" id="accountId" required placeholder="مثلاً: 1234567890abcdef" dir="ltr">
        <small>در داشبورد کلودفلر، در بخش Overview حساب خود پیدا کنید.</small>
      </div>

      <div class="form-group">
        <label>Cloudflare API Token</label>
        <input type="password" id="cfToken" required placeholder="توکن API کلودفلر" dir="ltr">
        <small>توکنی با دسترسی‌های Edit Workers, Edit D1, Edit KV بسازید.</small>
      </div>

      <div class="form-group">
        <label>Telegram Bot Token</label>
        <input type="password" id="botToken" required placeholder="مثلاً: 8934970819:AAFjZlz..." dir="ltr">
        <small>توکن ربات خود را از BotFather دریافت کنید.</small>
      </div>

      <div class="form-group">
        <label>Bot Username (بدون @)</label>
        <input type="text" id="botUsername" required placeholder="EchoSecBot" dir="ltr">
        <small>نام کاربری ربات شما در تلگرام.</small>
      </div>

      <div class="form-group">
        <label>GitHub Repository Raw URL</label>
        <input type="url" id="repoUrl" required placeholder="https://raw.githubusercontent.com/username/repo/main/" dir="ltr">
        <small>آدرس Base ریپازیتوری خود که فایل‌های worker.js و... در آن قرار دارند.</small>
      </div>

      <div class="form-group">
        <label>Admin Password</label>
        <input type="password" id="adminPass" required placeholder="رمز عبور دلخواه برای پنل مدیریت" dir="ltr">
      </div>

      <button type="submit" class="btn" id="submitBtn">
        <span id="btnText">شروع نصب جادویی</span>
        <div class="spinner" id="spinner"></div>
      </button>
    </form>

    <div class="log-box" id="logBox"></div>
  </div>

  <script>
    const form = document.getElementById('setupForm');
    const submitBtn = document.getElementById('submitBtn');
    const spinner = document.getElementById('spinner');
    const btnText = document.getElementById('btnText');
    const alertBox = document.getElementById('alertBox');
    const logBox = document.getElementById('logBox');

    function showAlert(message, type) {
      alertBox.style.display = 'block';
      alertBox.className = 'alert alert-' + type;
      alertBox.innerHTML = message;
    }

    function addLog(message) {
      logBox.style.display = 'block';
      logBox.innerHTML += '> ' + message + '\\n';
      logBox.scrollTop = logBox.scrollHeight;
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      alertBox.style.display = 'none';
      logBox.innerHTML = '';
      logBox.style.display = 'none';
      submitBtn.disabled = true;
      spinner.style.display = 'block';
      btnText.textContent = 'در حال انجام عملیات...';

      const data = {
        accountId: document.getElementById('accountId').value.trim(),
        cfToken: document.getElementById('cfToken').value.trim(),
        botToken: document.getElementById('botToken').value.trim(),
        botUsername: document.getElementById('botUsername').value.trim(),
        repoUrl: document.getElementById('repoUrl').value.trim(),
        adminPassword: document.getElementById('adminPass').value
      };

      try {
        addLog('Sending request to setup worker...');
        const response = await fetch('/api/setup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });

        const result = await response.json();

        if (result.success) {
          addLog('Setup completed successfully!');
          showAlert('🎉 راه‌اندازی با موفقیت انجام شد!<br><br>آدرس پنل مدیریت شما:<br><a href="' + result.dashboardUrl + '" target="_blank" style="color:#10b981; font-weight:bold;">' + result.dashboardUrl + '</a><br><br><b>نکته مهم:</b> لطفاً این صفحه را ببندید و ورکر مربوط به Setup را از کلودفلر پاک کنید.', 'success');
        } else {
          addLog('Error: ' + result.error);
          showAlert('خطا در راه‌اندازی: ' + result.error, 'error');
        }
      } catch (err) {
        addLog('Fetch Error: ' + err.message);
        showAlert('خطای شبکه یا سرور: ' + err.message, 'error');
      } finally {
        submitBtn.disabled = false;
        spinner.style.display = 'none';
        btnText.textContent = 'شروع نصب جادویی';
      }
    });
  </script>
</body>
</html>`;
}