<?php
declare(strict_types=1);

/**
 * WASLA — installer (D9): creates config, runs migrations in order, seeds
 * the first technical-admin account, then SELF-LOCKS (storage/installed.lock).
 * Re-running after lock simply redirects to the app.
 *
 * Post-audit hardening (W-01/02/03/11):
 * - the DB NAME chosen by the operator is honoured (migrations no longer
 *   carry CREATE DATABASE / USE `wasla`; the installer validates the name);
 * - demonstration data (003) is OFF by default and flagged dev-only, and its
 *   accounts get verify-nothing sentinel hashes — real dev credentials are
 *   printed once by tools/seed-demo.php;
 * - the admin-existence query is actually executed before fetch();
 * - a failed install-lock write aborts the installation;
 * - config.php is written 0640 and the installer verifies 27 tables after 001+004.
 */

use App\Core\Autoloader;
use App\Core\InstallLock;

require __DIR__ . '/app/Core/Autoloader.php';
require __DIR__ . '/app/Core/helpers.php';
Autoloader::register();
define('BASE_PATH', __DIR__);
$GLOBALS['wasla_config'] = [];

session_name('wasla_install');
session_start();
if (empty($_SESSION['_csrf'])) {
    $_SESSION['_csrf'] = bin2hex(random_bytes(32));
}

if (InstallLock::isInstalled()) {
    header('Location: index.php');
    exit;
}

$errors = [];
$done = false;

function install_check_db(array $db, bool $createDb): PDO
{
    if (preg_match('/^[A-Za-z0-9_]{1,64}$/', $db['name']) !== 1) {
        throw new RuntimeException('invalid database name (letters, digits, underscore; max 64)');
    }
    $pdo = new PDO(
        "mysql:host={$db['host']};port={$db['port']};charset=utf8mb4",
        $db['user'],
        $db['pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
    if ($createDb) {
        $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$db['name']}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    }
    $pdo->exec("USE `{$db['name']}`");
    return $pdo;
}

/** @return list<string> applied versions */
function install_run_migrations(PDO $pdo, bool $withDemo): array
{
    $applied = [];
    $have = $pdo->query('SHOW TABLES LIKE \'schema_migrations\'')->fetch();
    if ($have === false) {
        // 001 must run first; it creates the database objects
        $sql = (string) file_get_contents(__DIR__ . '/database/migrations/001_initial_schema.sql');
        $pdo->exec($sql);
    }
    $known = $pdo->query('SELECT version FROM schema_migrations')->fetchAll(PDO::FETCH_COLUMN);
    $known = array_map('strval', $known);
    foreach (['001_initial_schema.sql', '002_reference_seed.sql', '003_demo_data.sql', '004_audit_hardening.sql'] as $i => $file) {
        $version = sprintf('%03d', $i + 1);
        if (in_array($version, $known, true)) {
            continue;
        }
        if ($version === '003' && !$withDemo) {
            continue;
        }
        $sql = (string) file_get_contents(__DIR__ . '/database/migrations/' . $file);
        $pdo->exec($sql);
        $applied[] = $version;
    }
    // W-03.6: verify the schema really landed (a silent exec() failure must
    // not produce a half-installed platform)
    $tables = (int) $pdo->query('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()')->fetchColumn();
    if ($tables < 27) {
        throw new RuntimeException('schema incomplete: ' . $tables . ' tables found, 27 expected');
    }
    return $applied;
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $sent = (string) ($_POST['_csrf'] ?? '');
    if (!hash_equals((string) $_SESSION['_csrf'], $sent)) {
        $errors[] = 'CSRF mismatch';
    } else {
        $db = [
            'host' => trim((string) ($_POST['db_host'] ?? '127.0.0.1')),
            'port' => trim((string) ($_POST['db_port'] ?? '3306')),
            'name' => trim((string) ($_POST['db_name'] ?? 'wasla')),
            'user' => trim((string) ($_POST['db_user'] ?? 'root')),
            'pass' => (string) ($_POST['db_pass'] ?? ''),
            'charset' => 'utf8mb4',
        ];
        $adminEmail = trim(mb_strtolower((string) ($_POST['admin_email'] ?? '')));
        $adminPass = (string) ($_POST['admin_password'] ?? '');
        $withDemo = isset($_POST['load_demo']);

        try {
            if (!filter_var($adminEmail, FILTER_VALIDATE_EMAIL)) {
                throw new RuntimeException('admin e-mail invalid');
            }
            if (strlen($adminPass) < 12) {
                throw new RuntimeException('admin password must be >= 12 characters');
            }
            $pdo = install_check_db($db, true);
            $applied = install_run_migrations($pdo, $withDemo);

            // first technical-admin account (T-01). W-03: the statement is
            // EXECUTED before fetch; the check targets the submitted e-mail,
            // not the role, so a pre-seeded demo admin cannot block the real one.
            $q = $pdo->prepare('SELECT 1 FROM users WHERE email = ?');
            $q->execute([$adminEmail]);
            if ($q->fetchColumn() === false) {
                $ins = $pdo->prepare(
                    'INSERT INTO users (email, password_hash, role, full_name) VALUES (?,?, \'technical_admin\', ?)'
                );
                $ins->execute([$adminEmail, \App\Core\Auth::hashPassword($adminPass), 'Technical Administrator']);
            }

            // write config/config.php (config/ is deny-by-default, SEC-08)
            $configPhp = "<?php\ndeclare(strict_types=1);\nreturn " . var_export(['db' => $db, 'app' => [
                'env' => 'prod',
                'log_path' => __DIR__ . '/storage/logs',
                'upload_path' => __DIR__ . '/storage/uploads',
                'backup_path' => __DIR__ . '/storage/backups',
                'lock_path' => __DIR__ . '/storage/installed.lock',
            ]], true) . ";\n";
            if (@file_put_contents(__DIR__ . '/config/config.php', $configPhp) === false) {
                throw new RuntimeException('cannot write config/config.php');
            }
            @chmod(__DIR__ . '/config/config.php', 0640);   // W-11: owner+group only
            // ensure runtime directories (uploads/logs/backups)
            foreach (['storage/uploads', 'storage/logs', 'storage/backups'] as $rel) {
                $dir = __DIR__ . '/' . $rel;
                if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
                    throw new RuntimeException('cannot create ' . $rel);
                }
            }

            // self-lock
            InstallLock::mark();
            $done = true;
        } catch (Throwable $e) {
            $errors[] = $e->getMessage();
        }
    }
}

$csrf = (string) $_SESSION['_csrf'];
?><!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WASLA — Install</title>
<style>
body{font-family:system-ui,sans-serif;background:#faf7f0;margin:0;padding:2rem;color:#1c2321}
.card{max-width:34rem;margin:0 auto;background:#fff;border:1px solid #e3ddd0;border-radius:16px;padding:2rem}
label{display:block;font-weight:600;margin:.8rem 0 .2rem}
input[type=text],input[type=password],input[type=email]{width:100%;padding:.5rem;border:1px solid #e3ddd0;border-radius:8px;font:inherit}
button{margin-top:1.2rem;background:#2a4a3a;color:#fff;border:0;border-radius:10px;padding:.7rem 1.5rem;font:inherit;font-weight:700;cursor:pointer}
.err{background:#fef2f2;border:1px solid #b3261e;color:#b3261e;border-radius:8px;padding:.6rem;margin:.6rem 0}
.ok{background:#f0fdf4;border:1px solid #2e7d32;color:#2e7d32;border-radius:8px;padding:.6rem;margin:.6rem 0}
code{background:#f1ece1;padding:0 .3rem;border-radius:4px}
</style>
</head>
<body>
<div class="card">
  <h1>WASLA — Installation</h1>
  <?php if ($done): ?>
    <div class="ok">Installed and self-locked (D9). <strong>Delete <code>install.php</code> now</strong> —
    the lock already refuses re-runs, but removing the file removes the surface entirely.</div>
    <p><a href="index.php">Open the platform</a></p>
  <?php else: ?>
    <?php foreach ($errors as $err): ?><div class="err"><?= htmlspecialchars($err) ?></div><?php endforeach; ?>
    <p>MariaDB must be running (XAMPP control panel). This installer runs the SQL migrations
       <code>001</code>–<code>004</code> against the database name you choose, creates the first
       technical-admin account, writes <code>config/config.php</code> and then self-locks.
       Use a dedicated DB account on real deployments — not <code>root</code>.</p>
    <form method="post" action="">
      <input type="hidden" name="_csrf" value="<?= htmlspecialchars($csrf) ?>">
      <label>DB host</label><input type="text" name="db_host" value="127.0.0.1">
      <label>DB port</label><input type="text" name="db_port" value="3306">
      <label>DB name</label><input type="text" name="db_name" value="wasla">
      <label>DB user</label><input type="text" name="db_user" value="root">
      <label>DB password</label><input type="password" name="db_pass" value="">
      <label>Admin e-mail</label><input type="email" name="admin_email" value="">
      <label>Admin password (≥ 12)</label><input type="password" name="admin_password" value="">
      <label><input type="checkbox" name="load_demo"> Load demonstration data — <strong>development
      only</strong>, never on a real deployment (BR-13). Demo accounts get no usable passwords until
      <code>php tools/seed-demo.php</code> is run.</label>
      <button type="submit">Install</button>
    </form>
  <?php endif; ?>
</div>
</body>
</html>
