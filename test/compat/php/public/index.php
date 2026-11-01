<?php
// Router. The legacy (symfony/mercure 0.7) and Mercure 1.0 (0.9) halves each have their own vendor directory: the two
// library versions cannot be loaded in one process.
declare(strict_types=1);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
require str_starts_with($path, '/v1/') ? __DIR__ . '/v1.php' : __DIR__ . '/legacy.php';
