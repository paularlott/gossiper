<?php
// Test app for the Gossiper protocol-compatibility suite. Uses the official symfony/mercure component.
//
//   GET /publish?topic=T[&topic=T2...]&data=D&private=1&id=I&type=Y&retry=N   -> publishes, returns the update id
//   GET /discover[?subscribe=S&subscribe=S2&publish=P]                          -> Link: <hub>; rel="mercure" and the
//                                                                                  mercureAuthorization cookie
//   GET /info                                                                   -> JSON: hub URLs, JWT for the cookie
//
// Environment: MERCURE_URL (where this app publishes), MERCURE_PUBLIC_URL (what browsers use), MERCURE_JWT_SECRET.

declare(strict_types=1);

require __DIR__ . '/../vendor-legacy/autoload.php';

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Mercure\Authorization;
use Symfony\Component\Mercure\Discovery;
use Symfony\Component\Mercure\Hub;
use Symfony\Component\Mercure\HubRegistry;
use Symfony\Component\Mercure\Jwt\FactoryTokenProvider;
use Symfony\Component\Mercure\Jwt\LcobucciFactory;
use Symfony\Component\Mercure\Update;
use Symfony\Component\WebLink\HttpHeaderSerializer;

$secret = getenv('MERCURE_JWT_SECRET') ?: 'compat-secret-compat-secret-0123456789';
$url = getenv('MERCURE_URL') ?: 'http://localhost/.well-known/mercure';
$publicUrl = getenv('MERCURE_PUBLIC_URL') ?: $url;

$factory = new LcobucciFactory($secret, 'hmac.sha256', 3600);
// The app's own publish token: may publish anything (what a Symfony app configures as MERCURE_JWT_SECRET).
$hub = new Hub($url, new FactoryTokenProvider($factory, [], ['*']), $factory, $publicUrl);
$registry = new HubRegistry($hub);

$request = Request::createFromGlobals();
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

// PHP folds repeated parameters; read the raw query string so that topic=a&topic=b means two topics.
function multi(string $name): array
{
    $out = [];
    foreach (explode('&', $_SERVER['QUERY_STRING'] ?? '') as $pair) {
        if ($pair === '') {
            continue;
        }
        [$k, $v] = array_pad(explode('=', $pair, 2), 2, '');
        if (urldecode($k) === $name) {
            $out[] = urldecode($v);
        }
    }
    return $out;
}

function fail(int $status, string $message): never
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    echo $message;
    exit;
}

switch ($path) {
    case '/publish':
        $topics = multi('topic');
        if (!$topics) {
            fail(400, 'missing topic');
        }
        $data = multi('data')[0] ?? '';
        $private = isset($_GET['private']) && $_GET['private'] !== '' && $_GET['private'] !== '0';
        $id = isset($_GET['id']) && $_GET['id'] !== '' ? $_GET['id'] : null;
        $type = isset($_GET['type']) && $_GET['type'] !== '' ? $_GET['type'] : null;
        $retry = isset($_GET['retry']) && $_GET['retry'] !== '' ? (int) $_GET['retry'] : null;
        try {
            $eventId = $hub->publish(new Update($topics, $data, $private, $id, $type, $retry));
        } catch (Throwable $e) {
            fail(502, get_class($e) . ': ' . $e->getMessage());
        }
        header('Content-Type: text/plain; charset=utf-8');
        echo $eventId;
        break;

    case '/discover':
        $discovery = new Discovery($registry);
        $discovery->addLink($request);
        $links = $request->attributes->get('_links');
        header('Link: ' . (new HttpHeaderSerializer())->serialize($links->getLinks()));

        $subscribe = multi('subscribe') ?: ['*'];
        $publish = multi('publish');
        $authorization = new Authorization($registry);
        $cookie = $authorization->createCookie($request, $subscribe, $publish ?: null);
        header('Set-Cookie: ' . $cookie);
        header('Content-Type: application/json');
        echo json_encode(['hub' => $publicUrl, 'cookie' => $cookie->getName(), 'subscribe' => $subscribe]);
        break;

    case '/info':
        header('Content-Type: application/json');
        echo json_encode(['url' => $url, 'publicUrl' => $publicUrl, 'secret' => $secret]);
        break;

    default:
        fail(404, 'not found');
}
