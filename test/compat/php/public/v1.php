<?php
// The Mercure 1.0 half of the test app: symfony/mercure >= 0.9 (ProtocolVersion::V1 is its default), publishing with
// RFC 9068 access tokens (typ at+jwt; iss, aud, sub, client_id, exp, authorization_details).
//
//   GET /v1/publish?topic=T[&topic=T2...]&data=D&private=1&id=I&type=Y&retry=N[&grant=urlpattern:*]
//   GET /v1/discover[?subscribe=exact:T&subscribe=urlpattern:P]   Link header + the access-token cookie
//   GET /v1/info
//
// Environment: MERCURE_URL, MERCURE_PUBLIC_URL, MERCURE_JWT_SECRET, MERCURE_ISSUER (the hub's trusted issuer),
// MERCURE_AUDIENCE (default: MERCURE_URL and MERCURE_PUBLIC_URL, both).

declare(strict_types=1);

require __DIR__ . '/../vendor-v1/autoload.php';

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Mercure\Authorization;
use Symfony\Component\Mercure\Discovery;
use Symfony\Component\Mercure\Hub;
use Symfony\Component\Mercure\HubRegistry;
use Symfony\Component\Mercure\Jwt\DefaultClaimsTokenFactory;
use Symfony\Component\Mercure\Jwt\FactoryTokenProvider;
use Symfony\Component\Mercure\Jwt\Grant;
use Symfony\Component\Mercure\Jwt\LcobucciFactory;
use Symfony\Component\Mercure\ProtocolVersion;
use Symfony\Component\Mercure\Update;
use Symfony\Component\WebLink\HttpHeaderSerializer;

$secret = getenv('MERCURE_JWT_SECRET') ?: 'compat-secret-compat-secret-0123456789';
$url = getenv('MERCURE_URL') ?: 'http://localhost/.well-known/mercure';
$publicUrl = getenv('MERCURE_PUBLIC_URL') ?: $url;
$issuer = getenv('MERCURE_ISSUER') ?: 'https://localhost';
$audience = getenv('MERCURE_AUDIENCE') ? explode(',', getenv('MERCURE_AUDIENCE')) : array_values(array_unique([$url, $publicUrl]));

$claims = ['iss' => $issuer, 'aud' => $audience, 'sub' => 'compat-app', 'client_id' => 'compat-app'];
$factory = new LcobucciFactory($secret, 'hmac.sha256', 3600, '', ProtocolVersion::V1);
$tokenFactory = new DefaultClaimsTokenFactory($factory, $claims);

// "exact:T" / "urlpattern:P" / "T" (exact) -> a matcher map
function matchers(array $specs): array
{
    $out = [];
    foreach ($specs as $spec) {
        if (preg_match('/^(exact|urlpattern):(.*)$/s', $spec, $m)) {
            $out[$m[1]][] = $m[2];
        } else {
            $out['exact'][] = $spec;
        }
    }
    return $out;
}

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

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$request = Request::createFromGlobals();

switch ($path) {
    case '/v1/publish':
        $topics = multi('topic');
        if (!$topics) {
            fail(400, 'missing topic');
        }
        $grantSpecs = multi('grant') ?: ['urlpattern:*'];
        $provider = new FactoryTokenProvider($tokenFactory, [new Grant([Grant::ACTION_PUBLISH], matchers($grantSpecs))]);
        $hub = new Hub($url, $provider, $tokenFactory, $publicUrl, null, null, ProtocolVersion::V1);
        $data = multi('data')[0] ?? '';
        $private = isset($_GET['private']) && $_GET['private'] !== '' && $_GET['private'] !== '0';
        $id = isset($_GET['id']) && $_GET['id'] !== '' ? $_GET['id'] : null;
        $type = isset($_GET['type']) && $_GET['type'] !== '' ? $_GET['type'] : null;
        $retry = isset($_GET['retry']) && $_GET['retry'] !== '' ? (int) $_GET['retry'] : null;
        try {
            $eventId = $hub->publish(new Update($topics, $data, $private, $id, $type, $retry));
        } catch (Throwable $e) {
            $prev = $e->getPrevious();
            fail(502, get_class($e) . ': ' . $e->getMessage() . ($prev ? ' / ' . $prev->getMessage() : ''));
        }
        header('Content-Type: text/plain; charset=utf-8');
        echo $eventId;
        break;

    case '/v1/discover':
        $hub = new Hub($url, new FactoryTokenProvider($tokenFactory), $tokenFactory, $publicUrl, null, null, ProtocolVersion::V1);
        $registry = new HubRegistry($hub);
        (new Discovery($registry))->addLink($request);
        header('Link: ' . (new HttpHeaderSerializer())->serialize($request->attributes->get('_links')->getLinks()));

        $subscribe = multi('subscribe') ?: ['urlpattern:*'];
        $grants = [new Grant([Grant::ACTION_SUBSCRIBE], matchers($subscribe), multi('payload') ? json_decode(multi('payload')[0], true) : null)];
        $out = ['hub' => $publicUrl, 'cookieName' => $hub->getCookieName()];
        try {
            $cookie = (new Authorization($registry))->createCookie($request, $grants);
            header('Set-Cookie: ' . $cookie);
            $out['token'] = $cookie->getValue();
        } catch (Throwable $e) {
            // "__Secure-" needs https: the library refuses on a plain-HTTP hub URL. Hand out the token itself, a
            // raw HTTP client can still send it in the __Secure- cookie.
            $out['cookieError'] = $e->getMessage();
            $out['token'] = $tokenFactory->create($grants, ['exp' => new DateTimeImmutable('+1 hour')]);
        }
        header('Content-Type: application/json');
        echo json_encode($out);
        break;

    case '/v1/info':
        header('Content-Type: application/json');
        echo json_encode(['url' => $url, 'publicUrl' => $publicUrl, 'issuer' => $issuer, 'audience' => $audience]);
        break;

    default:
        fail(404, 'not found');
}
