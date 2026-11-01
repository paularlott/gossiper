# FrankenPHP WITHOUT the built-in hub: the app publishes to Gossiper.
{
	auto_https off
	frankenphp
}
:80 {
	root * /app/public
	php_server
}
