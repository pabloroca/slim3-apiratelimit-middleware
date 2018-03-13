# API Rate Limiter for Slim3

Middleware for API Rate limiter. When request limit exceeds a predefined value it returns HTTP Status code 429 and does not process further requests.

It works with a MySQL & MariaDB database

## Main specs

- If you have CloudFare, it checks that the origin ip belongs to them, also sets the proper remote IP

## Install

**1 Create table xrequests where all incoming requests are registered. Be sure that the password in apiusers is sha1 encrypted**

```sql
CREATE TABLE IF NOT EXISTS `xrequests` (
  `id` int(11) NOT NULL,
  `originip` varchar(45) NOT NULL DEFAULT '',
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=85 DEFAULT CHARSET=utf8 COMMENT='Requests from remote IPs';

ALTER TABLE `xrequests`
 ADD PRIMARY KEY (`id`), ADD KEY `ts` (`ts`), ADD KEY `originip` (`originip`);

ALTER TABLE `xrequests`
MODIFY `id` int(11) NOT NULL AUTO_INCREMENT,AUTO_INCREMENT=1;


CREATE TABLE IF NOT EXISTS `apiusers` (
  `user_id` INTEGER			NOT NULL AUTO_INCREMENT	PRIMARY KEY,
  `user` 	VARCHAR(128)	NOT NULL,
  `password` 	VARCHAR(1024)	NOT NULL,
  `limit`	INTEGER				NOT NULL,
) ENGINE=InnoDB AUTO_INCREMENT=85 DEFAULT CHARSET=utf8 COMMENT='Registered API Users';

CREATE TABLE IF NOT EXISTS `apiuseractivity` (
  `id` INTEGER	NOT NULL AUTO_INCREMENT	PRIMARY KEY,
  `user_id` INTEGER	NOT NULL,
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=85 DEFAULT CHARSET=utf8 COMMENT='Requests from API Users';

```


**2 Add the settings**

```php

$settings = [
	'apirate' => [
		'pdo' => [
			'connection' => 'mysql:host=localhost;dbname=DBNAME;charset=utf8',
			'user' => 'DBUSERNAME',
			'pass' => 'DBPASSWD',
		],
		'inmins' => 60,
		'requests' => 100,
	]
];

```

**3. Create the PDO object in container for DI**

```php

$container['apidb'] = function ($c){

	$settings = $c->get('settings')['apirate'];
	$pdo = $settings['pdo'];

	return new PDO($pdo['connection'], $pdo['user'], $pdo['pass']);
}

```


**4 Add Application Middleware and give it the Container for DI.**

```php



$container = $app->getContainer();

$app->add(function ($request, $response, $next) use ($container) {

	$APIRateLimit = new App\Utils\APIRateLimit($container);
	$mustbethrottled = $APIRateLimit($request, $response, $next);

	if ($mustbethrottled == false) {
        $responsen = $next($request, $response);
	} else {
        $responsen = $response ->withStatus(429)
                               ->withHeader('RateLimit-Limit', $requests);
	}

    return $responsen;
});
```


**Notes**: beware that you need to have an event who deletes periodically the xrequests table. You can use the MySQL Event Scheduler https://dev.mysql.com/doc/refman/5.7/en/event-scheduler.html or a cron job.

**Notes 2**: If you are planning to use the User Throttle functionallity, be sure of usig HTTPS connections because at the moment, this
middleware only support HTTP Auth Basic. So you user:pass is going to be sent as a header base64 encoded.

**Note 3**: It is possible to use other database vendors if the sql schema if adapted and the PDO connection string is properly configured in the
settings.

**Note 4**: The target of making all these changes is give a basic support or small inspiration for resolving

It will be better integrated in my **Slim 3 Very simple REST Skeleton**  https://github.com/pabloroca/slim3-simple-rest-skeleton
