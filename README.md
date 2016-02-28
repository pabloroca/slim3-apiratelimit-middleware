# API Rate Limit for Slim3

Middleware for API Rate limit. When limit exceeded it returns HTTP Status code 429 and does not process further requests.

It works with a MySQL / MariaDB database

## Install

**1 Create table xrequests where all incoming requests are registered**

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
```

**2 Add Application Middleware**

```php
$app->add(function ($request, $response, $next) {

	$requests = 100;
	$inmins = 60;
	
	$APIRateLimit = new App\Utils\APIRateLimit($requests, $inmins);
	$mustbethrottled = $APIRateLimit();
	
	if ($mustbethrottled == false) {
        $responsen = $next($request, $responsen);
	} else {
        $responsen = $responsen ->withStatus(429)
                                ->withHeader('RateLimit-Limit', $this->settings['apithrottle']['requests']);
	}

    return $responsen;
});
```

**Notes**: beware that you need to have an event who deletes periodically the xrequests table. You can use the MySQL Event Scheduler https://dev.mysql.com/doc/refman/5.7/en/event-scheduler.html or a cron job.
