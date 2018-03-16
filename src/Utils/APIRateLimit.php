<?php


namespace App\Utils;

use Slim\Middleware;
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;


// Jose Álvaro Domínguez @ 2018
// Pablo Roca @ 2016

/**
 * Class APIRateLimit
 */

class APIRateLimit
{
    /**
     * @var \PDO
     */
    private $pdo;

    private $requests;
    private $inmins;
    private $settings;

    /**
     * Constructor.
     * @param ContainerInterface $container Slim container object for DI.
     */
    public function __construct($container)
    {
        $this->settings = $container->get('settings')['apirate'];
        $this->pdo = $container->get('apidb');

        $this->inmins = $this->settings['inmins'];
        $this->requests = $this->settings['requests'];
    }

    /**
     * Callable used by entrypoint for Middlewares.
     * @param ServerRequestInterface $request Slim request object
     * @param ResponseInterface $response Slim response object
     * @param callable $next Callable that link the next middleware.
     */
    public function __invoke(Request $request, Response $response, $next)
    {
        // Check if we have an Authorization header. Only supporting Basic Auth at the moment.
        $header = $this->getAuthorizationHeader($request);

        if($header){
            // Get Api User information from [apiusers] table. Getting user_id, user name and throttle limit from database.
            $user = $this->getUser($header);
            if($user){
                // If we have a valid user, then try to throttle.
                return $this->throttleUser($user);
            }
        }
        // If Not API user detected, try to Throttle by IP.
        $ip = $this->info_about_ip()['REMOTE_ADDR'];
        return $this->throttleIp($ip);
    }

    /**
     * Getting and decoding Authorization Header for Basic auth.
     * @param ServerRequestInterface $request Request object from Slim.
     * @return string|NULL Return an string with user:password decoded or Null if it does not exit.
     */
    protected function getAuthorizationHeader(Request $request)
    {
        // HTTP Authorization Header format:
        // 		Authorization: Basic base64(user:password)

        $headers = $request->getHeaders();
        if(array_key_exists('Authorization', $headers)){
            $header = $headers['Authorization'];

            $parts = explode(' ', $header);
            $hash = array_pop($parts);
            $plain = base64_decode($hash);

            return $plain;
        }
        return NULL;
    }

    /**
     * Getting User from database extracting the username and sha1 hash from Authozation header
     * @param string $header Plain string with [user:pasword] decoded from Authorization header
     * @return mixed|NULL Return an Array with the user information or null if the user is not found.
     */
    protected function getUser($header)
    {
        if(preg_match("#([\w]+)[:]([\w]+)#", $header, $matches)){
            $user = $matches[1];
            $pass = $matches[2];

            // Looking for the user in [apiusers] table.
            $sql = "SELECT user_id, user, throttle FROM %s WHERE user = %s AND password = %s";
            $sql = sprintf($sql, 'apiusers', $user, sha1($pass));

            $stmt = $this->pdo->prepare($sql);
            $stmt->execute();

            if ($stmt) {
                $result = $stmt->fetch(\PDO::FETCH_ASSOC);
                // Return the user_id, the user name and the throttle limit for processing.
                return [
                    'id' 		=> $result['user_id'],
                    'user' 		=> $result['user'],
                    'limit'		=> $result['limit'],
                ];
            }
        }
        return NULL;
    }

    /**
     * Try to throttle a existing API User.
     * @param mixed $user Array with user information for processing.
     * @return bool Return TRUE or FALSE depending if the user has exceed the limits configured for him in the database.
     */
    protected function throttleUser($user)
    {

        // Get all the activity from the [apiuseractivity] table in the proper time window.
        $sql = "SELECT count(*) as requests FROM ( select 1 FROM %s WHERE user_id = %s AND ts >= date_sub(NOW(), interval %s MINUTE)  LIMIT %s ) AS result";
        $sql = sprintf($sql, 'apiuseractivity', $user['id'], $this->inmins, $user['limit']);

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute();

        if ($stmt) {
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);

            // If it exceed the setted parameter, then throttle it.
            if ($result['requests'] > $user['limit']) {
                return TRUE;
            }
        }

        // Incrementing requests by the user.
        $sql = sprintf('INSERT INTO %s (user_id) VALUES (:user_id)', 'apiuseractivity');
        $stmt = $this->pdo->prepare($sql);
        // bind the key
        $stmt->bindValue(':user_id', $user['id']);
        $stmt->execute();

        return FALSE;
    }

    /**
     * Try to Throttle by IP. This is the original Behavour of the middleware.
     * @param string $ip IP from the origin of the request.
     * @return bool Return TRUE or FALSE depending if the IP has exceed the limits configured for him in the database.
     */
    protected function throttleIp ($ip)
    {

        // fast count by http://stackoverflow.com/questions/4871747/mysql-count-performance
        //

        $sql = "SELECT count(*) as requests FROM ( select 1 FROM xrequest WHERE originip = '".$ip."' AND ts >= date_sub(NOW(), interval ".$this->inmins." MINUTE)  LIMIT ".$this->requests." ) AS result";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute();

        if ($stmt) {
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
        } else {
            $result = null;
        }

        if ($result['requests'] > $this->requests) {
            return TRUE;
        }

        $sql = sprintf('INSERT INTO %s (originip) VALUES (:originip)', $ip);
        $stmt = $this->pdo->prepare($sql);
        // bind the key
        $stmt->bindValue(':originip', $ip);
        $stmt->execute();

        return FALSE;

    }

    protected function info_about_ip () {
        //
        // cloudfare ip ranges
        //
        // https://www.cloudflare.com/ips-v4 28/2/2016
        // https://www.cloudflare.com/ips-v6 28/2/2016
        //
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $cf_ip_ranges = array(
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '104.16.0.0/12',
            '108.162.192.0/18',
            '131.0.72.0/22',
            '141.101.64.0/18',
            '162.158.0.0/15',
            '172.64.0.0/13',
            '173.245.48.0/20',
            '188.114.96.0/20',
            '190.93.240.0/20',
            '197.234.240.0/22',
            '198.41.128.0/17',
            '199.27.128.0/21',
            '2400:cb00::/32',
            '2405:8100::/32',
            '2405:b500::/32',
            '2606:4700::/32',
            '2803:f800::/32',
            );
            foreach ($cf_ip_ranges as $range) {
                if ($this->ipVersion($range) == 4) {
                    if ($this->ip_in_range($_SERVER['REMOTE_ADDR'], $range)) {
                        $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP'];
                        break;
                    }
                } else {
                    if ($this->PMA_ipv6MaskTest($range,$_SERVER['REMOTE_ADDR'])) {
                        $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP'];
                        break;
                    }
                }
            }
        }

        $array = array(
            "REMOTE_ADDR" => $_SERVER['REMOTE_ADDR']
        );

        return $array;
    }

    protected function ipVersion($txt) {
        return strpos($txt, ":") === false ? 4 : 6;
    }

    /**
     * Check if a given ip is in a network
     * @param  string $ip    IP to check in IPV4 format eg. 127.0.0.1
     * @param  string $range IP/CIDR netmask eg. 127.0.0.0/24, also 127.0.0.1 is accepted and /32 assumed
     * @return boolean true if the ip is in this range / false if not.
     */
    protected function ip_in_range( $ip, $range ) {
        if ( strpos( $range, '/' ) == false ) {
            $range .= '/32';
        }
        // $range is in IP/CIDR format eg 127.0.0.1/24
        list( $range, $netmask ) = explode( '/', $range, 2 );
        $range_decimal = ip2long( $range );
        $ip_decimal = ip2long( $ip );
        $wildcard_decimal = pow( 2, ( 32 - $netmask ) ) - 1;
        $netmask_decimal = ~ $wildcard_decimal;
        return ( ( $ip_decimal & $netmask_decimal ) == ( $range_decimal & $netmask_decimal ) );
    }

    /**
    * IPv6 matcher
    * CIDR section taken from http://stackoverflow.com/a/10086404
    * Modified for phpMyAdmin
    *
    * Matches:
    * xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
    * (exact)
    * xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:[yyyy-zzzz]
    * (range, only at end of IP - no subnets)
    * xxxx:xxxx:xxxx:xxxx/nn
    * (CIDR)
    *
    * Does not match:
    * xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xx[yyy-zzz]
    * (range, partial octets not supported)
    *
    * @param string $test_range string of IP range to match
    * @param string $ip_to_test string of IP to test against range
    *
    * @return boolean    whether the IP mask matches
    *
    * @access  public
    */
    function PMA_ipv6MaskTest($test_range, $ip_to_test)
    {
        $result = true;
        // convert to lowercase for easier comparison
        $test_range = strtolower($test_range);
        $ip_to_test = strtolower($ip_to_test);
        $is_cidr = strpos($test_range, '/') > -1;
        $is_range = strpos($test_range, '[') > -1;
        $is_single = ! $is_cidr && ! $is_range;
        $ip_hex = bin2hex(inet_pton($ip_to_test));
        if ($is_single) {
            $range_hex = bin2hex(inet_pton($test_range));
            $result = $ip_hex === $range_hex;
            return $result;
        }
        if ($is_range) {
            // what range do we operate on?
            $range_match = array();
            $match = preg_match(
                '/\[([0-9a-f]+)\-([0-9a-f]+)\]/', $test_range, $range_match
            );
            if ($match) {
                $range_start = $range_match[1];
                $range_end   = $range_match[2];
                // get the first and last allowed IPs
                $first_ip  = str_replace($range_match[0], $range_start, $test_range);
                $first_hex = bin2hex(inet_pton($first_ip));
                $last_ip   = str_replace($range_match[0], $range_end, $test_range);
                $last_hex  = bin2hex(inet_pton($last_ip));
                // check if the IP to test is within the range
                $result = ($ip_hex >= $first_hex && $ip_hex <= $last_hex);
            }
            return $result;
        }
        if ($is_cidr) {
            // Split in address and prefix length
            list($first_ip, $subnet) = explode('/', $test_range);
            // Parse the address into a binary string
            $first_bin = inet_pton($first_ip);
            $first_hex = bin2hex($first_bin);
            $flexbits = 128 - $subnet;
            // Build the hexadecimal string of the last address
            $last_hex = $first_hex;
            $pos = 31;
            while ($flexbits > 0) {
                // Get the character at this position
                $orig = substr($last_hex, $pos, 1);
                // Convert it to an integer
                $origval = hexdec($orig);
                // OR it with (2^flexbits)-1, with flexbits limited to 4 at a time
                $newval = $origval | (pow(2, min(4, $flexbits)) - 1);
                // Convert it back to a hexadecimal character
                $new = dechex($newval);
                // And put that character back in the string
                $last_hex = substr_replace($last_hex, $new, $pos, 1);
                // We processed one nibble, move to previous position
                $flexbits -= 4;
                $pos -= 1;
            }
            // check if the IP to test is within the range
            $result = ($ip_hex >= $first_hex && $ip_hex <= $last_hex);
        }
        return $result;
    } // end of the "PMA_ipv6MaskTest()" function
}

