<?php 
define("SHARED_SECRET", "sup3rs3cr3t!!");

if(!function_exists('hash_equals')) {
    function hash_equals($str1, $str2) {
        // Run constant-time comparison for PHP < 5.6 which doesn't support hmac_equals
        $str1_len = strlen($str1);
        $str2_len = strlen($str2);

        // Calculate XOR
        $diff = $str1_len ^ $str2_len;
        for($x = 0; $x < $str1_len && $x < $str2_len; $x++) {
            $diff |= ord($str1[$x]) ^ ord($str2[$x]);
        }

        return $diff === 0;
    }
}

function verifySignature($string_to_verify, $signature, $shared_secret) {
    return hash_equals(hash_hmac("sha512", $string_to_verify, $shared_secret), $signature);
}

function verifyTime($decoded_json) {
    $j = json_decode($decoded_json, true);
    if(time() - $j['timestamp'] > 320) {
        throw new Exception('Timestamp too far in the past');
    }
    return $j;
}

$url = '/?data=eyJuYW1lIjoiam9lIHNtaXRoIiwiY2F0ZWdvcnkiOiJwZW9wbGUiLCJhY3Rpb24iOiJ0cmFuc3BvcnQiLCJ3aGVyZSI6InBsdXRvIiwidGltZXN0YW1wIjoxNjcyMDI3MDE5fQ==&signature=ZmQyNWEwYWI4OGU0ZGQxYTYyYTZmMjYxOTFmM2JiZjRjYmY2OWQzMzE0MmM2ZTNjMTc1NmJkMzIzOGRjMDEzZmY4YmJhZTdiZjcxNWNkM2E0YTVmNmNmOGU1ZDQ2OTdkZWZlMWExNGFkZjRjN2YwNDlmZGU2ODMyODc3OWFlNDU=';
$query_components = array();
$query = parse_str(parse_url($url)['query'], $query_components);

$decoded_signature = base64_decode($query_components['signature']);
$decoded_json = base64_decode($query_components['data']);

if (verifySignature($decoded_json, $decoded_signature, SHARED_SECRET) !== false) {
    echo "Valid signature\n";

    # Verify timestamp
    $payload = verifyTime($decoded_json);
    echo "Timestamp verified\n";
    print_r($payload);
} else {
    echo "Invalid signature\n";
}
