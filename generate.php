<?php
define("SHARED_SECRET", "sup3rs3cr3t!!");

function signString($string_to_sign, $shared_secret) {
	return hash_hmac("sha512", $string_to_sign, $shared_secret);
}


$payload = array(
	'name' => 'joe smith',
	'category' => 'people',
	'action' => 'transport',
	'where' => 'pluto',
	'timestamp' => time()
);

$json_payload = json_encode($payload);
$signature = signString($json_payload, SHARED_SECRET);

$encoded_signature = base64_encode($signature);
$encoded_payload = base64_encode($json_payload);

echo "/?data={$encoded_payload}&signature={$encoded_signature}\n";
