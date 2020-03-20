<?php
assert_options(ASSERT_ACTIVE, 1);

require(__DIR__.'/../app/classes.php');

$crypto = new Aes256GcmCrypto();
$keyCache = new NoKeyCache();

$timestamp = time();
$cleartext = "Captain on the bridge!";
$password = "NCC-1701-D";
$iterations = 1000;
$salt = random_bytes(16);

$original_entry = new ImmutableCleartextLogEntry($timestamp, $cleartext);
$encrypted_entry = $crypto->encrypt($original_entry, $password, $salt, $iterations, $keyCache);
$decrypted_entry = $crypto->decrypt($encrypted_entry, $password, $keyCache);

// Timestamp must be the same
assert($original_entry->get_timestamp() === $encrypted_entry->get_timestamp());
assert($original_entry->get_timestamp() === $decrypted_entry->get_timestamp());

// Payload must be encrypted and successfully decrypted
assert($original_entry->get_payload() != $encrypted_entry->get_payload());
assert($original_entry->get_payload() === $decrypted_entry->get_payload());
