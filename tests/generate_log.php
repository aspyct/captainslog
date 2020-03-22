<?php
require __DIR__.'/../app/classes.php';

$storage = new SingleFileStorage('/tmp');
$crypto = new Aes256GcmCrypto();
$hash = new SaltySha256Algorithm("salt");
$key_cache = new SingleKeyCache();
$choreographer = new DefaultChoreographer($crypto, $storage, $hash);

$user = "Jean-Luc Picard";
$password = "NCC-1701-D";

$choreographer->initialize_user($user, $password, "Meeting at Farpoint Station", $key_cache);
$choreographer->append_log_entry($user, $password, time(), "Meeting at Farboint Station.", $key_cache);
$choreographer->append_log_entry($user, $password, time(), "Meeting at Farboint Station.", $key_cache);
$choreographer->append_log_entry($user, $password, time(), "Meeting at Farboint Station.", $key_cache);
$choreographer->append_log_entry($user, $password, time(), "Meeting at Farboint Station.", $key_cache);
$choreographer->append_log_entry($user, $password, time(), "Meeting at Farboint Station.", $key_cache);
$choreographer->append_log_entry($user, $password, time(), "Meeting at Farboint Station.", $key_cache);
$choreographer->append_log_entry($user, $password, time(), "Meeting at Farboint Station.", $key_cache);
$choreographer->append_log_entry($user, $password, time(), "Meeting at Farboint Station.", $key_cache);
$choreographer->append_log_entry($user, $password, time(), "Meeting at Farboint Station.", $key_cache);
$choreographer->append_log_entry($user, $password, time(), "Meeting at Farboint Station.", $key_cache);
