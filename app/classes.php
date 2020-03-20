<?php
/**
 * EncryptedLogEntry
 * 
 * A encrypted log entry ready to be stored, or fresh out of storage.
 * 
 * A log entry should be self-sufficient to be decrypted.
 * That allows us to discard old log entries when not needed anymore.
 * In turns, this will allow us to use a simple logrotate, redis streams or one SQL table.
 * It thus makes it easy to spin-up demo versions, implement expiration or disk management.
 */
interface EncryptedLogEntry {
    function get_timestamp() : int;
    function get_salt() : string;
    function get_iterations() : int;
    function get_iv() : string;
    function get_tag() : string;
    function get_payload() : string;
}

/**
 * CleartextLogEntry
 * 
 * A human-readable log entry. Do not store this!
 */
interface CleartextLogEntry {
    function get_timestamp() : int;
    function get_payload() : string;
}

interface LogEntryFormatViolation {
    function get_code() : int;
    function get_description() : string;
    function get_params() : array;
}

class LogEntryValidationError extends Exception {
    private $violations = [];

    public function add_violation(LogEntryFormatViolation $violation) {
        $this->violations[] = $violation;
    }

    public function get_violations() : array {
        return $this->violations;
    }
}

/**
 * LogEntryValidator
 * 
 * Decides whether or not a log entry is valid and may be encrypted and stored.
 * 
 * Can be used to enforce field length limits, e.g. if you are using VARCHAR(255) fields,
 * or require a certain etiquette (tags, json, etc.).
 */
interface LogEntryValidator {
    /**
     * @throw LogEntryValidationError if the log entry isn't valid
     */
    function validate_log_entry(CleartextLogEntry $entry);
}

interface UserHashAlgorithm {
    function hash_username(string $username) : string;
}

interface Storage {
    function get_last_entry(string $user_hash) : EncryptedLogEntry;
    function list_entries_in_range(string $user_hash, $from_timestamp, $to_timestamp) : array;
    function append_entry(string $user_hash, EncryptedLogEntry $entry) : void;
}

/**
 * KeyCache
 * 
 * By design, a key takes time to calculate.
 * The time depends on the number of pbkdf2 iterations we do.
 * Because of that, it's useful to keep a cache of the keys while decrypting stuff.
 * 
 * A KeyCache MUST NOT be shared by multiple users.
 * A KeyCache should be wiped from memory (well... php, right?) as soon as possible.
 */
interface KeyCache {
    /**
     * @throw NoSuchKeyException if no key matches the given parameters
     */
    function get_key(string $salt, int $iterations) : string;
    function put_key(string $salt, int $iterations, string $key) : void;
}

class NoSuchKeyException extends Exception {}

interface Crypto {
    function encrypt(CleartextLogEntry $entry, string $password, string $salt, int $iterations, KeyCache $keyCache) : EncryptedLogEntry;

    /**
     * @throw InvalidPasswordException if the provided password is invalid
     */
    function decrypt(EncryptedLogEntry $entry, string $password, KeyCache $keyCache) : CleartextLogEntry;
}

class InvalidPasswordException extends Exception {}

interface Output {
    function die(string $message, int $code = 0);
    function display_log_entries(array $entries);
}

/*
 * Implementation 
 */

class NoKeyCache implements KeyCache {
    public function get_key(string $salt, int $iterations) : string {
        throw new NoSuchKeyException();
    }

    public function put_key(string $salt, int $iterations, string $key) : void {}
}

class OneKeyCache implements KeyCache {
    private $salt;
    private $iterations;
    private $key;

    public function get_key(string $salt, int $iterations) : string {
        if ($salt === $this->salt && $iterations === $this->iterations) {
            return $this->key;
        }
        else {
            throw new NoSuchKeyException();
        }
    }

    public function put_key(string $salt, int $iterations, string $key) : void {
        $this->salt = $salt;
        $this->iterations = $iterations;
        $this->key = $key;
    }
}

class Aes256GcmCrypto implements Crypto {
    const CIPHER = 'aes-256-gcm';

    public function encrypt(CleartextLogEntry $entry, string $password, string $salt, int $iterations, KeyCache $keyCache) : EncryptedLogEntry {
        $key = $this->get_key($password, $salt, $iterations, $keyCache);
        $iv = random_bytes(openssl_cipher_iv_length(self::CIPHER));

        $encrypted_payload = openssl_encrypt($entry->get_payload(), self::CIPHER, $key, $this->get_options(), $iv, $tag);

        return new ImmutableEncryptedLogEntry(
            $entry->get_timestamp(),
            $salt,
            $iterations,
            $iv,
            $tag,
            $encrypted_payload
        );
    }

    /**
     * @throw InvalidPasswordException if the provided password is invalid
     */
    public function decrypt(EncryptedLogEntry $entry, string $password, KeyCache $keyCache) : CleartextLogEntry {
        $key = $this->get_key($password, $entry->get_salt(), $entry->get_iterations(), $keyCache);
        
        $decrypted_payload = openssl_decrypt(
            $entry->get_payload(),
            self::CIPHER,
            $key,
            $this->get_options(),
            $entry->get_iv(),
            $entry->get_tag()
        );

        return new ImmutableCleartextLogEntry(
            $entry->get_timestamp(),
            $decrypted_payload
        );
    }

    private function get_options() {
        return 0;
    }

    /**
     * Generates a valid aes key with a pbkdf2 derivation of the provided password.
     */
    private function get_key(string $password, string $salt, int $iterations, KeyCache $cache) : string {
        try {
            return $cache->get_key($salt, $iterations);
        }
        catch (NoSuchKeyException $_) {
            $key = hash_pbkdf2('sha256', $password, $salt, $iterations, 32, true);
            $cache->put_key($salt, $iterations, $key);

            return $key;
        }
    }
}

class ImmutableEncryptedLogEntry implements EncryptedLogEntry {
    private $timestamp;
    private $salt;
    private $iterations;
    private $iv;
    private $tag;
    private $payload;

    public function __construct(
        int $timestamp,
        string $salt,
        int $iterations,
        string $iv,
        string $tag,
        string $payload
    ) {
        $this->timestamp = $timestamp;
        $this->salt = $salt;
        $this->iterations = $iterations;
        $this->iv = $iv;
        $this->tag = $tag;
        $this->payload = $payload;
    }

    function get_timestamp() : int {
        return $this->timestamp;
    }

    function get_salt() : string {
        return $this->salt;
    }

    function get_iterations() : int {
        return $this->iterations;
    }

    function get_iv() : string {
        return $this->iv;
    }

    function get_tag() : string {
        return $this->tag;
    }

    function get_payload() : string {
        return $this->payload;
    }
}

class ImmutableCleartextLogEntry implements CleartextLogEntry {
    private $timestamp;
    private $payload;

    public function __construct(int $timestamp, string $payload) {
        $this->timestamp = $timestamp;
        $this->payload = $payload;
    }

    function get_timestamp() : int {
        return $this->timestamp;
    }

    function get_payload() : string {
        return $this->payload;
    }
}

/* Initialize user (username, password, cleartext_payload)
 *
 * $user_hash = $hash_algorithm->hash_username($username);
 * $user_exists = $storage->get_last_entry($user_hash) !== null;
 * 
 * if ($user_exists) {
 *   die("User already exists");
 * }
 * else {
 *   $keyCache = new InMemoryKeyCache();
 *   $salt = random_bytes(PBKDF2_SALT_BYTES);
 *   $iterations = PBKDF2_ITERATIONS;
 *   
 *   $cleartext_entry = new CleartextLogEntry(time(), $user_provided_payload);
 *   $encrypted_entry = $crypto->encrypt($cleartext_entry, $password, $salt, $iterations, $keyCache);
 *   $storage->append_entry($user_hash, $encrypted_entry);
 * }
 */

/* Authenticate user (username, password)
 *
 * $keyCache = new InMemoryKeyCache();
 * $user_hash = $hash_algorithm->hash_username($username);
 * $last_entry = $storage->get_last_entry($user_hash);
 * try {
 *   $crypto->decrypt($last_entry, $password, $keyCache);
 *   return true;
 * }
 * catch InvalidPasswordException {
 *   return false;
 * }

/* Append log entry
 *
 * $last_entry = $storage->get_last_entry($user_hash);
 * $validator->validate_log_entry($cleartext_entry);
 * $keyCache = new InMemoryKeyCache();
 * $new_entry = $crypto->encrypt($cleartext_entry, $password, $last_entry->salt, $last_entry->iterations, $keyCache);
 * $storage->append_entry($user_hash, $new_entry);
 */

/* List log entries for range
 *
 * $entry_list = $storage->list_entries_in_range($user_hash, $from_timestamp, $to_timestamp);
 * $keyCache = new InMemoryKeyCache();
 * foreach ($entry_list as $log_entry) {
 *   $cleartext_entry = $crypto->decrypt($log_entry, $password, $keyCache);
 * }
 */

class ApplicationSettings {
    public $storage_directory;
    public $log_filename_pattern;
    public $user_dir_salt;
    public $pbkdf2_iterations;
    public $pbkdf2_salt_bytes;
    public $auth_payload_bytes;
    public $user_settings_file;
}

class UserSettings {
    public $auth_iv;
    public $auth_tag;
    public $auth_payload;
    public $pbkdf2_salt;
    public $pbkdf2_iterations;

    private $key = null;

    const CIPHER = 'aes-256-gcm';

    public function initialize_new_user($password) {
        $this->pbkdf2_salt = openssl_random_pseudo_bytes(PBKDF2_SALT_BYTES);
        $this->pbkdf2_iterations = PBKDF2_ITERATIONS;

        $this->generate_key($password);
        $this->auth_iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(CIPHER));

        $cleartext_auth_payload = openssl_random_pseudo_bytes(AUTH_PAYLOAD_BYTES);
        $this->auth_payload = $this->encrypt($cleartext_auth_payload, $this->auth_iv, $this->auth_tag);
    }

    public function authenticate($password) {
        $this->generate_key($password);
        return $this->decrypt($this->auth_payload, $this->auth_iv, $this->auth_tag) !== false;
    }

    public function generate_key($password) {
        if ($this->key === null) {
            $this->key = hash_pbkdf2('sha512', $password, $this->pbkdf2_salt, $this->pbkdf2_iterations);
        }
    }

    public function encrypt($payload, $iv, &$tag) {
        $this->require_key();
        return openssl_encrypt($payload, self::CIPHER, $this->key, 0, $iv, $tag);
    }

    public function decrypt($payload, $iv, $tag) {
        $this->require_key();
        return openssl_decrypt($payload, self::CIPHER, $this->key, 0, $iv, $tag);
    }

    private function require_key() {
        if ($this->key === null) {
            throw new AssertionError("Key should not be null");
        }
    }

    public function to_json() {
        $serialized_settings = [];

        $serialized_settings['auth_iv'] = base64_encode($this->auth_iv);
        $serialized_settings['auth_tag'] = base64_encode($this->auth_tag);
        $serialized_settings['auth_payload'] = base64_encode($this->auth_payload);
        $serialized_settings['pbkdf2_salt'] = base64_encode($this->pbkdf2_salt);
        $serialized_settings['pbkdf2_iterations'] = $this->pbkdf2_iterations;

        return json_encode($serialized_settings);
    }

    public static function from_json($json_string) {
        $serialized_settings = json_decode($json_string, true);

        $settings = new UserSettings();
        $settings->auth_iv = base64_decode($serialized_settings['auth_iv']);
        $settings->auth_tag = base64_decode($serialized_settings['auth_tag']);
        $settings->auth_payload = base64_decode($serialized_settings['auth_payload']);
        $settings->pbkdf2_salt = base64_decode($serialized_settings['pbkdf2_salt']);
        $settings->pbkdf2_iterations = $serialized_settings['pbkdf2_iterations'];

        return $settings;
    }
}
class HtmlOutput implements Output {
    function die(string $message, int $code = 0) {
        die("Error #$code: $message");
    }

    function display_log_entries(array $log_entries) {
        include(__DIR__.'/templates/log_entries.php');
    }
}

class Timer {
    private $start_time;
    private $end_time;

    public function __construct() {
        $this->start_time = hrtime(true);
    }

    public function stop() {
        $this->end_time = hrtime(true);
    }

    public function get_duration_ms() {
        return ($this->end_time - $this->start_time) / 1000000.0;
    }
}

class User {
    private $directory;

    public function __construct(string $name) {
        # Derive the user/password to find out the user's home directory
        $user_hash = hash('sha512', $name.':'.USER_DIR_SALT);

        # This is safe, because the hash can only contain alphanumeric characters
        $this->directory = STORAGE_DIR.'/'.$user_hash;
    }

    public function authenticate(string $password) {
        $user_settings_file = $user_dir.'/'.USER_SETTINGS_FILE;

        if (!is_dir($user_dir)) {
            # User does not exist, and...
            if (is_writeable(STORAGE_DIR)) {
                # ... we can create it
                mkdir($user_dir);

                # We're going to generate pbkdf salt, and a randon payload to encrypt.
                # This encrypted payload will allow us to authenticate the user later
                $settings = new UserSettings();
                $settings->initialize_new_user($_SERVER['PHP_AUTH_PW']);
                file_put_contents($user_settings_file, $settings->to_json());
            }
            else {
                # ... we can't create the user
                $output->die("This user does not exist and cannot be created.");
            }
        }
        else {
            $settings = UserSettings::from_json(file_get_contents($user_settings_file));
            
            if (!$settings->authenticate($_SERVER['PHP_AUTH_PW'])) {
                die("Invalid password");
            }
        }
    }

    public function get_logs_since(string $since) {

    }

    public function add_log_entry(string $date, string $payload) {
        
    }
}

class LogEntry {
    public $date;
    public $iv;
    public $tag;
    public $encrypted_payload;
}

class LogFile {
    private $abspath;

    public function __construct(string $abspath) {
        $this->abspath = $abspath;
    }

    public function append_entry(LogEntry $entry) {

    }

    public function list_entries() {

    }
}
