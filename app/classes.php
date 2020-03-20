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
    /**
     * @throw NoSuchUserException
     */
    function get_last_entry(string $user_hash) : EncryptedLogEntry;

    /**
     * @throw NoSuchUserException
     */
    function list_entries_in_range(string $user_hash, int $from_timestamp_included, int $to_timestamp_excluded) : array;
    function append_entry(string $user_hash, EncryptedLogEntry $entry) : void;

    /**
     * @throw NoSuchUserException
     */
    function entry_count(string $user_hash) : int;

    function delete_all_data(string $user_hash) : void;
}

class NoSuchUserException extends Exception {}

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
    function encrypt(CleartextLogEntry $entry, string $password, string $salt, int $iterations, KeyCache $key_cache) : EncryptedLogEntry;

    /**
     * @throw InvalidPasswordException if the provided password is invalid
     */
    function decrypt(EncryptedLogEntry $entry, string $password, KeyCache $key_cache) : CleartextLogEntry;
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

class SingleKeyCache implements KeyCache {
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

    public function encrypt(CleartextLogEntry $entry, string $password, string $salt, int $iterations, KeyCache $key_cache) : EncryptedLogEntry {
        $key = $this->get_key($password, $salt, $iterations, $key_cache);
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
    public function decrypt(EncryptedLogEntry $entry, string $password, KeyCache $key_cache) : CleartextLogEntry {
        $key = $this->get_key($password, $entry->get_salt(), $entry->get_iterations(), $key_cache);
        
        $decrypted_payload = openssl_decrypt(
            $entry->get_payload(),
            self::CIPHER,
            $key,
            $this->get_options(),
            $entry->get_iv(),
            $entry->get_tag()
        );

        if ($decrypted_payload === false) {
            throw new InvalidPasswordException();
        }


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

class Sha256Algorithm implements UserHashAlgorithm {
    public function hash_username(string $username) : string {
        return hash('sha256', $username);
    }
}

/**
 * SingleFileStorage
 * 
 * A very simple storage that puts everything in a single file for a user.
 * That will probably not scale too well, but is good to test the features of the app.
 * 
 * Please note that no validation is made on the $user_hash, since it is expected
 * that it will actually be a "filename safe" value.
 * 
 * As such, this could potentially read any file on the filesystem.
 */
class SingleFileStorage implements Storage {
    private $directory;

    public function __construct($directory) {
        $this->directory = $directory;
    }

    public function get_last_entry(string $user_hash) : EncryptedLogEntry {
        $all_entries = $this->get_all_entries($user_hash);
        return $all_entries[count($all_entries) - 1];
    }

    public function list_entries_in_range(string $user_hash, int $from_timestamp_included, int $to_timestamp_excluded) : array {
        $all_entries = $this->get_all_entries($user_hash);
        $matching_entries = [];

        foreach ($all_entries as $log_entry) {
            $timestamp = $log_entry->get_timestamp();

            if ($timestamp >= $from_timestamp_included && $timestamp < $to_timestamp_excluded) {
                $matching_entries[] = $log_entry;
            }
        }

        return $matching_entries;
    }

    public function append_entry(string $user_hash, EncryptedLogEntry $entry) : void {
        $filepath = $this->get_filepath($user_hash);
        $handle = fopen($filepath, 'a');

        if ($handle === false) {
            throw new StorageException("Could not open file for writing: $filepath");
        }

        $csv_array = $this->log_entry_to_csv_array($entry);
        if (fputcsv($handle, $csv_array) === false) {
            throw new StorageException("Could not write to file: $filepath");
        }

        fclose($handle);
    }

    public function entry_count(string $user_hash) : int {
        return count($this->get_all_entries($user_hash));
    }
    
    public function delete_all_data(string $user_hash) : void {
        unlink($this->get_filepath($user_hash));
    }

    private function get_all_entries(string $user_hash) {
        $filepath = $this->get_filepath($user_hash);

        if (!is_file($filepath)) {
            throw new NoSuchUserException();
        }

        $handle = fopen($filepath, 'r');

        if ($handle === false) {
            throw new StorageException("Could not open file for reading: $filepath");
        }

        $all_entries = [];
        while (($csv_array = fgetcsv($handle)) !== false) {
            $log_entry = $this->csv_array_to_log_entry($csv_array);
            $all_entries[] = $log_entry;
        }

        return $all_entries;
    }

    private function get_filepath(string $user_hash) {
        return $this->directory.'/'.$user_hash.'.log';
    }

    private function log_entry_to_csv_array(EncryptedLogEntry $entry) {
        return [
            $entry->get_timestamp(),
            base64_encode($entry->get_salt()),
            $entry->get_iterations(),
            base64_encode($entry->get_iv()),
            base64_encode($entry->get_tag()),
            base64_encode($entry->get_payload())
        ];
    }

    private function csv_array_to_log_entry(array $csv_array) {
        return new ImmutableEncryptedLogEntry(
            intval($csv_array[0]),
            base64_decode($csv_array[1]),
            intval($csv_array[2]),
            base64_decode($csv_array[3]),
            base64_decode($csv_array[4]),
            base64_decode($csv_array[5]),
        );
    }
}

class StorageException extends Exception {}

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
 * $user_exists = $storage->entry_count($user_hash) > 0;
 * 
 * if ($user_exists) {
 *   die("User already exists");
 * }
 * else {
 *   $key_cache = new InMemoryKeyCache();
 *   $salt = random_bytes(PBKDF2_SALT_BYTES);
 *   $iterations = PBKDF2_ITERATIONS;
 *   
 *   $cleartext_entry = new CleartextLogEntry(time(), $user_provided_payload);
 *   $encrypted_entry = $crypto->encrypt($cleartext_entry, $password, $salt, $iterations, $key_cache);
 *   $storage->append_entry($user_hash, $encrypted_entry);
 * }
 */

/* Authenticate user (username, password)
 *
 * $key_cache = new InMemoryKeyCache();
 * $user_hash = $hash_algorithm->hash_username($username);
 * $last_entry = $storage->get_last_entry($user_hash);
 * try {
 *   $crypto->decrypt($last_entry, $password, $key_cache);
 *   return true;
 * }
 * catch InvalidPasswordException {
 *   return false;
 * }

/* Append log entry
 *
 * $last_entry = $storage->get_last_entry($user_hash);
 * $validator->validate_log_entry($cleartext_entry);
 * $key_cache = new InMemoryKeyCache();
 * $new_entry = $crypto->encrypt($cleartext_entry, $password, $last_entry->salt, $last_entry->iterations, $key_cache);
 * $storage->append_entry($user_hash, $new_entry);
 */

/* List log entries for range
 *
 * $entry_list = $storage->list_entries_in_range($user_hash, $from_timestamp, $to_timestamp);
 * $key_cache = new InMemoryKeyCache();
 * foreach ($entry_list as $log_entry) {
 *   $cleartext_entry = $crypto->decrypt($log_entry, $password, $key_cache);
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
