<?php
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

interface Output {
    function die(string $message, int $code = 0);
    function display_log_entries(array $entries);
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
