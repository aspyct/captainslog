<?php
require('config.php');

# Verify that the config is correct
if (!defined('STORAGE_DIR')) {
    die("Missing 'STORAGE_DIR' constant in config.php. Use any location that is NOT publicly accessible.");
}

$known_ciphers = ['aes-256-gcm'];
if (!(defined('CIPHER') && in_array(CIPHER, $known_ciphers))) {
    die("Missing or invalid 'CIPHER' constant in config.php. Allowed values are " . implode(',', $known_ciphers));
}

if (!defined('LOG_FILENAME_PATTERN')) {
    die("Missing 'LOG_FILENAME_PATTERN' constant in config.php. A good starting point would be 'Y-m'." );
}

if (!(defined('PBKDF2_SALT_BYTES') && is_numeric(PBKDF2_SALT_BYTES))) {
    die("Missing or invalid 'PBKDF2_SALT_BYTES' constant in config.php. A good starting point would be 16");
}

if (!(defined('PBKDF2_ITERATIONS') && is_numeric(PBKDF2_ITERATIONS))) {
    # TODO What's a good starting point for iteration count, actually?
    die("Missing or invalid 'PBKDF2_ITERATIONS constant in config.php. A good starting point would be 20");
}

if (!defined('USER_DIR_SALT')) {
    die("Missing 'USER_DIR_SALT' constant in config.php.");
}

if (!defined('USER_SETTINGS_FILE')) {
    die("Missing 'USER_SETTINGS_FILE' constant in config.php.");
}

if (!(defined('AUTH_PAYLOAD_BYTES') && is_numeric(AUTH_PAYLOAD_BYTES))) {
    # TODO What's a good starting point for iteration count, actually?
    die("Missing or invalid 'AUTH_PAYLOAD_BYTES constant in config.php. A good starting point would be 20");
}

class Settings {
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
        if ($this->key !== null) {
            $this->key = hash_pbkdf2('sha512', $password, $this->pbkdf2_salt, $this->pbkdf2_iterations);
        }
    }

    public function encrypt($payload, $iv, &$tag) {
        assert($this->key !== null);
        return openssl_encrypt($payload, self::CIPHER, $this->key, 0, $iv, $tag);
    }

    public function decrypt($payload, $iv, $tag) {
        assert($this->key !== null);
        return openssl_decrypt($payload, self::CIPHER, $this->key, 0, $iv, $tag);
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

        $settings = new Settings();
        $settings->auth_iv = base64_decode($serialized_settings['auth_iv']);
        $settings->auth_tag = base64_decode($serialized_settings['auth_tag']);
        $settings->auth_payload = base64_decode($serialized_settings['auth_payload']);
        $settings->pbkdf2_salt = base64_decode($serialized_settings['pbkdf2_salt']);
        $settings->pbkdf2_iterations = $serialized_settings['pbkdf2_iterations'];

        return $settings;
    }
}

# NEVER ask for HTTP basic over HTTP-non-S, unless we're in debug mode
if ((empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') && !empty($_ENV['CAPTAIN_DEBUGGER'])) {
    die("For security reasons, this app can't be used on HTTP-non-S.");
}

# Workaround for servers that don't publish the PHP_AUTH_* variables
list($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']) = explode(':', base64_decode(substr($_SERVER['HTTP_AUTHORIZATION'], 6)));

# Require basic authentication
if (!isset($_SERVER['PHP_AUTH_USER']) || empty($_SERVER['PHP_AUTH_PW'])) {
    header('WWW-Authenticate: Basic realm="Captain\'s Log"');
    header('HTTP/1.0 401 Unauthorized');
    die("401. Please provide your credentials.");
}

# Derive the user/password to find out the user's home directory
$user_hash = hash('sha512', $_SERVER['PHP_AUTH_USER'].':'.USER_DIR_SALT);

# This is safe, because the hash can only contain alphanumeric characters
$user_dir = STORAGE_DIR.'/'.$user_hash;
$user_settings_file = $user_dir.'/'.USER_SETTINGS_FILE;

# The permission system is very simple.
# If the folder does exist, the user is allowed.
# Otherwise, the user is allowed if and only if we can create a new folder.
# So for example, if you want to restrict access to only one user,
# create his directory first, and then lock the STORAGE_DIR permissions.
$start = hrtime(true);
if (!is_dir($user_dir)) {
    # User does not exist, and...
    if (is_writeable(STORAGE_DIR)) {
        # ... we can create it
        mkdir($user_dir);

        # We're going to generate pbkdf salt, and a randon payload to encrypt.
        # This encrypted payload will allow us to authenticate the user later
        $settings = new Settings();
        $settings->initialize_new_user($_SERVER['PHP_AUTH_PW']);
        file_put_contents($user_settings_file, $settings->to_json());
    }
    else {
        # ... we can't create the user
        die("This user does not exist and cannot be created.");
    }
}
else {
    $settings = Settings::from_json(file_get_contents($user_settings_file));
    
    if (!$settings->authenticate($_SERVER['PHP_AUTH_PW'])) {
        die("Invalid password");
    }
}
$end = hrtime(true);
$time_to_key = ($end - $start) / 1000000.0;

# GET lists the recent log entries
# POST creates a new log entry
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    # We need a payload to encrypt, even if it's empty
    $cleartext_payload = $_POST['payload'] ?? null;

    if (is_null($cleartext_payload)) {
        die("Please provide a payload. It can be empty, but must be set.");
    }

    # A log entry must have a timestamp, obviously
    $current_time = time();
    
    # Also, we're clustering logs by month
    $basename = gmdate(LOG_FILENAME_PATTERN, $current_time);
    $filepath = $user_dir.'/'.$basename.'.log';

    # And finally, the full utc iso date format for the log entry itself
    $date = gmdate('c', $current_time);
    
    # Random IV
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(CIPHER));

    # "0" is options. I chose to keep the padding.
    $encrypted_payload = $settings->encrypt($cleartext_payload, $iv, $tag);
    
    # base64 everything so we can write it in a text file
    $b64_iv = base64_encode($iv);
    $b64_tag = base64_encode($tag);
    $b64_payload = base64_encode($encrypted_payload);

    $csv_array = [
        $date,
        $b64_iv,
        $b64_tag,
        $b64_payload
    ];

    # Almost done, all that's left it writing to the file, if we can.
    $file_handle = fopen($filepath, 'a');
    if ($file_handle !== false) {
        if(fputcsv($file_handle, $csv_array) !== false) {
            fclose($file_handle);
            
            # This should probably be different if we're called as an API
            header("Location: log.php"); 
            die("Log recorded.");
        }
        else {
            fclose($file_handle);
            die("File was open, but I could not write to it.");
        }
    }
    else {
        die("Could not open log file in append mode.");
    }
}

# By default, get the logs 30 days back
$since = $_GET['since'] || (time() - 86400 * 30);

# List all files for this user
$log_files = glob($user_dir.'/*.log');

$decrypted_entries = [];
$errors = [];

# TODO Improve the "since" selection.
# For now, we'll simply parse all files and filter afterwards.
# Something smarter could be done with the file's mtime, I guess
$start = hrtime(true);
foreach ($log_files as $filepath) {
    $file_handle = fopen($filepath, 'r');

    if ($file_handle !== false) {
        while (($csv_array = fgetcsv($file_handle)) !== false) {
            [
                $date,
                $b64_iv,
                $b64_tag,
                $b64_payload
            ] = $csv_array;

            $iv = base64_decode($b64_iv);
            $tag = base64_decode($b64_tag);
            $payload = base64_decode($b64_payload);
            
            $decrypted_payload = $settings->decrypt($payload, $iv, $tag);
            $decrypted_entries[] = [$date, $decrypted_payload];
        }
    }
    else {
        $errors[] = "Could not open file: " . htmlentities($basename);
    }

    fclose($file_handle);
}
$end = hrtime(true);
$time_to_decrypt = ($end - $start) / 1000000.0;

?>
<!DOCTYPE html>
<html>
    <head>
        <title>Captain's Log</title>
    </head>
    <body>
        <h1>Captain's Log</h1>
            <a href="//logout@<?= $_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'] ?>">logout</a>
        <h2>New entry</h2>
        <form method="post">
            <input type="text" name="payload"/>
            <button type="submit">Log</button>
        </form>
        <h2>Previous entries</h2>
        <table>
            <thead>
                <tr>
                    <th>Date</th>
                    <th>Payload</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach (array_reverse($decrypted_entries) as $entry): [$date, $payload] = $entry ?>
                <tr>
                    <td><?= htmlentities($date) ?></td>
                    <td><?= $payload !== false ? htmlentities($payload) : '<b>Could not decrypt data</b>' ?></td>
                </tr>
            <?php endforeach ?>
            </tbody>
        </table>
        <footer>
            <span>Time to generate key: <?= $time_to_key ?></span>
            <span>Time to decrypt log: <?= $time_to_decrypt ?></span>
        </footer>
    </body>
</html>