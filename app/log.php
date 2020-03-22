<?php
require('config.php');
require('classes.php');

$output = new HtmlOutput();
$application_settings = new ApplicationSettings();

$application_settings->set_storage_directory('STORAGE_DIR');

# Verify that the config is correct
if (!defined('STORAGE_DIR')) {
    $output->die("Missing 'STORAGE_DIR' constant in config.php. Use any location that is NOT publicly accessible.");
}

$known_ciphers = ['aes-256-gcm'];
if (!(defined('CIPHER') && in_array(CIPHER, $known_ciphers))) {
    $output->die("Missing or invalid 'CIPHER' constant in config.php. Allowed values are " . implode(',', $known_ciphers));
}

if (!defined('LOG_FILENAME_PATTERN')) {
    $output->die("Missing 'LOG_FILENAME_PATTERN' constant in config.php. A good starting point would be 'Y-m'." );
}

if (!(defined('PBKDF2_SALT_BYTES') && is_numeric(PBKDF2_SALT_BYTES))) {
    $output->die("Missing or invalid 'PBKDF2_SALT_BYTES' constant in config.php. A good starting point would be 16");
}

if (!(defined('PBKDF2_ITERATIONS') && is_numeric(PBKDF2_ITERATIONS))) {
    # TODO What's a good starting point for iteration count, actually?
    $output->die("Missing or invalid 'PBKDF2_ITERATIONS constant in config.php. A good starting point would be 20");
}

if (!defined('USER_DIR_SALT')) {
    $output->die("Missing 'USER_DIR_SALT' constant in config.php.");
}

if (!defined('USER_SETTINGS_FILE')) {
    $output->die("Missing 'USER_SETTINGS_FILE' constant in config.php.");
}

if (!(defined('AUTH_PAYLOAD_BYTES') && is_numeric(AUTH_PAYLOAD_BYTES))) {
    # TODO What's a good starting point for iteration count, actually?
    $output->die("Missing or invalid 'AUTH_PAYLOAD_BYTES constant in config.php. A good starting point would be 20");
}

# Config is validated

# NEVER ask for HTTP basic over HTTP-non-S, unless we're in debug mode
if ((empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') && !empty($_ENV['CAPTAIN_DEBUGGER'])) {
    $output->die("For security reasons, this app can't be used on HTTP-non-S.");
}

# Workaround for servers that don't publish the PHP_AUTH_* variables
if (!isset($_SERVER['PHP_AUTH_USER'])) {
    [$_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']] = explode(':', base64_decode(substr($_SERVER['HTTP_AUTHORIZATION'], 6)));
}

# Require basic authentication
if (!isset($_SERVER['PHP_AUTH_USER']) || empty($_SERVER['PHP_AUTH_USER']) ||  empty($_SERVER['PHP_AUTH_PW'])) {
    header('WWW-Authenticate: Basic realm="Captain\'s Log"');
    header('HTTP/1.0 401 Unauthorized');
    $output->die("401. Please provide your credentials.");
}

$storage = new SingleFileStorage(STORAGE_DIR);
$crypto = new Aes256GcmCrypto();
$hash = new SaltySha256Algorithm(USER_SALT);
$key_cache = new SingleKeyCache();
$choreographer = new DefaultChoreographer($crypto, $storage, $hash);

$username = $_SERVER['PHP_AUTH_USER'];
$password = $_SERVER['PHP_AUTH_PW'];



# Derive the user/password to find out the user's home directory
$stream_id = hash('sha512', $_SERVER['PHP_AUTH_USER'].':'.USER_DIR_SALT);

# This is safe, because the hash can only contain alphanumeric characters
$user_dir = STORAGE_DIR.'/'.$stream_id;
$user_settings_file = $user_dir.'/'.USER_SETTINGS_FILE;

# The permission system is very simple.
# If the folder does exist, the user is allowed.
# Otherwise, the user is allowed if and only if we can create a new folder.
# So for example, if you want to restrict access to only one user,
# create his directory first, and then lock the STORAGE_DIR permissions.
$key_generation_timer = new Timer();
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
$key_generation_timer->stop();

# GET lists the recent log entries
# POST creates a new log entry
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    # We need a payload to encrypt, even if it's empty
    $cleartext_payload = $_POST['payload'] ?? null;

    if (is_null($cleartext_payload)) {
        $output->die("Please provide a payload. It can be empty, but must be set.");
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
            $output->die("Log recorded.");
        }
        else {
            fclose($file_handle);
            $output->die("File was open, but I could not write to it.");
        }
    }
    else {
        $output->die("Could not open log file in append mode.");
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
$log_decryption_timer = new Timer();
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
$log_decryption_timer->stop();

$output->display_log_entries($decrypted_entries);