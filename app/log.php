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

# Require basic authentication
if (!isset($_SERVER['PHP_AUTH_USER']) || empty($_SERVER['PHP_AUTH_PW'])) {
    header('WWW-Authenticate: Basic realm="Captain\'s Log"');
    header('HTTP/1.0 401 Unauthorized');
    die("401. Please provide your credentials.");
}

# Derive the user/password to find out the user's home directory
$user_hash = hash('sha512', $_SERVER['PHP_AUTH_USER'].':'.$_SERVER['PHP_AUTH_PW']);

# This is safe, because the hash can only contain alphanumeric characters
define('USER_DIR', STORAGE_DIR.'/'.$user_hash);

# The permission system is very simple.
# If the folder does exist, the user is allowed.
# Otherwise, the user is allowed if and only if we can create a new folder.
# So for example, if you want to restrict access to only one user,
# create his directory first, and then lock the STORAGE_DIR permissions.
if (!is_dir(USER_DIR)) {
    if (is_writeable(STORAGE_DIR)) {
        mkdir(USER_DIR);
    }
    else {
        die("This user does not exist and cannot be created.");
    }
}

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
    $filepath = USER_DIR.'/'.$basename.'.log';

    # And finally, the full utc iso date format for the log entry itself
    $date = gmdate('c', $current_time);
    
    # Generate the key based on the user's password, using pbkdf2 derivation
    $salt = openssl_random_pseudo_bytes(PBKDF2_SALT_BYTES);
    $key = hash_pbkdf2('sha256', $_SERVER['PHP_AUTH_PW'], $salt, PBKDF2_ITERATIONS);

    # Random IV
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(CIPHER));

    # "0" is options. I chose to keep the padding.
    $encrypted_payload = openssl_encrypt($cleartext_payload, CIPHER, $key, 0, $iv, $tag);
    
    # base64 everything so we can write it in a text file
    $b64_salt = base64_encode($salt);
    $b64_iv = base64_encode($iv);
    $b64_tag = base64_encode($tag);
    $b64_payload = base64_encode($encrypted_payload);

    $csv_array = [
        $date,
        $b64_salt,
        PBKDF2_ITERATIONS,
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
$log_files = scandir(USER_DIR);

$decrypted_entries = [];
$errors = [];

# TODO Improve the "since" selection.
# For now, we'll simply parse all files and filter afterwards.
# Something smarter could be done with the file's mtime, I guess
foreach ($log_files as $basename) {
    $filepath = USER_DIR.'/'.$basename;

    $file_handle = fopen($filepath, 'r');

    if ($file_handle !== false) {
        while (($csv_array = fgetcsv($file_handle)) !== false) {
            [
                $date,
                $b64_salt,
                $pbkdf2_iterations,
                $b64_iv,
                $b64_tag,
                $b64_payload
            ] = $csv_array;

            $salt = base64_decode($b64_salt);
            $iv = base64_decode($b64_iv);
            $tag = base64_decode($b64_tag);
            $payload = base64_decode($b64_payload);
            
            $key = hash_pbkdf2('sha256', $_SERVER['PHP_AUTH_PW'], $salt, $pbkdf2_iterations);

            $decrypted_payload = openssl_decrypt($payload, CIPHER, $key, 0, $iv, $tag);
            $decrypted_entries[] = [$date, $decrypted_payload];
        }
    }
    else {
        $errors[] = "Could not open file: " . htmlentities($basename);
    }

    fclose($file_handle);
}

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
            <?php foreach ($decrypted_entries as $entry): [$date, $payload] = $entry ?>
                <tr>
                    <td><?= htmlentities($date) ?></td>
                    <td><?= $payload !== false ? htmlentities($payload) : '<b>Could not decrypt data</b>' ?></td>
                </tr>
            <?php endforeach ?>
            </tbody>
        </table>
    </body>
</html>