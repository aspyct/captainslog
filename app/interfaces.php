<?php
/**
 * Choreographer
 * 
 * Handles the heavy lifting for user-facing operations.
 */
interface Choreographer {
    function initialize_user(string $username) : void;
    function authenticate(string $username, string $password);
    function append_log_entry(string $username, string $password, int $timestamp, string $payload) : void;
    function list_log_entries(string $username, string $password, int $from_timestamp_included, int $to_timestamp_excluded) : array;
}

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
