<?php
function test_Aes256GcmCrypto() {
    section("Aes256GcmCrypto", function() {
        $crypto = new Aes256GcmCrypto();
        $key_cache = new NoKeyCache();

        $timestamp = time();
        $cleartext = "Captain on the bridge!";
        $password = "NCC-1701-D";
        $iterations = 1000;
        $salt = random_bytes(16);

        $original_entry = new ImmutableCleartextLogEntry($timestamp, $cleartext);
        $encrypted_entry = $crypto->encrypt($original_entry, $password, $salt, $iterations, $key_cache);
        $decrypted_entry = $crypto->decrypt($encrypted_entry, $password, $key_cache);

        // Timestamp must be the same
        assert_true($original_entry->get_timestamp() === $encrypted_entry->get_timestamp());
        assert_true($original_entry->get_timestamp() === $decrypted_entry->get_timestamp());

        // Payload must be encrypted and successfully decrypted
        assert_true($original_entry->get_payload() != $encrypted_entry->get_payload());
        assert_true($original_entry->get_payload() === $decrypted_entry->get_payload());

        assert_throws('InvalidPasswordException', function() use ($crypto, $encrypted_entry, $key_cache) {
            $crypto->decrypt($encrypted_entry, "wrong password", $key_cache);
        });
    });
}

function test_SingleFileStorage() {
    section("SingleFileStorage", function() {
        $storage = new SingleFileStorage("/tmp");

        $user_hash = sha1("valid_filename");
        $entry = new ImmutableEncryptedLogEntry(
            time(),
            "some salt",
            1000,
            "some iv",
            "some tag",
            "some payload"
        );

        try {
            assert_throws('NoSuchUserException', function() use ($storage, $user_hash) {
                $storage->entry_count($user_hash);
            });

            assert_throws('NoSuchUserException', function() use ($storage, $user_hash) {
                $storage->get_last_entry($user_hash);
            });

            assert_throws('NoSuchUserException', function() use ($storage, $user_hash) {
                $storage->list_entries_in_range($user_hash, 0, time());
            });

            $storage->append_entry($user_hash, $entry);

            assert_true(1 === $storage->entry_count($user_hash));

            $recovered_entry = $storage->get_last_entry($user_hash);

            assert_true($entry->get_timestamp() === $recovered_entry->get_timestamp());
            assert_true($entry->get_salt() === $recovered_entry->get_salt());
            assert_true($entry->get_iterations() === $recovered_entry->get_iterations());
            assert_true($entry->get_iv() === $recovered_entry->get_iv());
            assert_true($entry->get_tag() === $recovered_entry->get_tag());
            assert_true($entry->get_payload() === $recovered_entry->get_payload());

            $second_entry = new ImmutableEncryptedLogEntry(
                $entry->get_timestamp() + 1000,
                "some salt",
                1000,
                "some iv",
                "some tag",
                "some payload"
            );

            $storage->append_entry($user_hash, $second_entry);

            assert_true(2 === $storage->entry_count($user_hash));

            $recovered_second_entry = $storage->get_last_entry($user_hash);

            assert_true($second_entry->get_timestamp() === $recovered_second_entry->get_timestamp());

            $entry_list = $storage->list_entries_in_range(
                $user_hash,
                $entry->get_timestamp(), // included
                $second_entry->get_timestamp() + 1 // excluded
            );

            assert_true(2 === count($entry_list));
            assert_true($entry_list[0]->get_timestamp() === $entry->get_timestamp());
            assert_true($entry_list[1]->get_timestamp() === $second_entry->get_timestamp());

            $entry_list = $storage->list_entries_in_range(
                $user_hash,
                $entry->get_timestamp(), // included
                $second_entry->get_timestamp() // excluded
            );

            assert_true(1 === count($entry_list));
            assert_true($entry->get_timestamp() === $entry_list[0]->get_timestamp());

            $entry_list = $storage->list_entries_in_range(
                $user_hash,
                $entry->get_timestamp() + 1,
                $second_entry->get_timestamp() + 1
            );

            assert_true(1 === count($entry_list));
            assert_true($second_entry->get_timestamp() === $entry_list[0]->get_timestamp());
        }
        finally {
            $storage->delete_all_data($user_hash);
            assert_throws('NoSuchUserException', function() use($storage, $user_hash) {
                $storage->entry_count($user_hash);
            });
        }
    });
}

function test_SaltySha256Algorithm() {
    section("SaltySha256Algorithm", function() {
        $salt = "Captain ";
        $username = "Kathryn Janeway";
        $expected_hash = "c213c371e069bee75c562191d876e72c332f9b738b54ed811dc1e7b80a85f00a";

        $algo = new SaltySha256Algorithm($salt);
        $actual_hash = $algo->hash_username($username);
        assert_true($actual_hash === $expected_hash);
    });
}

function test_all() {
    test_assert_functions();
    test_Aes256GcmCrypto();
    test_SingleFileStorage();
    test_SaltySha256Algorithm();
}

function section($name, $tests) {
    begin_section($name);
    $tests();
    end_section($name);
}

function begin_section($name) {
    echo "$name\n";
}

function end_section($name) {
    echo "\n";
}

function fail($message) {
    die("\n###\nFAIL: $message\n###\n");
}

function assert_true($expression, $message = null) {
    if (!$expression) {
        throw new AssertionError($message);
    }
    else {
        echo ".";
    }
}

function assert_throws($exception_type, $function) {
    try {
        $function();
        assert_true(false, "No exception was raised. Expected $exception_type.");
    }
    catch (Exception $e) {
        $actual_type = get_class($e);
        assert_true($actual_type === $exception_type, "Wrong exception raised. Got $actual_type. Expected $exception_type");
        echo ".";
    }
}

function test_assert_functions() {
    echo "###\nBasic testing functionalities.\n###\n";

    try {
        assert_true(false);
        fail("This should have raised an AssertionError.");
    }
    catch (AssertionError $e) {
        echo "assert_true() works fine.\n";
    }

    try {
        assert_throws('No Such Exception', function() {
            // Throw nothing
        });
        fail("assert_throws() didn't work with no exception.");
    }
    catch (AssertionError $e) {
        echo "assert_throws() works fine with no exception.\n";
    }

    try {
        assert_throws('Not the right exception', function() {
            throw new RuntimeException();
        });
        fail("assert_throws() didn't work with wrong exception type.");
    }
    catch (AssertionError $e) {
        echo "assert_throws() works fine with wrong exception type.\n";
    }

    echo "Basic testing functionalities work. Continuing with the actual tests.\n\n";
}

require_once(__DIR__.'/../app/classes.php');
test_all();
