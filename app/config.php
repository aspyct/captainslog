<?php
# The storage directory should not be publicly accessible
# If this directory is writeable, the app will be able to enroll new users.
# If the directory is unwriteable, only previously created users will be able to access the app.
define('STORAGE_DIR', __DIR__.'/../storage');

define('USERNAME_SALT', )

# How many iterations to use while deriving the password to an AES key
define('PBKDF2_ITERATIONS', 10000);

# How many random bytes to use as salt for pbkdf2 password derivation
define('PBKDF2_SALT_BYTES', 32);

# How many random bytes to use for authentication payload
define('AUTH_PAYLOAD_BYTES', 32);

# Name of the file storing the pbkdf2 salt in the user directory. Anything not ending in .log is fine.
define('USER_SETTINGS_FILE', 'settings.json');
