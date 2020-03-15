<?php
# The storage directory should not be publicly accessible
# If this directory is writeable, the app will be able to enroll new users.
# If the directory is unwriteable, only previously created users will be able to access the app.
define('STORAGE_DIR', '../storage');

# The date pattern used to generate the filename
define('LOG_FILENAME_PATTERN', 'Y-m');

# What type of cipher is used. To date, only "aes-256-gcm" is supported
define('CIPHER', 'aes-256-gcm');

# How many iterations to use while deriving the password to an AES key
define('PBKDF2_ITERATIONS', 30);

# How many random bytes to use as salt for pbkdf2 password derivation
define('PBKDF2_SALT_BYTES', 16);
