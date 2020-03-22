<?php
require_once __DIR__.'/config.php';
require_once __DIR__.'/classes.php';

abstract class AbstractResource implements Resource {
    public function do_get(array $untrusted_urlparams, array $untrusted_get) {}
    public function do_post(array $untrusted_urlparams, array $untrusted_get, array $untrusted_post) {}
    public function do_delete(array $untrusted_urlparams, array $untrusted_get) {}
    public function do_put(array $untrusted_urlparams, array $untrusted_get, array $untrusted_post) {}
}

class ApiUsageException extends Exception {}

class Repository extends AbstractResource {
    const STREAM_ID_REGEX = '/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}/';

    private $storage;

    public function __construct(Storage $storage) {

    }

    public function do_get(array $untrusted_urlparams, array $untrusted_get) {
        $stream_id = $this->get_stream_id($untrusted_urlparams);
        $from = intval($untrusted_get['from'] ?? (time() - 30 * 86400));
        $to = intval($untrusted_get['to'] ?? time());

        $storage->list_entries_in_range($stream_id, $from, $to);
    }

    public function do_post(array $untrusted_urlparams, array $untrusted_get, array $untrusted_post) {
        $stream_id = $this->get_stream_id($untrusted_urlparams);

        $log_entry = new ImmutableEncryptedLogEntry(
            $this->get_timestamp($untrusted_post),
            $this->get_salt($untrusted_post),
            $this->get_iterations($untrusted_post),
            $this->get_iv($untrusted_post),
            $this->get_tag($untrusted_post),
            $this->get_payload($untrusted_post)
        );

        $storage->append_log_entry($stream_id, $log_entry);
    }

    private function get_stream_id(array $untrusted_urlparams) {
        $untrusted_stream_id = $untrusted_urlparams['stream_id'];
        if (preg_match(self::STREAM_ID_REGEX, $untrusted_stream_id, $matches)) {
            $stream_id = $matches[0];
        }
        else {
            throw new ApiUsageException("stream_id must be a valid UUID");
        }
    }

    private function get_timestamp(array $untrusted_post) {
        return $this->get_integer($untrusted_post, 'timestamp');
    }

    private function get_salt(array $untrusted_post) {
        return $this->get_base64($untrusted_post, 'salt');
    }

    private function get_iterations(array $untrusted_post) {
        return $this->get_intereg($untrusted_post, 'iterations');
    }

    private function get_iv(array $untrusted_post) {
        return $this->get_base64($untrusted_post, 'iv');
    }

    private function get_tag(array $untrusted_post) {
        return $this->get_base64($untrusted_post, 'tag');
    }

    private function get_payload(array $untrusted_post) {
        return $this->get_base64($untrusted_post, 'payload');
    }

    private function get_integer($untrusted_post, $key) {
        $untrusted_input = $this->get_or_fail($untrusted_post, $key);

        if (!is_numeric($untrusted_input)) {
            throw new ApiUsageException("Invalid integer input for parameter: '$key'");
        }
        else {
            return intval($untrusted_input);
        }
    }

    private function get_base64($untrusted_post, $key) {
        $untrusted_input = $this->get_or_fail($untrusted_post, $key);
        $decoded = base64_decode($untrusted_input);

        if ($decoded === false) {
            throw new ApiUsageException("Invalid base64 input for parameter: '$key'");
        }
        else {
            return $decoded;
        }
    }

    private function get_or_fail($untrusted_post, $key) {
        if (array_key_exists($key, $untrusted_post)) {
            return $untrusted_post[$key];
        }
        else {
            throw new ApiUsageException("Missing required POST parameter: '$key'");
        }
    }
}

class SimpleApplication implements Application {
    private $resources;

    public function __construct(array $resources) {
        $this->resources = [];

        foreach ($resources as $pattern => $resource) {
            $this->resources[] = new PathMatcher($pattern, $resource);
        }
    }

    public function serve($server, $untrusted_get, $untrusted_post) {
        $path = $server['PATH_INFO'];

        foreach ($this->resources as $matcher) {
            if ($matcher->matches($path, $matches)) {
                return $this->run_resource($matcher->get_resource(), $server, $matches, $untrusted_get, $untrusted_post);
            }
        }

        http_response_code(404);
        die("404 Not Found");
    }

    private function run_resource(Resource $resource, array $server, array $untrusted_urlparams, array $untrusted_get, array $untrusted_post) {
        try {
            switch ($server['REQUEST_METHOD']) {
                case 'GET':
                    $resource->do_get($untrusted_urlparams, $untrusted_get);
                break;
                case 'POST':
                    $resource->do_post($untrusted_urlparams, $untrusted_get, $untrusted_post);
                break;
                case 'PUT':
                    $resource->do_put($untrusted_urlparams, $untrusted_get, $untrusted_post);
                break;
                case 'DELETE':
                    $resource->do_delete($untrusted_urlparams, $untrusted_get);
                break;
            }
        }
        catch (ApiUsageException $e) {
            die(json_encode([
                'error' => $e->getMessage()
            ]));
        }
    }
}

class PathMatcher {
    private $regex;
    private $resource;

    public function __construct(string $pattern, Resource $resource) {
        // Turn the URL pattern into an actual regex
        $this->regex = '#'.preg_replace('#\{([^}]+)\}#', '(?<$1>[^/]+)', $pattern).'#';
        $this->resource = $resource;
    }

    public function matches($path, &$matches) {
        return preg_match($this->regex, $path, $matches);
    }

    public function get_resource() {
        return $this->resource;
    }
}

$storage = new SingleFileStorage(STORAGE_DIR);
$repository = new Repository($storage);
$application = new SimpleApplication([
    '/repository/{stream_id}' => $repository
]);

$application->serve($_SERVER, $_GET, $_POST);
