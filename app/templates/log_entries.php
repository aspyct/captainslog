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
            <?php foreach (array_reverse($log_entries) as $entry): [$date, $payload] = $entry ?>
                <tr>
                    <td><?= htmlentities($date) ?></td>
                    <td><?= $payload !== false ? htmlentities($payload) : '<b>Could not decrypt data</b>' ?></td>
                </tr>
            <?php endforeach ?>
            </tbody>
        </table>
    </body>
</html>