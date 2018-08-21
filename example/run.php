<?php

/*
 * Copyright (c) 2018 François Kooman <fkooman@tuxed.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

require_once \dirname(__DIR__).'/vendor/autoload.php';

use fkooman\Jwt\HS256;
use fkooman\Jwt\Keys\PrivateKey;
use fkooman\Jwt\Keys\PublicKey;
use fkooman\Jwt\Keys\SymmetricKey;
use fkooman\Jwt\RS256;
use ParagonIE\ConstantTime\Base64;

try {
    // RS256
    $r = new RS256(
        new PublicKey(\file_get_contents(__DIR__.'/jwt.pub')),
        new PrivateKey(\file_get_contents(__DIR__.'/jwt.key'))
    );
    $jwtStr = $r->encode(['foo' => 'bar']);
    \var_export($r->decode($jwtStr));

    // HS256
    $h = new HS256(
        new SymmetricKey(Base64::decode('LaJlZbkRC7BBEQvnwefrlc3UJs+Z54Idq07munqE5AQ='))
    );
    $jwtStr = $h->encode(['foo' => 'bar']);
    \var_export($h->decode($jwtStr));
} catch (Exception $e) {
    echo 'ERROR: '.$e->getMessage().PHP_EOL;
}
