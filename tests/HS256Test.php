<?php

/*
 * Copyright (c) 2019-2020 François Kooman <fkooman@tuxed.net>
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

namespace fkooman\Jwt\Tests;

use fkooman\Jwt\HS256;
use fkooman\Jwt\Keys\HS256\SecretKey;
use PHPUnit\Framework\TestCase;

class HS256Test extends TestCase
{
    public function testSimple()
    {
        $h = new HS256(new SecretKey(\base64_decode('LaJlZbkRC7BBEQvnwefrlc3UJs+Z54Idq07munqE5AQ=', true)));
        $jwtStr = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8CymvZz4_nrhKF9cO2y4yo3UmDJ30QiuidJvLlH_0Is';
        $payloadData = [
              'sub' => '1234567890',
              'name' => 'John Doe',
              'iat' => 1516239022,
        ];
        $this->assertSame($jwtStr, $h->encode($payloadData));
        $this->assertSame(
            $payloadData,
            $h->decode($jwtStr)
        );
    }

    public function testExtractKeyId()
    {
        $this->assertSame(
            'foo',
            HS256::extractKeyId('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZvbyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.hu7CYwVz0vwCiRThrkcnKBgjyN8k9IYqDzTNvNsO59w')
        );
    }

    public function testExtractKeyIdNoKid()
    {
        $this->assertNull(
            HS256::extractKeyId('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')
        );
    }

    public function testNoKeyId()
    {
        $h = new HS256(new SecretKey(\base64_decode('LaJlZbkRC7BBEQvnwefrlc3UJs+Z54Idq07munqE5AQ=', true)));
        $jwtStr = $h->encode(['foo' => 'bar']);
        $this->assertNull(HS256::extractKeyId($jwtStr));
    }

    public function testManualKeyId()
    {
        $h = new HS256(new SecretKey(\base64_decode('LaJlZbkRC7BBEQvnwefrlc3UJs+Z54Idq07munqE5AQ=', true)));
        $h->setKeyId('my_key_id');
        $jwtStr = $h->encode(['foo' => 'bar']);
        $this->assertSame('my_key_id', HS256::extractKeyId($jwtStr));
    }
}
