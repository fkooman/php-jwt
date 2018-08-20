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

namespace fkooman\Jose\Tests;

use fkooman\JWT\Keys\PrivateKey;
use fkooman\JWT\Keys\PublicKey;
use fkooman\JWT\RS256;
use PHPUnit\Framework\TestCase;

class RS256Test extends TestCase
{
    public function testSimple()
    {
        $publicKey = new PublicKey('-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D
o2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----');
        $privateKey = new PrivateKey('-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw
33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW
+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS
3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp
uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE
2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0
GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K
Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY
6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5
fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523
Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP
FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==
-----END RSA PRIVATE KEY-----');
        $r = new RS256(
            $publicKey,
            $privateKey
        );
        $jwtStr = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM';
        $payloadData = [
            'sub' => '1234567890',
            'name' => 'John Doe',
            'admin' => true,
            'iat' => 1516239022,
        ];
        $this->assertSame($jwtStr, $r->encode($payloadData));
        $this->assertSame(
            $payloadData,
            $r->decode($jwtStr)
        );
    }

    public function testDataporten()
    {
        $publicKey = new PublicKey('-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxFyeEkBwkozPqYqelBrX
YsfxMGBMXYTZusE+1hj7WAZ6lNGhITiw6CSb42IIJd11g8TfwxmcV36QHejFguo9
18UYY2cwshSro9HzFx2Gjd4pulavMa1xLC5kOStEzZns8viPyvl3oXarP3+X5w1N
c1MzPPvtksTffB8cACL9lvADHt9vVDALxhm7ctlf2ysXJLeeZxlax1gQFZkX7ZA4
s4cKDvb+zYNNvg2/u7KgD6vXMqmxIj3Gi8zhTP4qN2ro69YCImCHtWXXubUtvq16
j/fxj8hQmv2KnPKtsMrGHQRso2a+NGAvHGe3N+0fyrJ+E/ANa3EpsbydmAMcneS8
WwIDAQAB
-----END PUBLIC KEY-----');
        $r = new RS256(
            $publicKey
        );
        $jwtStr = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvYXV0aC5kYXRhcG9ydGVuLm5vIiwiYXVkIjoiNjVlMGE2MDktNzcwZC00ODk5LTlhMTYtYzUwMDkxNTQyZTE2Iiwic3ViIjoiNTVkZTdkNzEtNGEyNS00MTAzLThlNDMtMzVkZjhjMmQ0NzJhIiwiaWF0IjoxNTM0NzUzMjgzLCJleHAiOjE1MzQ3NTY4ODMsImF1dGhfdGltZSI6MTUzNDc1MzI4MX0.i3OLSrRl3hiEHoH7X7aceOHI7-UVj-G9L554hz1cC1jcCgsWlFTILHvDTKA6Qt2wy4gSE6TMotnjuJePt5ZnMllwwESIyCdSF3YQjF-A8Fz-DOKP24iyVmPgYuFMZ_m8gqKn0TaVTEcy5MOPncvPj53v0Zhr8VyxBY39qA9Gbbzvhhns72lWuhePNx6QLxoeEQx3UVQd6fNlXRj5cmgGGUOYNZ-_wDFmGbigC2mBlFQvs7Hhu6wAB2LLN16Fcc2Q6rXJ6CXJVuZQDqulLvxNGnOSrTOQxPTG1b8tbEdN1skhphqVDBSh0ZP1bnTwNhaB98IdKjkU2DTFqsKSCmrAmg';
        $payloadData = [
            'iss' => 'https://auth.dataporten.no',
            'aud' => '65e0a609-770d-4899-9a16-c50091542e16',
            'sub' => '55de7d71-4a25-4103-8e43-35df8c2d472a',
            'iat' => 1534753283,
            'exp' => 1534756883,
            'auth_time' => 1534753281,
        ];
        $this->assertSame(
            $payloadData,
            $r->decode($jwtStr)
        );
    }
}