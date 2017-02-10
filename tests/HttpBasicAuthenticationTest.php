<?php
use FastD\BasicAuthenticate\HttpBasicAuthentication;
use FastD\Http\JsonResponse;
use FastD\Http\ServerRequest;
use FastD\Middleware\Delegate;

/**
 * @author    jan huang <bboyjanhuang@gmail.com>
 * @copyright 2016
 *
 * @link      https://www.github.com/janhuang
 * @link      http://www.fast-d.cn/
 */
class HttpBasicAuthenticationTest extends PHPUnit_Framework_TestCase
{
    public $data = [
        'msg' => 'not allow access',
        'code' => 401
    ];

    public function createBasicAuthentication()
    {
        return new HttpBasicAuthentication([
            'authenticator' => [
                'class' => \FastD\BasicAuthenticate\PhpAuthenticator::class,
                'params' => [
                    'foo' => 'bar'
                ]
            ],
            'response' => [
                'class' => JsonResponse::class,
                'data' => $this->data
            ]
        ]);
    }

    public function createDelegate()
    {
        return new Delegate(function () {
            return new JsonResponse([
                'foo' => 'bar'
            ]);
        });
    }

    public function createRequest($method, $uri, array $header = [], \Psr\Http\Message\StreamInterface $body = null, array $server = [])
    {
        return new ServerRequest($method, $uri, $header, $body, $server);
    }

    public function testAuth()
    {
        $response = $this->createBasicAuthentication()->handle($this->createRequest('GET', '/foo'), $this->createDelegate());

        $this->assertEquals(json_encode($this->data), $response->getBody());
    }

    public function testUserInfoAuth()
    {
        $response = $this->createBasicAuthentication()->handle($this->createRequest('GET', 'http://foo@example.com/foo'), $this->createDelegate());

        $this->assertEquals(json_encode($this->data), $response->getBody());

        $response = $this->createBasicAuthentication()->handle($this->createRequest('GET', 'http://foo:bar@example.com/foo'), $this->createDelegate());

        $this->assertEquals(json_encode([
            'foo' => 'bar'
        ]), $response->getBody());
    }

    public function testServerUserAuth()
    {
        $response = $this->createBasicAuthentication()->handle($this->createRequest('GET', 'http://example.com/foo', [], null, [
            'PHP_AUTH_USER' => 'foo',
        ]), $this->createDelegate());

        $this->assertEquals(json_encode($this->data), $response->getBody());

        $response = $this->createBasicAuthentication()->handle($this->createRequest('GET', 'http://example.com/foo', [], null, [
            'PHP_AUTH_USER' => 'foo',
            'PHP_AUTH_PW' => 'bar',
        ]), $this->createDelegate());

        $this->assertEquals(json_encode([
            'foo' => 'bar'
        ]), $response->getBody());
    }

    public function testSwooleHeaderUserAuth()
    {
        $response = $this->createBasicAuthentication()->handle($this->createRequest('GET', 'http://example.com/foo', [
            'authorization' => 'Basic ' . base64_encode('admin:admin'),
        ]), $this->createDelegate());

        $this->assertEquals(json_encode($this->data), $response->getBody());

        $response = $this->createBasicAuthentication()->handle($this->createRequest('GET', 'http://example.com/foo', [
            'authorization' => 'Basic Zm9vOmJhcg==',
        ]), $this->createDelegate());

        $this->assertEquals(json_encode([
            'foo' => 'bar'
        ]), $response->getBody());
    }
}
