<?php
/**
 * @author    jan huang <bboyjanhuang@gmail.com>
 * @copyright 2016
 *
 * @link      https://www.github.com/janhuang
 * @link      http://www.fast-d.cn/
 */


use FastD\BasicAuthenticate\PdoAuthenticator;


class PdoAuthenticatorTest extends PHPUnit_Framework_TestCase
{
    public $pdo;

    public function setup()
    {
        $this->pdo = new \PDO("mysql:dbname=ci;host=127.0.0.1", 'root', '123456');
    }

    public function testPdoAuthenticatorInit()
    {
        $pdo = new PdoAuthenticator([
            'pdo' => $this->pdo,
            'table' => 'users',
            'field' => 'user',
            'hash' => 'hash'
        ]);

        $isPassed = $pdo->validate('root', 't00r');

        $this->assertTrue($isPassed);
        $this->assertEquals(['user' => 'root'], $pdo->getUserInfo());
        $this->assertFalse($pdo->validate('foo', 'bar'));
        $this->assertFalse($pdo->validate('root', 'bar'));
    }
}
