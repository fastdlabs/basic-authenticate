<?php
/**
 * @author    jan huang <bboyjanhuang@gmail.com>
 * @copyright 2016
 *
 * @link      https://www.github.com/janhuang
 * @link      http://www.fast-d.cn/
 */


use FastD\BasicAuthenticate\PhpAuthenticator;


class PhpAuthenticatorTest extends PHPUnit_Framework_TestCase
{
    public function testAuthenticatorInit()
    {
        $php = new PhpAuthenticator([
            'foo' => 'bar',
            'admin' => 'admin'
        ]);

        $this->assertTrue($php->validate('foo', 'bar'));
        $this->assertTrue($php->validate('admin', 'admin'));
        $this->assertFalse($php->validate('foo', 'admin'));

        $this->assertNull($php->getUserInfo());
    }
}
