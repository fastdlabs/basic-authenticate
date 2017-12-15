<?php
/**
 * @author    jan huang <bboyjanhuang@gmail.com>
 * @copyright 2016
 *
 * @link      https://www.github.com/janhuang
 * @link      http://www.fast-d.cn/
 */


use FastD\BasicAuthenticate\PdoAuthenticator;


class PdoAuthenticatorTest extends PHPUnit_Extensions_Database_TestCase
{
    protected $pdo;

    /**
     * Returns the test database connection.
     *
     * @return PHPUnit_Extensions_Database_DB_IDatabaseConnection
     */
    protected function getConnection()
    {
        $this->pdo = new \PDO("mysql:dbname=ci;host=127.0.0.1", 'root');

        $this->pdo->exec(
            "CREATE TABLE users (
                user VARCHAR(32) NOT NULL,
                hash VARCHAR(255) NOT NULL
            )"
        );

        return $this->createDefaultDBConnection($this->pdo);
    }

    /**
     * Returns the test dataset.
     *
     * @return \PHPUnit_Extensions_Database_DataSet_IDataSet
     */
    protected function getDataSet()
    {
        return new \PHPUnit_Extensions_Database_DataSet_YamlDataSet(__DIR__ . '/users.yml');
    }

    public function testPdoAuthenticatorInit()
    {
        $pdo = new PdoAuthenticator([
            'pdo' => $this->pdo,
            'table' => 'users',
            'field' => 'user',
            'hash' => 'hash'
        ]);

        $isPassed = $pdo->validate('admin', 'admin');

        $this->assertTrue($isPassed);
        $this->assertEquals(['user' => 'admin'], $pdo->getUserInfo());
        $this->assertFalse($pdo->validate('foo', 'bar'));
        $this->assertFalse($pdo->validate('root', 'bar'));
    }
}
